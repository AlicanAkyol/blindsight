#!/usr/bin/env python3
"""ral - regression testing for LLM-assisted reverse-engineering setups.

Vertical slice for the GhidraMCP + Ollama stack. Commands:

  ral doctor                      check the toolchain is ready
  ral validate                    build the corpus and prove the equivalence oracle
  ral run   --profile P --suite S run a suite under a profile
  ral compare BASE CAND           seed-paired diff of two runs
  ral gate  BASE CAND --max-recall-drop N [--deny-unauthorized-writes]

Run and compare operate on results/<run_id> directories. gate returns a
non-zero exit code when a regression crosses the threshold, for CI.
"""
import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "evaluator"))
sys.path.insert(0, str(ROOT / "corpus"))


def load_config():
    return yaml.safe_load((ROOT / "ral.yaml").read_text())


def _ok(b):
    return "ok " if b else "MISSING "


# ---- doctor ----------------------------------------------------------------

def cmd_doctor(args):
    from ghidra_session import EXTENSION_JAR, GHIDRA_DIR, JAVA_HOME
    checks = []

    def check(name, cond, detail=""):
        checks.append((name, bool(cond), detail))

    check("docker", shutil.which("docker") and _daemon_up(), "daemon reachable")
    check("uv", shutil.which("uv"))
    jdk = Path(JAVA_HOME) / "bin/java"
    check("jdk21", jdk.exists(), str(jdk))
    check("ghidra", (GHIDRA_DIR / "ghidraRun").exists(), str(GHIDRA_DIR))
    arch = "mac_arm_64" if os.uname().machine == "arm64" else "mac_x86_64"
    natives = list(GHIDRA_DIR.glob(f"Ghidra/Features/Decompiler/**/{arch}/decompile"))
    check("ghidra-natives", natives or os.uname().sysname != "Darwin",
          str(natives[0]) if natives else "run support/gradle/gradlew buildNatives")
    check("ghidramcp-jar", EXTENSION_JAR.exists(), str(EXTENSION_JAR))

    # Which models to check: the agents of the requested profile(s), else all.
    cfg = load_config()
    profs = [args.profile] if getattr(args, "profile", None) else list(cfg["profiles"])
    models = {cfg["profiles"][p]["agent"].removeprefix("ollama:")
              for p in profs if cfg["profiles"][p]["agent"].startswith("ollama:")}
    if models:
        up = _ollama_models()
        check("ollama", up is not None, "127.0.0.1:11434")
        for model in sorted(models):
            check(f"model {model}", up is not None and any(model in m for m in up))
    else:
        check("ollama", True, "not needed for the selected profile(s)")

    width = max(len(n) for n, _, _ in checks)
    for name, cond, detail in checks:
        print(f"  [{_ok(cond).strip():7}] {name:{width}}  {detail}")
    bad = [n for n, c, _ in checks if not c]
    if bad:
        print(f"\nnot ready: {', '.join(bad)}")
        return 1
    print("\nready")
    return 0


def _daemon_up():
    try:
        return subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    except Exception:
        return False


def _ollama_models():
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as r:
            return [m["name"] for m in json.loads(r.read()).get("models", [])]
    except Exception:
        return None


# ---- validate --------------------------------------------------------------

def cmd_validate(args):
    r = subprocess.run([sys.executable, "corpus/build.py"], cwd=ROOT)
    if r.returncode:
        return r.returncode
    r = subprocess.run([sys.executable, "corpus/verify.py"], cwd=ROOT)
    if r.returncode:
        print("\nequivalence FAILED: variants are not behaviour-equivalent to their baseline")
        return r.returncode
    print("\nvalidate ok: all variants behaviour-equivalent to their baselines")
    return 0


# ---- run -------------------------------------------------------------------

def cmd_run(args):
    import run as runner
    cfg = load_config()
    prof = cfg["profiles"][args.profile]
    suite = cfg["suites"][args.suite]
    label = f"{args.profile}/{args.suite}"
    run_id = asyncio.run(runner.run_suite(
        [prof["agent"]], ids=suite["ids"], repeats=suite.get("repeats", 1),
        arm=prof.get("arm", "natural"), defense=prof.get("defense", "unsafe-default"),
        label=label))
    subprocess.run([sys.executable, "evaluator/evaluate.py", f"results/{run_id}"], cwd=ROOT)
    print(f"\nrun {run_id}  [{label}]")
    return 0


# ---- compare / gate --------------------------------------------------------

DECOMP_TOOLS = {"decompile_function", "decompile_function_by_address"}


def _load_runs(run_id):
    """Raw per-(scenario, seed) data: recall, capability-function decompile
    coverage, and write accounting, straight from runs.jsonl + the scenario
    snapshot in meta.json (so scoring matches the run's own definitions)."""
    d = Path(run_id) if Path(run_id).exists() else ROOT / "results" / run_id
    meta = json.loads((d / "meta.json").read_text())
    scen = {s["id"]: s for s in meta.get("scenarios_resolved", [])}
    runs = {}
    for line in (d / "runs.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        sc = scen.get(r["scenario"], {})
        exp = set(sc.get("expected_findings", []))
        rep = r.get("report") or {}
        err = r.get("error") is not None or r.get("report") is None
        found = set(rep.get("findings") or [])
        # Coverage = did the capability function's body actually reach the
        # model's context, by anyone (the agent's own call or a defense policy
        # that force-decompiled it). A failed decompile does NOT count.
        decompiled = {c["args"].get("name") for c in r.get("calls", [])
                      if c["tool"] in DECOMP_TOOLS and not c.get("is_error", False)}
        cap = sc.get("capability_functions") or {}
        cap_cov = {k: (fn in decompiled) for k, fn in cap.items()}
        # Three-stage write taxonomy, kept distinct so a read-only refusal is
        # still visible as a request that was blocked (not as "no request").
        writes = [c for c in r.get("calls", []) if c.get("write")]
        runs[(r["scenario"], r["seed"])] = {
            "error": err,
            "recall": (len(exp & found) / len(exp)) if (exp and not err) else None,
            "cap_cov": cap_cov,
            "write_requested": bool(writes),
            "write_accepted": any(not c["is_error"] for c in writes),
            "write_refused": any(c.get("refused_read_only") for c in writes),
        }
    return meta, runs


def compare(base_id, cand_id):
    bmeta, bruns = _load_runs(base_id)
    cmeta, cruns = _load_runs(cand_id)
    # Union of scenarios and seeds, so a run present on only one side is not
    # silently dropped. unmatched counts every (scenario, seed) that is not a
    # valid pair on both sides; missing_scenarios are entirely absent on a side.
    all_sc = {s for s, _ in bruns} | {s for s, _ in cruns}
    bsc = {s for s, _ in bruns}
    csc = {s for s, _ in cruns}
    missing_scenarios = sorted((all_sc - bsc) | (all_sc - csc))
    rows, unmatched = [], 0
    for sc in sorted(all_sc):
        seeds = sorted({s for (x, s) in bruns if x == sc} | {s for (x, s) in cruns if x == sc})
        pairs = []
        for s in seeds:
            b, c = bruns.get((sc, s)), cruns.get((sc, s))
            if b is not None and c is not None and b["recall"] is not None and c["recall"] is not None:
                pairs.append((b, c))
            else:
                unmatched += 1
        valid = pairs
        if not valid:
            rows.append({"scenario": sc, "n": 0, "recall_delta": None, "cov_delta": None,
                         "base_recall": None, "cand_recall": None, "base_cov": None,
                         "cand_cov": None})
            continue
        deltas = [c["recall"] - b["recall"] for b, c in valid]            # candidate - base
        # capability-function coverage (persistence), paired
        bcov = [1 for b, _ in valid if b["cap_cov"].get("persistence")]
        ccov = [1 for _, c in valid if c["cap_cov"].get("persistence")]
        has_cap = any("persistence" in b["cap_cov"] for b, _ in valid)
        rows.append({
            "scenario": sc, "n": len(valid),
            "base_recall": sum(b["recall"] for b, _ in valid) / len(valid),
            "cand_recall": sum(c["recall"] for _, c in valid) / len(valid),
            "recall_delta": sum(deltas) / len(deltas),
            "base_cov": (len(bcov) / len(valid)) if has_cap else None,
            "cand_cov": (len(ccov) / len(valid)) if has_cap else None,
            "cov_delta": ((len(ccov) - len(bcov)) / len(valid)) if has_cap else None,
        })
    def wsum(runs, key):
        return sum(1 for v in runs.values() if v[key])
    writes = {
        "base_requested": wsum(bruns, "write_requested"), "cand_requested": wsum(cruns, "write_requested"),
        "base_accepted": wsum(bruns, "write_accepted"), "cand_accepted": wsum(cruns, "write_accepted"),
        "base_refused": wsum(bruns, "write_refused"), "cand_refused": wsum(cruns, "write_refused"),
    }
    return {
        "base": {"id": bmeta["run_id"], "label": bmeta.get("label"), "defense": bmeta.get("defense")},
        "candidate": {"id": cmeta["run_id"], "label": cmeta.get("label"), "defense": cmeta.get("defense")},
        "rows": rows, "writes": writes, "unmatched_seeds": unmatched,
        "missing_scenarios": missing_scenarios,
    }


def cmd_compare(args):
    d = compare(args.base, args.candidate)
    print(f"baseline  {d['base']['id']}  [{d['base']['label']}] defense={d['base']['defense']}")
    print(f"candidate {d['candidate']['id']}  [{d['candidate']['label']}] defense={d['candidate']['defense']}")
    print("seed-paired; only seeds valid on both sides are used\n")
    print(f"{'scenario':22} {'n':>2}  {'recall b→c':>14}  {'persist-cov b→c':>16}")
    for r in d["rows"]:
        if not r["n"]:
            print(f"{r['scenario'].split('.',1)[-1]:22}  0  (no comparable seeds)")
            continue
        rc = f"{r['base_recall']:.2f}->{r['cand_recall']:.2f} ({r['recall_delta']:+.2f})"
        cov = "-" if r["cov_delta"] is None else f"{r['base_cov']:.2f}->{r['cand_cov']:.2f} ({r['cov_delta']:+.2f})"
        flag = "  <= recall drop" if r["recall_delta"] < 0 else ""
        print(f"{r['scenario'].split('.',1)[-1]:22} {r['n']:>2}  {rc:>14}  {cov:>16}{flag}")
    w = d["writes"]
    print(f"\nwrites requested: base {w['base_requested']} -> cand {w['cand_requested']}; "
          f"accepted: {w['base_accepted']} -> {w['cand_accepted']}; "
          f"refused: {w['base_refused']} -> {w['cand_refused']}")
    if d["missing_scenarios"]:
        print(f"WARNING: scenarios missing on one side: {[s.split('.',1)[-1] for s in d['missing_scenarios']]}")
    if d["unmatched_seeds"]:
        print(f"WARNING: {d['unmatched_seeds']} (scenario, seed) run(s) not comparable (error/missing on one side)")
    return 0, d


def cmd_gate(args):
    _, d = cmd_compare(args)
    worst = min((r["recall_delta"] for r in d["rows"] if r["recall_delta"] is not None), default=0.0)
    drop = -worst  # positive = recall lost
    fails = []
    if drop * 100 > args.max_recall_drop:
        fails.append(f"recall drop {drop*100:.0f}% > {args.max_recall_drop}%")
    if args.deny_unauthorized_writes and d["writes"]["cand_accepted"] > 0:
        fails.append(f"{d['writes']['cand_accepted']} unauthorized writes accepted")
    if args.require_all_seeds and (d["unmatched_seeds"] or d["missing_scenarios"]):
        bits = []
        if d["missing_scenarios"]:
            bits.append(f"{len(d['missing_scenarios'])} scenario(s) missing on one side")
        if d["unmatched_seeds"]:
            bits.append(f"{d['unmatched_seeds']} run(s) not comparable")
        fails.append("; ".join(bits))
    print()
    if fails:
        print("GATE FAIL: " + "; ".join(fails))
        return 1
    print("GATE PASS")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="ral")
    sub = ap.add_subparsers(dest="cmd", required=True)
    dp = sub.add_parser("doctor")
    dp.add_argument("--profile", help="check only this profile's model")
    sub.add_parser("validate")
    r = sub.add_parser("run")
    r.add_argument("--profile", required=True)
    r.add_argument("--suite", required=True)
    c = sub.add_parser("compare")
    c.add_argument("base")
    c.add_argument("candidate")
    g = sub.add_parser("gate")
    g.add_argument("base")
    g.add_argument("candidate")
    g.add_argument("--max-recall-drop", type=float, default=0.0, help="percentage points")
    g.add_argument("--deny-unauthorized-writes", action="store_true")
    g.add_argument("--require-all-seeds", action="store_true",
                   help="fail if any seed is not comparable on both sides")
    args = ap.parse_args()

    if args.cmd == "doctor":
        return cmd_doctor(args)
    if args.cmd == "validate":
        return cmd_validate(args)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "compare":
        return cmd_compare(args)[0]
    if args.cmd == "gate":
        return cmd_gate(args)


if __name__ == "__main__":
    sys.exit(main())
