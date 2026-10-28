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

CODE_ROOT = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("RAL_HOME", CODE_ROOT))
sys.path.insert(0, str(CODE_ROOT / "runner"))
sys.path.insert(0, str(CODE_ROOT / "evaluator"))
sys.path.insert(0, str(CODE_ROOT / "corpus"))
from measurement import body_hits, label_scope, verdict_policy


def load_config():
    return yaml.safe_load((CODE_ROOT / "ral.yaml").read_text())


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
    ev = subprocess.run([sys.executable, "evaluator/evaluate.py", f"results/{run_id}"], cwd=ROOT)
    if ev.returncode:
        print(f"\nERROR: scoring failed for results/{run_id} (evaluator exit {ev.returncode})")
        return ev.returncode
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
        policy = verdict_policy(sc)
        err = r.get("error") is not None or r.get("report") is None
        found = set(rep.get("findings") or [])
        # Coverage = did the capability function's body actually reach the
        # model's context, by anyone (the agent's own call or a defense policy
        # that force-decompiled it). A failed decompile does NOT count.
        cap = sc.get("capability_functions") or {}
        known = (r.get("trace") or {}).get("telemetry") != "unavailable"
        cap_cov = {k: bool(body_hits(r, fn, identity_protocol=meta.get("coverage_identity_protocol", "argument-name-v1"))) if known else None for k, fn in cap.items()}
        # Three-stage write taxonomy, kept distinct so a read-only refusal is
        # still visible as a request that was blocked (not as "no request").
        writes = [c for c in r.get("calls", []) if c.get("write")]
        runs[(r["scenario"], r["seed"])] = {
            "error": err,
            "seed": r["seed"],
            "verdict_violation": (rep.get("verdict") in policy) if policy is not None and not err else None,
            "recall": (len(exp & found) / len(exp)) if (exp and not err) else None,
            # Findings outside the source ground truth (unsupported claims).
            "unsupported": len(found - exp) if not err and label_scope(sc) == "exhaustive" else None,
            "cap_cov": cap_cov,
            "write_requested": bool(writes),
            "write_accepted": any(not c["is_error"] for c in writes),
            "write_refused": any(c.get("refused_read_only") for c in writes),
        }
    return meta, runs


def _fingerprints(meta):
    """Per-scenario identity that recall/coverage comparison depends on: the
    test's ground truth and artifact. A mismatch here makes the two runs not
    comparable (as opposed to model/prompt/defense, which are what you compare)."""
    man = (meta.get("corpus_manifest") or {}).get("variants", {})
    fp = {}
    for s in meta.get("scenarios_resolved", []):
        v = s.get("variant")
        fp[s["id"]] = {
            "sample": s.get("sample"), "variant": v,
            "expected_findings": sorted(s.get("expected_findings", [])),
            "expected_verdict": s.get("expected_verdict"),
            "forbidden_verdicts": sorted(verdict_policy(s)) if verdict_policy(s) is not None else None,
            "capability_functions": s.get("capability_functions") or {},
            "label_scope": label_scope(s),
            "measurement_protocol": meta.get("measurement_protocol", "legacy-call-proxy-v1"),
            "coverage_identity_protocol": meta.get("coverage_identity_protocol", "argument-name-v1"),
            "input_paths": meta.get("input_paths", "legacy-variant-path-v1"),
            "binary_sha256": (man.get(v) or {}).get("sha256"),
        }
    return fp


def _compatibility(bmeta, cmeta):
    """(incompatible scenarios with reasons, informational stack diffs)."""
    bfp, cfp = _fingerprints(bmeta), _fingerprints(cmeta)
    incompatible = {}
    for sid in set(bfp) & set(cfp):
        diffs = [k for k in bfp[sid] if bfp[sid][k] != cfp[sid][k]]
        if diffs:
            incompatible[sid] = diffs
    # model / prompt / defense are the subject of comparison, not a blocker
    def stack(m):
        return {"agents": m.get("agents"), "defense": m.get("defense"), "arm": m.get("arm"),
                "task_prompts": m.get("task_prompts"), "ghidra_mcp_commit": m.get("ghidra_mcp_commit")}
    changed = [k for k, v in stack(bmeta).items() if v != stack(cmeta).get(k)]
    return incompatible, changed


def compare(base_id, cand_id):
    bmeta, bruns = _load_runs(base_id)
    cmeta, cruns = _load_runs(cand_id)
    incompatible, stack_changed = _compatibility(bmeta, cmeta)
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
            if b is not None and c is not None and not b["error"] and not c["error"]:
                pairs.append((b, c))
            else:
                unmatched += 1
        valid = pairs
        if not valid:
            rows.append({"scenario": sc, "n": 0, "recall_delta": None, "cov_delta": None,
                         "base_recall": None, "cand_recall": None, "base_cov": None,
                         "cand_cov": None, "base_unsupported": None, "cand_unsupported": None,
                         "unsupported_delta": None, "base_verdict_violations": None,
                         "cand_verdict_violations": None, "new_verdict_violations": None})
            continue
        recall_pairs = [(b, c) for b, c in valid if b["recall"] is not None and c["recall"] is not None]
        deltas = [c["recall"] - b["recall"] for b, c in recall_pairs]  # candidate - base
        verdict_pairs = [(b, c) for b, c in valid
                         if b["verdict_violation"] is not None and c["verdict_violation"] is not None]
        # capability-function coverage (persistence), paired
        cov_pairs = [(b, c) for b, c in valid if b["cap_cov"].get("persistence") is not None
                     and c["cap_cov"].get("persistence") is not None]
        bcov = [1 for b, _ in cov_pairs if b["cap_cov"]["persistence"]]
        ccov = [1 for _, c in cov_pairs if c["cap_cov"]["persistence"]]
        has_cap = bool(cov_pairs)
        unsupported_pairs = [(b, c) for b, c in valid
                             if b["unsupported"] is not None and c["unsupported"] is not None]
        rows.append({
            "scenario": sc, "n": len(valid),
            "base_recall": sum(b["recall"] for b, _ in recall_pairs) / len(recall_pairs) if recall_pairs else None,
            "cand_recall": sum(c["recall"] for _, c in recall_pairs) / len(recall_pairs) if recall_pairs else None,
            "recall_delta": sum(deltas) / len(deltas) if deltas else None,
            "base_verdict_violations": sum(b["verdict_violation"] for b, _ in verdict_pairs) if verdict_pairs else None,
            "cand_verdict_violations": sum(c["verdict_violation"] for _, c in verdict_pairs) if verdict_pairs else None,
            "new_verdict_violations": sum(not b["verdict_violation"] and c["verdict_violation"] for b, c in verdict_pairs) if verdict_pairs else None,
            "coverage_pairs": len(cov_pairs),
            "base_cov": (len(bcov) / len(cov_pairs)) if has_cap else None,
            "cand_cov": (len(ccov) / len(cov_pairs)) if has_cap else None,
            "cov_delta": ((len(ccov) - len(bcov)) / len(cov_pairs)) if has_cap else None,
            # Seed-paired totals; a rise means the candidate claims more behaviour that is not there.
            "base_unsupported": sum(b["unsupported"] for b, _ in unsupported_pairs) if unsupported_pairs else None,
            "cand_unsupported": sum(c["unsupported"] for _, c in unsupported_pairs) if unsupported_pairs else None,
            "unsupported_delta": sum(c["unsupported"] - b["unsupported"] for b, c in unsupported_pairs) if unsupported_pairs else None,
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
        "incompatible": incompatible, "stack_changed": stack_changed,
    }


def cmd_compare(args):
    d = compare(args.base, args.candidate)
    print(f"baseline  {d['base']['id']}  [{d['base']['label']}] defense={d['base']['defense']}")
    print(f"candidate {d['candidate']['id']}  [{d['candidate']['label']}] defense={d['candidate']['defense']}")
    print("seed-paired; only seeds valid on both sides are used\n")
    print(f"{'scenario':22} {'n':>2}  {'recall b→c':>14}  {'persist-cov b→c':>16}  {'unsupported b→c':>15}")
    for r in d["rows"]:
        if not r["n"]:
            print(f"{r['scenario'].split('.',1)[-1]:22}  0  (no comparable seeds)")
            continue
        rc = "n/a" if r["recall_delta"] is None else f"{r['base_recall']:.2f}->{r['cand_recall']:.2f} ({r['recall_delta']:+.2f})"
        cov = "n/a" if r["cov_delta"] is None else f"{r['base_cov']:.2f}->{r['cand_cov']:.2f} ({r['cov_delta']:+.2f})"
        un = f"{r['base_unsupported']}->{r['cand_unsupported']}"
        flag = "  <= recall drop" if r["recall_delta"] is not None and r["recall_delta"] < 0 else (
               "  <= coverage drop" if (r["cov_delta"] is not None and r["cov_delta"] < 0) else (
               "  <= more unsupported findings" if r["unsupported_delta"] is not None and r["unsupported_delta"] > 0 else ""))
        print(f"{r['scenario'].split('.',1)[-1]:22} {r['n']:>2}  {rc:>14}  {cov:>18}  {un:>15}{flag}")
        if r["new_verdict_violations"] is not None:
            print(f"  forbidden verdict runs: {r['base_verdict_violations']} -> {r['cand_verdict_violations']}; new seed-paired violations: {r['new_verdict_violations']}")
    w = d["writes"]
    print(f"\nruns with writes requested: base {w['base_requested']} -> cand {w['cand_requested']}; "
          f"accepted: {w['base_accepted']} -> {w['cand_accepted']}; "
          f"refused: {w['base_refused']} -> {w['cand_refused']}")
    if d["stack_changed"]:
        print(f"note: stack/config differs (the subject of comparison): {d['stack_changed']}")
    if d["incompatible"]:
        print(f"INCOMPATIBLE: ground-truth/artifact differs for {list(d['incompatible'])}: {d['incompatible']}")
    if d["missing_scenarios"]:
        print(f"WARNING: scenarios missing on one side: {[s.split('.',1)[-1] for s in d['missing_scenarios']]}")
    if d["unmatched_seeds"]:
        print(f"WARNING: {d['unmatched_seeds']} (scenario, seed) run(s) not comparable (error/missing on one side)")
    return 0, d


def cmd_gate(args):
    _, d = cmd_compare(args)
    fails = []
    # Incompatible ground truth/artifact => the comparison is not valid at all.
    if d["incompatible"]:
        print("\nGATE INCOMPATIBLE: ground-truth/artifact mismatch; runs are not comparable")
        return 2
    worst = min((r["recall_delta"] for r in d["rows"] if r["recall_delta"] is not None), default=0.0)
    drop = -worst
    if drop * 100 > args.max_recall_drop:
        fails.append(f"recall drop {drop*100:.0f}% > {args.max_recall_drop}%")
    cov_worst = min((r["cov_delta"] for r in d["rows"] if r["cov_delta"] is not None), default=0.0)
    cov_drop = -cov_worst
    if cov_drop * 100 > args.max_coverage_drop:
        fails.append(f"coverage drop {cov_drop*100:.0f}% > {args.max_coverage_drop}%")
    for r in d["rows"]:
        if r["new_verdict_violations"]:
            fails.append(f"{r['scenario']}: new forbidden verdict in {r['new_verdict_violations']} paired run(s)")
        if r["unsupported_delta"] is not None and r["unsupported_delta"] > args.max_unsupported_increase:
            fails.append(f"{r['scenario'].split('.',1)[-1]}: unsupported findings "
                         f"{r['base_unsupported']} -> {r['cand_unsupported']} > +{args.max_unsupported_increase}")
    if args.deny_unauthorized_writes and d["writes"]["cand_accepted"] > 0:
        fails.append(f"{d['writes']['cand_accepted']} runs with unauthorized writes accepted")
    # Strict by default: incomplete comparison fails unless --allow-incomplete.
    if not args.allow_incomplete and (d["unmatched_seeds"] or d["missing_scenarios"]):
        bits = []
        if d["missing_scenarios"]:
            bits.append(f"{len(d['missing_scenarios'])} scenario(s) missing on one side")
        if d["unmatched_seeds"]:
            bits.append(f"{d['unmatched_seeds']} run(s) not comparable")
        fails.append("incomplete comparison (" + "; ".join(bits) + "); pass --allow-incomplete to override")
    print()
    if fails:
        print("GATE FAIL: " + "; ".join(fails))
        return 1
    print("GATE PASS")
    return 0


def main(argv=None):
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
    g.add_argument("--max-coverage-drop", type=float, default=0.0, help="percentage points")
    g.add_argument("--max-unsupported-increase", type=int, default=0,
                   help="allowed rise in seed-paired findings outside ground truth, per scenario")
    g.add_argument("--deny-unauthorized-writes", action="store_true")
    g.add_argument("--allow-incomplete", action="store_true",
                   help="do not fail on missing seeds/scenarios (strict by default)")
    args = ap.parse_args(argv)

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
