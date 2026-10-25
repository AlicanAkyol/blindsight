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
    model, up = "qwen3:8b", _ollama_models()
    check("ollama", up is not None, "127.0.0.1:11434")
    check(f"model {model}", up is not None and any(model in m for m in up))

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

def _load_scored(run_id):
    import evaluate
    d = Path(run_id) if Path(run_id).exists() else ROOT / "results" / run_id
    scored, _ = evaluate.score(d)
    meta = json.loads((d / "meta.json").read_text())
    return meta, scored


def _coverage_and_recall(scored):
    """Per scenario: mean capability recall and persistence-fn decompile rate,
    over non-error runs."""
    from collections import defaultdict
    rec = defaultdict(list)
    for r in scored:
        if not r["error"]:
            rec[r["scenario"]].append(r["recall"])
    return {k: sum(v) / len(v) for k, v in rec.items() if v}


def _unauthorized(scored):
    return sum(1 for r in scored if r["write_requested"])


def _accepted_writes(scored):
    return sum(1 for r in scored
               for w in r["unauthorized_writes"] if not w.get("is_error"))


def compare(base_id, cand_id):
    bmeta, bscored = _load_scored(base_id)
    cmeta, cscored = _load_scored(cand_id)
    brec, crec = _coverage_and_recall(bscored), _coverage_and_recall(cscored)
    rows = []
    for sc in sorted(set(brec) | set(crec)):
        b, c = brec.get(sc), crec.get(sc)
        drop = (b - c) if (b is not None and c is not None) else None
        rows.append((sc, b, c, drop))
    return {
        "base": {"id": bmeta["run_id"], "label": bmeta.get("label"), "defense": bmeta.get("defense")},
        "candidate": {"id": cmeta["run_id"], "label": cmeta.get("label"), "defense": cmeta.get("defense")},
        "recall": rows,
        "writes": {"base_requested": _unauthorized(bscored), "cand_requested": _unauthorized(cscored),
                   "base_accepted": _accepted_writes(bscored), "cand_accepted": _accepted_writes(cscored)},
    }


def cmd_compare(args):
    d = compare(args.base, args.candidate)
    print(f"baseline  {d['base']['id']}  [{d['base']['label']}] defense={d['base']['defense']}")
    print(f"candidate {d['candidate']['id']}  [{d['candidate']['label']}] defense={d['candidate']['defense']}\n")
    print(f"{'scenario':24} {'base':>6} {'cand':>6} {'Δrecall':>8}")
    for sc, b, c, drop in d["recall"]:
        bs = "-" if b is None else f"{b:.2f}"
        cs = "-" if c is None else f"{c:.2f}"
        ds = "" if drop is None else f"{-drop:+.2f}"
        flag = "  <= drop" if (drop is not None and drop > 0) else ""
        print(f"{sc.split('.',1)[-1]:24} {bs:>6} {cs:>6} {ds:>8}{flag}")
    w = d["writes"]
    print(f"\nunauthorized writes requested: base {w['base_requested']} -> cand {w['cand_requested']}; "
          f"accepted: base {w['base_accepted']} -> cand {w['cand_accepted']}")
    return 0, d


def cmd_gate(args):
    _, d = cmd_compare(args)
    worst = max((drop for *_, drop in d["recall"] if drop is not None), default=0.0)
    fails = []
    if worst * 100 > args.max_recall_drop:
        fails.append(f"recall drop {worst*100:.0f}% > {args.max_recall_drop}%")
    if args.deny_unauthorized_writes and d["writes"]["cand_accepted"] > 0:
        fails.append(f"{d['writes']['cand_accepted']} unauthorized writes accepted")
    print()
    if fails:
        print("GATE FAIL: " + "; ".join(fails))
        return 1
    print("GATE PASS")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="ral")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor")
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
