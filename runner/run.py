#!/usr/bin/env python3
"""Run agents against corpus scenarios and record raw results.

usage: uv run python runner/run.py --agents rule_agent gullible_agent [--repeats 1]
       uv run python runner/run.py --agents ollama:qwen3:8b --repeats 5

Repeat r uses seed r. The seed fixes the sampling stream; it does not
guarantee bit-identical output, since Ollama/GPU/runtime determinism is not
verified here.

Writes results/<run_id>/meta.json and results/<run_id>/runs.jsonl. Each
scenario run gets a fresh GhidraMCP headless session, so write actions from
one run can never leak into the next.
"""
import argparse
import asyncio
import json
import platform
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agents import AGENTS  # noqa: E402
from ghidra_session import GHIDRA_DIR, ghidra  # noqa: E402
import llm_agent  # noqa: E402
from tasks import TASKS  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
GHIDRA_MCP_COMMIT = "1e980252087b2479a21b9ca6d82d5829538651a7"


def _git(*args):
    import subprocess
    try:
        return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True).stdout.strip()
    except Exception:
        return None


def load_scenarios():
    out = []
    for f in sorted((ROOT / "corpus/scenarios").glob("*.yaml")):
        doc = yaml.safe_load(f.read_text())
        for sc in doc["scenarios"]:
            out.append({"task": doc["task"], **doc["defaults"], **sc})
    return out


ARM = "natural"  # set from --arm in main()


def resolve_agent(name):
    if name.startswith("ollama:"):
        return llm_agent.make_agent(name.removeprefix("ollama:"), arm=ARM)
    return AGENTS[name]


def agent_info(name):
    if name.startswith("ollama:"):
        return llm_agent.model_info(name.removeprefix("ollama:"))
    return {"mock": True}


async def run_one(agent_name, scenario, repeat):
    binary = ROOT / "build" / scenario["variant"] / scenario["sample"]
    started = time.time()
    record = {"agent": agent_name, "scenario": scenario["id"], "repeat": repeat, "seed": repeat}
    try:
        async with ghidra(binary) as session:
            report = await resolve_agent(agent_name)(session, TASKS[scenario["task"]], seed=repeat)
            record.update(report=report, calls=session.calls, trace=session.extra)
            if report is None:
                record["error"] = "no parsable report"
    except Exception as e:  # a crashed run is recorded, never silently dropped
        record.update(error=f"{type(e).__name__}: {e}", report=None, calls=[])
    record["seconds"] = round(time.time() - started, 1)
    return record


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", nargs="+", default=list(AGENTS))
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--only", help="substring filter on scenario id")
    ap.add_argument("--ids", nargs="+", help="exact scenario ids (overrides --only)")
    ap.add_argument("--arm", choices=["natural", "forced_decompile"], default="natural",
                    help="forced_decompile: harness decompiles every user function first")
    args = ap.parse_args()
    global ARM
    ARM = args.arm

    scenarios = load_scenarios()
    if args.ids:
        want = set(args.ids)
        scenarios = [s for s in scenarios if s["id"] in want or s["id"].split(".", 1)[1] in want]
    elif args.only:
        scenarios = [s for s in scenarios if args.only in s["id"]]
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "results" / run_id
    out_dir.mkdir(parents=True)

    manifest = json.loads((ROOT / "build/manifest.json").read_text())
    meta = {
        "run_id": run_id,
        "agents": {a: agent_info(a) for a in args.agents},
        "repeats": args.repeats,
        "arm": args.arm,
        "task_prompts": {k: v["prompt"] for k, v in TASKS.items()},
        "scenarios": [s["id"] for s in scenarios],
        # Full resolved scenario objects, so re-scoring uses the definitions as
        # they were at run time, not whatever the YAML says later.
        "scenarios_resolved": scenarios,
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "ghidra": GHIDRA_DIR.name,
        "ghidra_mcp_commit": GHIDRA_MCP_COMMIT,
        "ghidra_mcp_version": version("ghidra-mcp"),
        "corpus_manifest": manifest,
        "host": {"python": platform.python_version(), "machine": platform.machine(),
                 "system": f"{platform.system()} {platform.release()}"},
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    with open(out_dir / "runs.jsonl", "w") as f:
        for agent in args.agents:
            for sc in scenarios:
                for r in range(args.repeats):
                    rec = await run_one(agent, sc, r)
                    f.write(json.dumps(rec) + "\n")
                    f.flush()
                    status = rec.get("error") or (rec["report"] or {}).get("verdict")
                    print(f"{agent:15} {sc['id']:28} r{r} {rec['seconds']:6}s  {status}")
    print(f"\nresults/{run_id}")


if __name__ == "__main__":
    asyncio.run(main())
