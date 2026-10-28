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
import os
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agents import AGENTS  # noqa: E402
import llm_agent  # noqa: E402
from tasks import TASKS  # noqa: E402
from inputs import opaque_binary
from measurement import PROTOCOL, IDENTITY_PROTOCOL

ROOT = Path(os.environ.get("RAL_HOME", Path(__file__).resolve().parent.parent))
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


ARM = "natural"       # set from --arm / profile
DEFENSE = "unsafe-default"  # set from --defense / profile; "read-only" blocks write tools


def resolve_agent(name):
    if name.startswith("ollama:"):
        return llm_agent.make_agent(name.removeprefix("ollama:"), arm=ARM)
    return AGENTS[name]


def agent_info(name):
    if name.startswith("ollama:"):
        return llm_agent.model_info(name.removeprefix("ollama:"))
    return {"mock": True}


async def run_one(agent_name, scenario, repeat, binary_root=None, task_prompts=None):
    binary = Path(binary_root or ROOT) / "build" / scenario["variant"] / scenario["sample"]
    started = time.time()
    record = {"agent": agent_name, "scenario": scenario["id"], "repeat": repeat, "seed": repeat}
    try:
        with opaque_binary(binary) as opaque:
            return await _analyse_opaque(agent_name, scenario, repeat, task_prompts, opaque, record, started)
    except Exception as e:
        record.update(error=f"{type(e).__name__}: {e}", report=None, calls=[])
    record["seconds"] = round(time.time() - started, 1)
    return record


async def _analyse_opaque(agent_name, scenario, repeat, task_prompts, opaque, record, started):
    from ghidra_session import ghidra
    try:
        async with ghidra(opaque, read_only=(DEFENSE == "read-only")) as session:
            kwargs = {"seed": repeat}
            if agent_name.startswith("ollama:"):
                kwargs["force_functions"] = scenario.get("force_functions")
            task = {"prompt": task_prompts[scenario["task"]]} if task_prompts else TASKS[scenario["task"]]
            report = await resolve_agent(agent_name)(session, task, **kwargs)
            record.update(report=report, calls=session.calls, trace=session.extra)
            if report is None:
                record["error"] = "no parsable report"
    except Exception as e:  # a crashed run is recorded, never silently dropped
        record.update(error=f"{type(e).__name__}: {e}", report=None, calls=[])
    record["seconds"] = round(time.time() - started, 1)
    return record


async def run_suite(agents, ids=None, only=None, repeats=1, arm="natural",
                    defense="unsafe-default", label=None, scenario_snapshot=None,
                    seeds=None, binary_root=None, task_prompts=None):
    """Programmatic entry used by the ral CLI. Returns the run_id."""
    global ARM, DEFENSE
    from ghidra_session import GHIDRA_DIR
    ARM, DEFENSE = arm, defense

    scenarios = list(scenario_snapshot) if scenario_snapshot is not None else load_scenarios()
    if ids:
        want = set(ids)
        scenarios = [s for s in scenarios if s["id"] in want or s["id"].split(".", 1)[1] in want]
    elif only:
        scenarios = [s for s in scenarios if only in s["id"]]
    if not scenarios:
        raise ValueError("No scenarios selected; check suite IDs")
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    seeds = list(range(repeats)) if seeds is None else list(seeds)
    if not seeds or any(type(s) is not int or s < 0 for s in seeds) or len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be distinct non-negative integers")
    if ids:
        matched = {s["id"] for s in scenarios} | {s["id"].split(".", 1)[1] for s in scenarios}
        if set(ids) - matched:
            raise ValueError(f"Unknown scenario IDs: {sorted(set(ids) - matched)}")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out_dir = ROOT / "results" / run_id
    out_dir.mkdir(parents=True)

    artifact_root = Path(binary_root or ROOT)
    if binary_root:
        manifest = json.loads((artifact_root / "case.json").read_text())["corpus_manifest"]
    else:
        manifest = json.loads((ROOT / "build/manifest.json").read_text())
    meta = {
        "run_id": run_id, "label": label,
        "measurement_protocol": PROTOCOL, "input_paths": "opaque-v1",
        "coverage_identity_protocol": IDENTITY_PROTOCOL,
        "agents": {a: agent_info(a) for a in agents},
        "repeats": len(seeds), "seeds": seeds, "arm": arm, "defense": defense,
        "task_prompts": task_prompts or {k: v["prompt"] for k, v in TASKS.items()},
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
        for agent in agents:
            for sc in scenarios:
                for r in seeds:
                    rec = await run_one(agent, sc, r, binary_root=binary_root, task_prompts=task_prompts)
                    f.write(json.dumps(rec) + "\n")
                    f.flush()
                    status = rec.get("error") or (rec["report"] or {}).get("verdict")
                    print(f"{agent:15} {sc['id']:28} r{r} {rec['seconds']:6}s  {status}")
    print(f"\nresults/{run_id}")
    return run_id


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", nargs="+", default=list(AGENTS))
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--only", help="substring filter on scenario id")
    ap.add_argument("--ids", nargs="+", help="exact scenario ids (overrides --only)")
    ap.add_argument("--arm", choices=["natural", "forced_decompile", "forced_one", "coverage_aware"],
                    default="natural",
                    help="forced_decompile: decompile every user function first; "
                         "forced_one: decompile only the scenario's force_functions; "
                         "coverage_aware: decompile import/xref-selected functions")
    ap.add_argument("--defense", choices=["unsafe-default", "read-only"], default="unsafe-default")
    args = ap.parse_args()
    await run_suite(args.agents, ids=args.ids, only=args.only, repeats=args.repeats,
                    arm=args.arm, defense=args.defense)


if __name__ == "__main__":
    asyncio.run(main())
