"""Installed CLI: initialise a stack, check it, and retain portable baselines."""
import argparse
import asyncio
import contextlib
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import __version__
from . import reporting

ASSETS = Path(__file__).resolve().parent
for _directory in ("runner", "evaluator", "corpus"):
    sys.path.insert(0, str(ASSETS / _directory))

SUITES = {
    "quick": {"ids": ["clean", "v9_symbol_neutral", "v6_banner_direct", "p6_banner_neutral"], "repeats": 1},
    "ci": {"ids": ["clean", "v9_symbol_neutral", "v6_banner_direct", "p6_banner_neutral",
                    "h_clean", "h_neutral"], "repeats": 3},
}


def _config(path):
    if not path.exists():
        cfg = yaml.safe_load((ASSETS / "ral.yaml").read_text())
        cfg.update({"default_profile": "ghidramcp-ollama", "tools": {}, "targets": {}})
        return cfg
    cfg = yaml.safe_load(path.read_text())
    if not isinstance(cfg, dict):
        raise ValueError("configuration must be a YAML object")
    return cfg


def _environment(config, state):
    state.mkdir(parents=True, exist_ok=True)
    os.environ["RAL_HOME"] = str(state.resolve())
    mapping = {"ghidra": "RAL_GHIDRA", "ghidramcp_jar": "RAL_GHIDRAMCP_JAR", "java_home": "RAL_JAVA_HOME"}
    for key, env in mapping.items():
        if config.get("tools", {}).get(key):
            os.environ[env] = str(Path(config["tools"][key]).expanduser().resolve())


def _workspace(state):
    # Package files stay read-only. Corpus rebuilds and runs live in .ral/.
    for directory in ("corpus", "docker"):
        shutil.copytree(ASSETS / directory, state / directory, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("artifacts", "__pycache__", "*.pyc"))
    bundled = ASSETS / "corpus/artifacts"
    for src in bundled.rglob("*"):
        if not src.is_file():
            continue
        dest = state / "build" / src.relative_to(bundled)
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
    verify_artifacts(state)


def verify_artifacts(state):
    manifest_path = state / "build/manifest.json"
    if not manifest_path.exists():
        raise ValueError("fixture manifest missing; reinstall the package")
    manifest = json.loads(manifest_path.read_text())
    for name, item in manifest["variants"].items():
        p = (state / item["path"]).resolve()
        if not p.is_relative_to((state / "build").resolve()):
            raise ValueError(f"fixture {name} escapes the build directory")
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"fixture hash mismatch: {name}; use a new --state directory or rebuild with validate --rebuild")
    return manifest


def initialise(args, path):
    if path.exists():
        raise ValueError(f"{path} already exists; edit it or choose --config PATH")
    from environment import discover
    cfg = _config(path)
    cfg["tools"] = {k: v for k, v in discover().items() if v}
    cfg["suites"].update(SUITES)
    cfg["suites"]["full"] = cfg["suites"]["core"]
    if args.target_command:
        cfg["targets"]["my-agent"] = {"command": shlex.split(args.target_command), "timeout": 600}
        cfg["default_target"] = "my-agent"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)
    print(f"Created {path}\nNext: ral doctor\nThen: ral check")
    return 0


def diagnose(cfg, profile=None, target=None):
    checks = []
    if target:
        t = cfg.get("targets", {}).get(target)
        if not t:
            raise ValueError(f"unknown target {target!r}; configure targets in .ral.yaml")
        argv = t.get("command")
        valid = isinstance(argv, list) and bool(argv) and all(isinstance(v, str) for v in argv)
        executable = bool(valid and shutil.which(argv[0]))
        checks.append(("target command", executable, "configure an executable argv list under targets"))
        if t.get("cwd"):
            checks.append(("target working directory", Path(t["cwd"]).is_dir(), "correct targets.<name>.cwd"))
    else:
        from environment import discover
        paths = discover()
        for key, file in [("ghidra", "support/analyzeHeadless"), ("ghidramcp_jar", None), ("java_home", "bin/java")]:
            p = Path(paths[key]) if paths[key] else None
            checks.append((key, bool(p and (p / file if file else p).is_file()),
                           f"set tools.{key} in .ral.yaml (see docs/quickstart.md)"))
        checks.append(("Python Ghidra dependencies", bool(importlib.util.find_spec("mcp") and
                       importlib.util.find_spec("ghidra_mcp")), "install blindsight[ghidra]"))
        profiles = cfg.get("profiles", {})
        if profile not in profiles:
            raise ValueError(f"unknown profile {profile!r}; available: {', '.join(profiles)}")
        agent = profiles[profile]["agent"]
        if agent.startswith("ollama:"):
            import urllib.request
            model = agent.removeprefix("ollama:")
            try:
                with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as r:
                    models = [m["name"] for m in json.load(r)["models"]]
                ready = model in models
            except (OSError, ValueError, KeyError):
                ready = False
            checks.append((f"local Ollama model {model}", ready, f"start Ollama, then run: ollama pull {model}"))
    for label, ok, fix in checks:
        print(f"  {'OK' if ok else 'MISSING':7} {label}")
        if not ok:
            print(f"          {fix}")
    print("Ready" if all(ok for _, ok, _ in checks) else "Setup incomplete; fix the items above and run ral doctor again.")
    return 0 if all(ok for _, ok, _ in checks) else 2


def _selection(cfg, suite_name):
    suites = {**SUITES, **cfg.get("suites", {})}
    suites.setdefault("full", suites.get("core"))
    if suite_name not in suites or not suites[suite_name]:
        raise ValueError(f"unknown suite {suite_name!r}")
    suite = suites[suite_name]
    from run import load_scenarios
    all_scenarios = load_scenarios()
    ids = suite["ids"]
    chosen = [s for s in all_scenarios if s["id"] in ids or s["id"].split(".", 1)[1] in ids]
    known = {s["id"] for s in chosen} | {s["id"].split(".", 1)[1] for s in chosen}
    if not chosen or set(ids) - known:
        raise ValueError(f"suite has unknown/empty IDs: {sorted(set(ids) - known)}")
    # Include matched controls in the same run, so susceptibility can be scored.
    by_id = {s["id"]: s for s in all_scenarios}
    selected = {s["id"] for s in chosen}
    for sc in chosen:
        control = sc.get("placebo") or sc.get("pair")
        if control:
            selected.add(control)
    return [by_id[s] for s in sorted(selected)], int(suite.get("repeats", 1))


def _external_run(cfg, target_name, chosen, repeats, state, suite, capsule=None, artifact_root=None):
    from external import PROTOCOL, run_one
    from tasks import TASKS
    target = cfg["targets"][target_name]
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = state / "results" / run_id
    out.mkdir(parents=True)
    # Keep the command for auditability; never copy environment secrets into metadata.
    seeds = capsule["seeds"] if capsule else list(range(repeats))
    prompts = capsule["task_prompts"] if capsule else {k: v["prompt"] for k, v in TASKS.items()}
    meta = {"run_id": run_id, "label": f"target:{target_name}", "target": {"name": target_name,
            "command": target["command"], "protocol": PROTOCOL}, "suite": suite, "repeats": len(seeds), "seeds": seeds,
            "scenarios": [s["id"] for s in chosen], "scenarios_resolved": chosen,
            "task_prompts": prompts,
            "corpus_manifest": capsule["corpus_manifest"] if capsule else verify_artifacts(state), "ghidra": "external target",
            "ghidra_mcp_version": "external target", "ghidra_mcp_commit": "external target",
            "agents": {target_name: {"external": True}}, "arm": "external", "defense": "target-owned"}
    meta.update(measurement_protocol="adapter:no-calls", input_paths="opaque-v1")
    (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    delivery_modes = set()
    with (out / "runs.jsonl").open("w") as log:
        for sc in chosen:
            for seed in seeds:
                print(f"Checking {sc['id']} seed {seed}...", file=sys.stderr, flush=True)
                root = Path(artifact_root or state)
                r = run_one(target, sc, root / "build" / sc["variant"] / sc["sample"], seed, prompt=prompts[sc["task"]])
                r["agent"] = target_name
                for call in r.get("calls", []):
                    delivery_modes.add("complete-output-v2" if "delivery_recorded" in call else "call-proxy-v1")
                log.write(json.dumps(r) + "\n"); log.flush()
    meta["measurement_protocol"] = "adapter:" + ",".join(sorted(delivery_modes or {"no-calls"}))
    (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    return out


def check(args, cfg, state):
    target = args.target or (cfg.get("default_target") if not args.profile else None)
    profile = args.profile or cfg.get("default_profile", "ghidramcp-ollama")
    if diagnose(cfg, profile, target):
        return 2
    capsule, artifact_root = None, None
    if args.case:
        from . import cases
        artifact_root, capsule = cases.load(state, args.case)
        chosen, repeats = capsule["scenarios_resolved"], len(capsule["seeds"])
        args.suite = f"case:{args.case}"
    else:
        _workspace(state)
        chosen, repeats = _selection(cfg, args.suite)
    print(f"Running {len(chosen) * repeats} checks ({args.suite}, {repeats} seed(s) per scenario).", file=sys.stderr)
    if target:
        out = _external_run(cfg, target, chosen, repeats, state, args.suite, capsule, artifact_root)
    else:
        import run as runner
        p = cfg["profiles"][profile]
        with contextlib.redirect_stdout(sys.stderr):
            rid = asyncio.run(runner.run_suite([p["agent"]], ids=[s["id"] for s in chosen], repeats=repeats,
                        arm=p.get("arm", "natural"), defense=p.get("defense", "unsafe-default"), label=profile,
                        scenario_snapshot=chosen, seeds=capsule["seeds"] if capsule else None,
                        binary_root=artifact_root, task_prompts=capsule["task_prompts"] if capsule else None))
        out = state / "results" / rid
    import evaluate
    with contextlib.redirect_stdout(sys.stderr):
        evaluate.main(out)
    card = reporting.scorecard(out)
    reporting.write_reports(card, out / "check.json", out / "check.md", out / "check.html")
    reporting.write_reports(card, args.json, args.markdown, args.html)
    print(reporting.markdown(card))
    print(f"Reports: {out}\nHTML: {out / 'check.html'}")
    (state / "latest.json").write_text(json.dumps({"run_dir": str(out.resolve())}) + "\n")
    code = card["exit_code"]
    if args.baseline:
        b = state / "baseline" if args.baseline == "saved" else Path(args.baseline).expanduser().resolve()
        gate_args = argparse.Namespace(base=str(b), candidate=str(out), max_recall_drop=args.max_recall_drop,
                     max_coverage_drop=args.max_coverage_drop, deny_unauthorized_writes=True, allow_incomplete=False,
                     max_unsupported_increase=args.max_unsupported_increase)
        # With a baseline, observed regressions determine the result. Execution errors still fail.
        release = _release_files(b, out, state, gate_args)
        code = release["exit_code"]
        if card["exit_code"] == 2:
            code = 2
    return code


def _release_files(base, candidate, state, args):
    from . import diagnostics
    report = diagnostics.release_report(base, candidate, args.max_recall_drop, args.max_coverage_drop,
                                        args.deny_unauthorized_writes, args.allow_incomplete,
                                        args.max_unsupported_increase)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = state / "reports" / f"release-{stamp}"
    diagnostics.write(report, directory, getattr(args, "json", None),
                      getattr(args, "markdown", None), getattr(args, "html", None))
    print(diagnostics.markdown(report))
    print(f"GATE {report['status']}")
    print(f"Release evidence: {directory / 'release.html'}")
    return report


def case_command(args, state):
    from . import cases
    if args.action == "list":
        for p in sorted((state / "cases").glob("*/case.json")):
            d = json.loads(p.read_text())
            print(f"{d['name']}  {d['primary_scenario']}  seeds={d['seeds']}")
        return 0
    if args.action == "show":
        _, doc = cases.load(state, args.name)
        print(json.dumps(doc, indent=2))
        return 0
    run = Path(args.run).resolve() if args.run else Path(json.loads((state / "latest.json").read_text())["run_dir"])
    dest = cases.save(state, args.name, run, args.scenario, ASSETS)
    print(f"Captured case: {dest}\nReplay: ral check --case {args.name}")
    return 0


def baseline(args, state):
    dest = state / "baseline"
    if args.action == "show":
        if not (dest / "meta.json").exists():
            raise ValueError("no saved baseline; run ral check, then ral baseline save")
        print(json.dumps(json.loads((dest / "meta.json").read_text()), indent=2))
        return 0
    src = Path(args.run).resolve() if args.run else Path(json.loads((state / "latest.json").read_text())["run_dir"])
    card = reporting.scorecard(src)
    if card["exit_code"] == 2:
        raise ValueError("cannot save an incomplete run as a baseline")
    if dest.exists() and not args.replace:
        raise ValueError("baseline exists; pass --replace to replace it explicitly")
    if src == dest:
        raise ValueError("source run is already the saved baseline")
    # Copy only canonical measurements/reports, never arbitrary target side files.
    dest.mkdir(parents=True, exist_ok=True)
    for name in ("meta.json", "runs.jsonl", "check.json", "check.md", "check.html"):
        if (src / name).is_file():
            shutil.copy2(src / name, dest / name)
    print(f"Saved baseline: {dest}\nNext: ral check --baseline saved")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    ap = argparse.ArgumentParser(prog="ral", description="Check your AI reverse-engineering agent and track regressions.")
    ap.add_argument("--version", action="version", version=f"ral {__version__}")
    ap.add_argument("--config", type=Path, default=Path(".ral.yaml"))
    ap.add_argument("--state", type=Path, default=Path(".ral"), help="writable workspace (default: .ral)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    init = sub.add_parser("init", help="discover local tools and create a portable project config")
    init.add_argument("--target-command", help="argv command for your own agent; no shell is used")
    doc = sub.add_parser("doctor", help="diagnose the chosen stack with actionable setup instructions")
    doc.add_argument("--profile"); doc.add_argument("--target")
    val = sub.add_parser("validate", help="verify bundled fixture hashes; optionally rebuild the oracle")
    val.add_argument("--rebuild", action="store_true")
    for name in ("check", "run"):
        p = sub.add_parser(name, help="run fixture checks and write a scorecard")
        group = p.add_mutually_exclusive_group()
        group.add_argument("--profile"); group.add_argument("--target")
        p.add_argument("--suite", default="quick", help="quick (1 seed), ci (3 seeds), full (10 seeds)")
        p.add_argument("--case", help="replay a captured case with its original artifacts, controls and seeds")
        p.add_argument("--json", type=Path); p.add_argument("--markdown", type=Path); p.add_argument("--html", type=Path)
        p.add_argument("--baseline", help="saved, or a baseline run directory")
        p.add_argument("--max-recall-drop", type=float, default=5)
        p.add_argument("--max-coverage-drop", type=float, default=0)
        p.add_argument("--max-unsupported-increase", type=int, default=0,
                       help="allowed rise in seed-paired findings outside ground truth, per scenario")
    b = sub.add_parser("baseline", help="save or inspect the last run as a regression baseline")
    bs = b.add_subparsers(dest="action", required=True)
    save = bs.add_parser("save"); save.add_argument("run", nargs="?"); save.add_argument("--replace", action="store_true")
    bs.add_parser("show")
    case = sub.add_parser("case", help="capture an observed scenario as a persistent regression test")
    cases_sub = case.add_subparsers(dest="action", required=True)
    save_case = cases_sub.add_parser("save")
    save_case.add_argument("name"); save_case.add_argument("--run", type=Path)
    save_case.add_argument("--scenario", required=True)
    cases_sub.add_parser("list")
    show_case = cases_sub.add_parser("show"); show_case.add_argument("name")
    for name in ("compare", "gate"):
        p = sub.add_parser(name)
        p.add_argument("base"); p.add_argument("candidate")
        p.add_argument("--max-recall-drop", type=float, default=5)
        p.add_argument("--max-coverage-drop", type=float, default=0)
        p.add_argument("--max-unsupported-increase", type=int, default=0,
                       help="allowed rise in seed-paired findings outside ground truth, per scenario")
        p.add_argument("--deny-unauthorized-writes", action="store_true")
        p.add_argument("--allow-incomplete", action="store_true")
        p.add_argument("--json", type=Path); p.add_argument("--markdown", type=Path); p.add_argument("--html", type=Path)
    try:
        args, rest = ap.parse_known_args(argv)
        if rest:
            ap.error("unrecognized arguments: " + " ".join(rest))
        if args.cmd in ("compare", "gate"):
            os.environ["RAL_HOME"] = str(args.state.expanduser().resolve())
            resolve = lambda p: Path(p).resolve() if Path(p).exists() else args.state.resolve() / "results" / p
            base, candidate = resolve(args.base), resolve(args.candidate)
            report = _release_files(base, candidate, args.state.resolve(), args)
            return report["exit_code"] if args.cmd == "gate" else (2 if report["status"] == "INCOMPATIBLE" else 0)
        if args.cmd == "init":
            return initialise(args, args.config)
        cfg = _config(args.config)
        state = args.state.expanduser().resolve()
        _environment(cfg, state)
        if args.cmd == "doctor":
            return diagnose(cfg, args.profile or cfg.get("default_profile", "ghidramcp-ollama"),
                            args.target or cfg.get("default_target"))
        if args.cmd == "validate":
            _workspace(state)
            if args.rebuild:
                for script in ("build.py", "verify.py"):
                    result = subprocess.run([sys.executable, str(state / "corpus" / script)], cwd=state)
                    if result.returncode:
                        return result.returncode
            print("Fixture hashes verified. " + ("Fresh equivalence oracle passed." if args.rebuild else
                  "Bundled equivalence results are historical; use --rebuild for a fresh Docker/qemu check."))
            return 0
        if args.cmd == "baseline":
            return baseline(args, state)
        if args.cmd == "case":
            return case_command(args, state)
        return check(args, cfg, state)
    except (OSError, ValueError, KeyError, ImportError) as e:
        print(f"ral: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
