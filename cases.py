"""Freeze an observed scenario, controls and ELF artifacts for future releases."""
import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path

from .diagnostics import read_run


def _directory(state, name):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
        raise ValueError("case name must be lowercase letters/digits/hyphens, starting with a letter (max 64)")
    return Path(state) / "cases" / name


def save(state, name, run_dir, scenario, assets):
    dest = _directory(state, name)
    if dest.exists():
        raise ValueError(f"case {name!r} already exists; use a new name to retain provenance")
    meta, scenarios, records = read_run(run_dir)
    if scenario not in scenarios:
        raise ValueError(f"scenario {scenario!r} is absent from the source run")
    selected, pending = set(), [scenario]
    while pending:
        sid = pending.pop()
        if sid in selected:
            continue
        if sid not in scenarios:
            raise ValueError(f"source run is missing matched control {sid}; capture a run with its controls")
        selected.add(sid)
        sc = scenarios[sid]
        ctrl = sc.get("placebo") or sc.get("pair")
        if ctrl:
            pending.append(ctrl)
    seeds = sorted(meta.get("seeds", range(meta["repeats"])))
    if not seeds:
        raise ValueError("source scenario has no observed seeds")
    for sid in selected:
        for seed in seeds:
            record = records.get((sid, seed), {}).get("record")
            if not record or record.get("error") or record.get("report") is None:
                raise ValueError("case capture needs valid results for every selected scenario/control seed")
    manifest = meta.get("corpus_manifest", {}).get("variants", {})
    snapshot = [scenarios[s] for s in sorted(selected)]
    artifacts = {}
    for sc in snapshot:
        item = manifest.get(sc["variant"])
        if not item or not item.get("sha256"):
            raise ValueError("source run has no artifact hash for this scenario")
        rel = Path(item["path"])
        if rel.is_absolute() or ".." in rel.parts or rel.parts[:1] != ("build",):
            raise ValueError("artifact path must stay under build/")
        roots = [Path(run_dir).resolve().parent.parent, Path(state)]
        options = [root / rel for root in roots]
        options.append(Path(assets) / "corpus/artifacts" / Path(*rel.parts[1:]))
        source = next((p for p in options if p.is_file() and
                       hashlib.sha256(p.read_bytes()).hexdigest() == item["sha256"]), None)
        if source is None:
            raise ValueError(f"original artifact unavailable or hash changed for {sc['id']}")
        if source.read_bytes()[:4] != b"\x7fELF":
            raise ValueError("case artifacts must be ELF files; no host execution is performed")
        artifacts[sc["variant"]] = (item, source)
    tasks = meta.get("task_prompts", {})
    if any(not isinstance(tasks.get(sc["task"]), str) for sc in snapshot):
        raise ValueError("source run has no frozen task prompt")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".capture-", dir=dest.parent) as tmp:
        bundle = Path(tmp)
        for item, source in artifacts.values():
            p = bundle / item["path"]; p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, p)
        doc = {"schema": "ral.case.v1", "name": name, "source_run": meta["run_id"],
               "primary_scenario": scenario, "seeds": seeds, "scenarios_resolved": snapshot,
               "task_prompts": {sc["task"]: tasks[sc["task"]] for sc in snapshot},
               "corpus_manifest": {"variants": {v: item for v, (item, _) in artifacts.items()}}}
        (bundle / "case.json").write_text(json.dumps(doc, indent=2) + "\n")
        (bundle / "observed.jsonl").write_text("".join(json.dumps(records[(sid, seed)]["record"]) + "\n"
                                                for sid in sorted(selected) for seed in seeds))
        # Rename a fully written capsule; no partial case is registered.
        bundle.rename(dest)
    return dest


def load(state, name):
    root = _directory(state, name)
    doc = json.loads((root / "case.json").read_text())
    if doc.get("schema") != "ral.case.v1" or doc.get("name") != name:
        raise ValueError("invalid case schema/name")
    seeds = doc.get("seeds")
    if not isinstance(seeds, list) or not seeds or any(type(s) is not int or s < 0 for s in seeds) or len(set(seeds)) != len(seeds):
        raise ValueError("invalid case seed list")
    for item in doc["corpus_manifest"]["variants"].values():
        p = (root / item["path"]).resolve()
        if not p.is_relative_to(root.resolve() / "build"):
            raise ValueError("case artifact path escapes build/")
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("case artifact hash mismatch")
    return root, doc
