"""Recompute every headline number in README.md and docs/PREREG.md from the raw runs.

usage: uv run python evidence/recompute.py
Prints each published value next to the value recomputed from evidence/<run>/runs.jsonl
and exits 1 if any differ. Only meta.json/runs.jsonl are read; scores.json and report.md
in each run are evaluator output, kept for reference.
"""
import json
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluator"))
import ral  # noqa: E402
from evaluate import mcnemar_exact  # noqa: E402

NATURAL, FORCED = "20261025T034615Z", "20261025T052952Z"
HEALTH, FORCED_ONE = "20261025T085023Z", "20261025T095403Z"
COV_BASE, COV_DEFENSE = "20261025T122507Z", "20261025T134206Z"


def scenarios():
    # Runs before meta.scenarios_resolved existed use the corpus definitions.
    out = {}
    for f in (ROOT / "corpus" / "scenarios").glob("*.yaml"):
        for s in yaml.safe_load(f.read_text())["scenarios"]:
            out[s["id"]] = s
    return out


def runs(run_id):
    lines = (HERE / run_id / "runs.jsonl").read_text().splitlines()
    return {(r["scenario"], r["seed"]): r for r in map(json.loads, filter(str.strip, lines))}


def persistence(run_id, sid):
    """seed -> persistence reported (None if the run errored)."""
    return {seed: (None if r.get("error") or not r.get("report") else "persistence" in r["report"]["findings"])
            for (s, seed), r in runs(run_id).items() if s == sid}


def decompiled(run_id, sid, fn):
    return sum(any(c["tool"] in ral.DECOMP_TOOLS and c.get("args", {}).get("name") == fn
                   and not c.get("is_error", False) and c.get("result_chars", 0) > 0 for c in r.get("calls", []))
               for (s, _), r in runs(run_id).items() if s == sid)


def paired_p(a, b):
    """Exact McNemar over seeds valid in both maps."""
    seeds = [s for s in a if s in b and a[s] is not None and b[s] is not None]
    return mcnemar_exact(sum(a[s] and not b[s] for s in seeds), sum(b[s] and not a[s] for s in seeds))


def count(m):
    return f"{sum(bool(v) for v in m.values())}/{len(m)}"


SC = scenarios()
A, H = "agent_fixture.", "health."
checks = []


def claim(source, label, published, computed):
    checks.append((source, label, published, computed))


nat = {k: persistence(NATURAL, A + k) for k in ("clean", "v9_symbol_neutral", "v10_symbol_misleading", "v2_symbol")}
claim("PREREG H1 / README", "natural persistence clean", "5/10", count(nat["clean"]))
claim("PREREG H1 / README", "natural persistence v9 (neutral name)", "0/10", count(nat["v9_symbol_neutral"]))
claim("PREREG H1", "natural persistence v10 (misleading name)", "2/10", count(nat["v10_symbol_misleading"]))
claim("PREREG H2", "natural persistence v2 (instruction)", "0/10", count(nat["v2_symbol"]))
fn = SC[A + "v9_symbol_neutral"]["capability_functions"]["persistence"]
claim("README", f"natural v9 runs that decompiled {fn}", "0/10",
      f"{decompiled(NATURAL, A + 'v9_symbol_neutral', fn)}/10")
claim("PREREG H1 / README", "McNemar clean vs v9 (natural)", "0.0625",
      f"{paired_p(nat['clean'], nat['v9_symbol_neutral']):.4f}")

for k in ("clean", "v9_symbol_neutral", "v10_symbol_misleading", "v2_symbol", "v6_banner_direct"):
    claim("PREREG forced", f"forced-decompile persistence {k}", "10/10", count(persistence(FORCED, A + k)))

hn = {k: persistence(HEALTH, H + k) for k in ("h_clean", "h_neutral", "h_mislead")}
fo = {k: persistence(FORCED_ONE, H + k) for k in ("h_neutral", "h_mislead")}
claim("PREREG health", "natural persistence h_clean", "5/10", count(hn["h_clean"]))
claim("PREREG health / README", "natural persistence h_neutral", "2/10", count(hn["h_neutral"]))
claim("PREREG health", "natural persistence h_mislead", "5/10", count(hn["h_mislead"]))
claim("PREREG health", "McNemar h_neutral vs h_clean (natural)", "0.45", f"{paired_p(hn['h_clean'], hn['h_neutral']):.2f}")
claim("PREREG health / README", "forced_one persistence h_neutral", "10/10", count(fo["h_neutral"]))
claim("PREREG health", "forced_one persistence h_mislead", "10/10", count(fo["h_mislead"]))
claim("PREREG health", "McNemar h_neutral natural vs forced_one", "0.0078",
      f"{paired_p(fo['h_neutral'], hn['h_neutral']):.4f}")
claim("PREREG health", "McNemar h_mislead natural vs forced_one", "0.0625",
      f"{paired_p(fo['h_mislead'], hn['h_mislead']):.4f}")

published = {"clean": ("0.00 → 1.00", "0.83 → 0.97"), "v9_symbol_neutral": ("0.00 → 1.00", "0.60 → 1.00"),
             "h_clean": ("0.10 → 1.00", "0.47 → 1.00"), "h_neutral": ("0.00 → 1.00", "0.47 → 1.00")}
d = ral.compare(str(HERE / COV_BASE), str(HERE / COV_DEFENSE))
for row in d["rows"]:
    name = row["scenario"].split(".", 1)[1]
    cov, rec = published[name]
    claim("README table", f"{name} persistence function in context", cov,
          f"{row['base_cov']:.2f} → {row['cand_cov']:.2f}")
    claim("README table", f"{name} capability recall", rec, f"{row['base_recall']:.2f} → {row['cand_recall']:.2f}")
claim("PREREG coverage", "findings outside ground truth natural → coverage-aware", "6 → 1",
      f"{sum(r['base_unsupported'] for r in d['rows'])} → {sum(r['cand_unsupported'] for r in d['rows'])}")

bad = 0
for source, label, pub, got in checks:
    ok = pub == got
    bad += not ok
    print(f"{'ok ' if ok else 'MISMATCH'} {label}: published {pub}, recomputed {got}  [{source}]")
print(f"\n{len(checks) - bad}/{len(checks)} published values reproduced from raw runs.")
sys.exit(1 if bad else 0)
