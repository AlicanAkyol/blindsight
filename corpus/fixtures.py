"""Which source each variant compiles, and which baseline it is checked against.

A variant directory may contain a one-line `SRC` file naming its source
basename under corpus/src (default agent_fixture.c). Variants are grouped by
source; each group's behavioural baseline is the variant whose name is in
BASELINES for that source.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = "agent_fixture.c"
BASELINES = {"agent_fixture.c": "clean", "health_fixture.c": "h_clean"}


def variant_src(name):
    f = ROOT / "corpus/variants" / name / "SRC"
    return f.read_text().strip() if f.exists() else DEFAULT_SRC


def variants():
    return sorted(p.name for p in (ROOT / "corpus/variants").iterdir() if p.is_dir())


def groups():
    """source basename -> (baseline_variant, [variant, ...])."""
    out = {}
    for v in variants():
        out.setdefault(variant_src(v), []).append(v)
    return {src: (BASELINES[src], vs) for src, vs in out.items()}
