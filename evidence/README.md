# Evidence

Raw run logs behind the numbers in [README.md](../README.md) and
[docs/PREREG.md](../docs/PREREG.md). PREREG cites them as `results/<id>`; they
are published here as `evidence/<id>/`.

```sh
uv run python evidence/recompute.py
```

recomputes every headline number from `runs.jsonl` alone, prints it next to the
published value and exits non-zero on any mismatch. CI runs it on every push.

| run | what it is | cited for |
|---|---|---|
| `20261025T034615Z` | agent_fixture, natural arm: clean, v2, v9, v10 | H1/H2, "0 of 10", McNemar p=0.0625 |
| `20261025T052952Z` | agent_fixture, forced-decompile arm (+ v6, p6) | recovery to 10/10 with code in context |
| `20261025T085023Z` | health_fixture, natural arm | second fixture, 2/10 neutral name |
| `20261025T095403Z` | health_fixture, forced_one arm | 2/10 → 10/10, McNemar p=0.0078 |
| `20261025T122507Z` | coverage suite, natural (baseline) | coverage-aware table, baseline side |
| `20261025T134206Z` | coverage suite, coverage-aware defense | coverage-aware table, defense side |

All runs: Qwen3-8B via Ollama (Q4_K_M), Ghidra 12.1.4, GhidraMCP 2.0, 10 seeds
per scenario; versions and model digest are in each `meta.json`.

Each directory holds `meta.json` (run configuration) and `runs.jsonl` (one
line per scenario and seed: the agent's report, every tool call with its
arguments, and trace metadata). `scores.json` and `report.md` are the
evaluator's output (`uv run python evaluator/evaluate.py evidence/<id>`);
`20261025T095403Z` was compared across runs only, so it has none. Two runs
compare with `uv run python ral.py compare evidence/<base> evidence/<candidate>`.

The only edit to the original logs is removing the local checkout prefix from
binary paths (`/Users/.../re-agent-lab/build/...` → `build/...`); scoring
them again gives byte-identical `scores.json`. Logs contain the prompt
injection strings embedded in the harmless fixtures; treat them as data.

These are pilot measurements: one model, one toolchain, two small fixtures.
The coverage-aware defense was designed after the natural runs (in-sample).
