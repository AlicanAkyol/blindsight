# re-agent-lab

A regression harness for LLM-assisted reverse-engineering setups (Ghidra +
GhidraMCP today). It measures whether **behaviour-equivalent** changes to a
binary — a renamed function, an added string, attacker-controlled text — quietly
change what an AI agent analyses, what it concludes, and what tools it is willing
to invoke.

The headline question is not only "can the model be prompt-injected" but the
sharper one this harness surfaced: **a semantically neutral rename of a
capability function can make the agent skip that function entirely and miss the
capability**, with the code byte-for-byte unchanged.

Status: research pilot. Findings are pre-registered (`docs/PREREG.md`) and
reported honestly, including negative and null results. Not yet a packaged tool.

## What it measures

- **analysis coverage** — which functions the agent chooses to decompile
- **capability recall** — did it find the behaviours that are in the code
- **exposure / susceptibility** — did attacker text reach the model, and did it
  change the verdict (seed-paired against a matched control)
- **tool authority** — did the agent request/perform unauthorised writes

Every tool call is recorded independently of the model's own account, runs use
pinned tool/model versions, and each result embeds a scenario snapshot so it can
be re-scored exactly.

## Layout

- `corpus/src`, `corpus/variants` — two fixtures (`agent_fixture`, `health_fixture`)
  with the same capability classes but different shapes; variants change only data
  or a symbol name, so behaviour cannot drift
- `corpus/fixtures.py` — maps each variant to its source and behavioural baseline
- `corpus/verify.py` — proves every variant behaves like its baseline: stdout/
  stderr/rc, created files, qemu syscall trace, per-function normalised
  instructions and call targets, injected bytes outside executable sections
- `corpus/scenarios` — expected findings per variant; adversarial scenarios paired
  with a matched placebo or clean control at the same seed
- `runner/` — GhidraMCP headless sessions with every tool call recorded; a local
  Ollama agent; `natural`, `forced_decompile` and `forced_one` arms; mock agents
- `evaluator/` — seed-paired per-finding and verdict McNemar, Wilson intervals,
  delivery/recognition/compliance, three-stage write metrics
- `docs/PREREG.md`, `docs/RUBRIC.md` — pre-registered hypotheses and the verdict
  rubric; `docs/STATUS.md` — running log

## Reproduce

Requirements: Docker, JDK 21, uv, Ghidra 12.1.4 (natives built), GhidraMCP 2.0 jar,
and (for real-model runs) Ollama with `qwen3:8b`. Tool paths are currently set for
one machine in `runner/ghidra_session.py` (override with `RAL_TOOLS`,
`RAL_JAVA_HOME`).

    python3 corpus/build.py                 # build every variant in Docker
    python3 corpus/verify.py                # behavioural equivalence, all variants
    uv run python runner/run.py --agents rule_agent gullible_agent   # offline sanity
    uv run python runner/run.py --agents ollama:qwen3:8b --repeats 10 --arm natural
    uv run python evaluator/evaluate.py results/<run_id>
    uv run python tests/test_stats.py       # statistics regression tests

The corpus programs are harmless: they connect only to 127.0.0.1, write only
inside the sandbox directory they are given, and are run with `--network none`.

## License

Apache-2.0 (see `LICENSE`).
