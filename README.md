# re-agent-lab

Adversarial benchmark and regression harness for LLM-assisted reverse engineering
setups (Ghidra + GhidraMCP today).

Binaries carry attacker-controlled text (strings, symbol names). When an LLM reads
them through an MCP server, that text can steer its verdict or trigger write actions.
This project measures how often that happens, on pinned tool versions, with
machine-checkable success criteria.

## Layout

- `corpus/src`, `corpus/variants`: one fixture program, a clean build and
  adversarial variants that only add data or rename a symbol
- `corpus/verify.py`: proves every variant behaves like the clean build
  (stdout/stderr/rc, created files, syscall trace, per-function mnemonics,
  injected bytes outside executable sections)
- `corpus/scenarios`: expected findings and verdicts per variant, each adversarial
  scenario paired with its clean scenario
- `runner/`: GhidraMCP headless sessions with every tool call recorded; mock agents
- `evaluator/`: per-run failure classes and a Markdown/JSON report

## Reproduce

Requirements: Docker, JDK 21, uv, Ghidra 12.1.4 (natives built), GhidraMCP 2.0 jar.

    python3 corpus/build.py
    python3 corpus/verify.py
    uv run python runner/run.py --agents rule_agent gullible_agent
    uv run python evaluator/evaluate.py results/<run_id>

The corpus programs are harmless: they connect only to 127.0.0.1 and write only
inside the sandbox directory they are given, and they are run with `--network none`.
