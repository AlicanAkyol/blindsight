# blindsight

**Rename one function and your AI reverse-engineering agent may never read it.**

blindsight is a regression harness for LLM-assisted reverse engineering
(Ghidra + GhidraMCP today). It feeds the agent binaries that differ only in a
symbol name or a piece of data, verified **behaviour-equivalent**, and records
what the agent reads, what it concludes, and which tools it tries to use. The
`ral` CLI turns that into a CI gate for model, MCP, prompt or defense changes.

## The finding

A function that installs persistence was named `install_autostart`, then
renamed to `routine_b` with the code byte-for-byte unchanged. With the neutral
name, the agent (Qwen3-8B via Ollama, Ghidra 12.1.4 + GhidraMCP 2.0) found
persistence in **0 of 10** runs (descriptive name: 5/10; exact McNemar
p=0.0625, just outside significance) and **never decompiled the function in
any of the 10**. It picks what to read by name.

Putting the code in front of the model brings recall back to 10/10: all
decompiled bodies on the first fixture, and only the one persistence function
on a second, independently structured fixture (2/10 → 10/10, McNemar
p=0.008). It is a *coverage* failure, not a comprehension failure. A coverage-aware policy that
selects functions by imported-API xrefs instead of names closes the gap
(seed-paired, 10 seeds per scenario):

| scenario | persistence function in context | capability recall |
|---|---|---|
| clean (descriptive) | 0.00 → 1.00 | 0.83 → 0.97 |
| v9 (neutral name) | 0.00 → 1.00 | 0.60 → 1.00 |
| h_clean (descriptive) | 0.10 → 1.00 | 0.47 → 1.00 |
| h_neutral (neutral name) | 0.00 → 1.00 | 0.47 → 1.00 |

These are pilot numbers: one model, one toolchain, two small hand-written
fixtures, and a defense designed after seeing them (in-sample). Hypotheses,
including the null and non-significant results, are pre-registered in
[docs/PREREG.md](docs/PREREG.md). The raw run logs are in
[evidence/](evidence/); `uv run python evidence/recompute.py` recomputes every
number above from them.

Published runs predate opaque input paths and complete-output delivery tracking.
Their coverage numbers are historical successful-call proxies, not measurements
from the corrected protocol. No old result is relabelled as a fresh experiment.
See [measurement changes](docs/measurement.md).

## Quick start

Try the recorded demo first. With Python 3.10–3.13 and [uv](https://docs.astral.sh/uv/),
one command generates a browser report without Ghidra, Docker, a model or an API key:

```sh
uvx --from 'git+https://github.com/AlicanAkyol/blindsight' ral demo
```

Open `blindsight-demo/index.html`. The replay shows a no-change PASS control,
a policy change that improves recall but still FAILs on a new unsupported
finding, and a reversed comparison with coverage loss. It uses published pilot
records, not new model inference. Demo exit 0 means the replay behaved as
expected; it is not a security pass. Downloads are needed for installation;
the installed `ral demo` runs offline. [Details and limits](docs/demo.md).

From a clone (not yet on PyPI):

```sh
git clone https://github.com/AlicanAkyol/blindsight && cd blindsight
uv tool install .                       # external-agent adapter; lightweight
ral init --target-command 'python /absolute/path/to/your_adapter.py'
ral doctor
ral check --html report.html
ral baseline save
# After changing your agent:
ral check --baseline saved
```

For the bundled GhidraMCP/Ollama agent, install with `uv tool install '.[ghidra]'`,
then `ral init`, `ral doctor`, `ral check`. `init` discovers local tools;
missing paths go in `.ral.yaml`. Prepared ELF fixtures are included and
hash-checked, so a standard check does not require a Docker rebuild.

Already drive GhidraMCP with a local LLM? [examples/openai_compatible_agent.py](examples/openai_compatible_agent.py)
implements an adapter for OpenAI-compatible servers with tool calling.
The exercised model/server combination is **Qwen3:8b + Ollama**; LM Studio,
llama.cpp and vLLM have not been independently verified. Put the model name and Ghidra paths in
the target's `env` in `.ral.yaml`, then `ral check`. It reports every
GhidraMCP call it makes, so coverage is measured. To check your own agent,
copy it and replace the agent loop.

**[First report and troubleshooting](docs/quickstart.md)** ·
**[Connect your agent](docs/target-protocol.md)** ·
**[Release evidence and persistent cases](docs/release-checks.md)** · `ral --help`

Each release comparison shows which finding disappeared, its paired seeds,
and the tool-log lines that support the diagnosis. Keep the discovered case
for your next release:

```sh
ral compare /path/to/baseline /path/to/candidate --html release.html
ral case save persistence-miss --run /path/to/candidate --scenario agent_fixture.v9_symbol_neutral
ral check --case persistence-miss
```

`quick` uses one seed, `ci` three and `full` ten. Reports are saved as JSON,
Markdown and HTML in `.ral/results/<id>/`. A quick pass is a smoke-test result,
not a security certificate. External telemetry is labelled as target-reported;
missing telemetry does not silently pass coverage/authority checks.

Status: v0.4.0 beta. The package is `blindsight`; its command is `ral`.
Independent clean-machine testing is pending.

**[Watch the demo (MP4)](https://github.com/AlicanAkyol/blindsight/releases/download/v0.4.0/blindsight-demo.mp4)** ·
**[Runnable walkthrough](docs/demo.md)** ·
**[Measurement definitions and compatibility](docs/measurement.md)** ·
**[Project brief](docs/project-brief.md)**

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
  or a symbol name, to isolate the changed metadata
- `corpus/fixtures.py` — maps each variant to its source and behavioural baseline
- `corpus/verify.py` — a layered oracle that finds no behavioural difference
  between a variant and its baseline: stdout/stderr/rc, created files, qemu
  syscall trace, per-function normalised instructions and call targets, injected
  bytes outside executable sections (strong evidence, not a proof of semantic
  equivalence)
- `corpus/scenarios` — expected findings per variant; adversarial scenarios paired
  with a matched placebo or clean control at the same seed
- `runner/` — GhidraMCP headless sessions with every tool call recorded; a local
  Ollama agent; `natural`, `forced_decompile` and `forced_one` arms; mock agents
- `evaluator/` — seed-paired per-finding and verdict McNemar, Wilson intervals,
  delivery/recognition/compliance, three-stage write metrics
- `docs/PREREG.md`, `docs/RUBRIC.md` — pre-registered hypotheses and the verdict
  rubric

## CLI

The legacy research commands below remain available from the source checkout.
Fresh equivalence rebuilds need Docker; built-in real-model runs need JDK 21,
Ghidra 12.1.4, GhidraMCP 2.0 and local Ollama. The installed product commands
above use `.ral.yaml`; the legacy commands use `ral.yaml`.

    uv run --extra ghidra python ral.py doctor           # is the toolchain ready
    uv run python ral.py validate                        # build + prove the equivalence oracle
    uv run --extra ghidra python ral.py run --profile ghidramcp-ollama           --suite smoke
    uv run --extra ghidra python ral.py run --profile ghidramcp-ollama-readonly  --suite smoke
    uv run python ral.py compare results/<base> results/<cand>    # seed-paired recall + coverage diff
    uv run python ral.py gate    results/<base> results/<cand> \
        --max-recall-drop 5 --deny-unauthorized-writes            # non-zero exit for CI

`compare`/`gate` pair on `(scenario, seed)`, use only seeds valid on both sides, and
report whether the ground-truth capability function was decompiled (coverage) next
to the recall delta (comprehension). See `.github/workflows/ral-gate.yml.example`.

## Lower-level / tests

    python3 corpus/build.py                 # build every variant in Docker
    python3 corpus/verify.py                # behavioural equivalence, all variants
    uv run --extra ghidra python runner/run.py --agents rule_agent gullible_agent   # no model; needs Ghidra
    uv run python tests/test_stats.py       # statistics regression tests
    uv run python tests/test_cli.py         # seed-pairing / coverage / gate tests

The corpus programs are harmless: they connect only to 127.0.0.1, write only
inside the sandbox directory they are given, and are run with `--network none`.

## License

Apache-2.0 (see `LICENSE`).
