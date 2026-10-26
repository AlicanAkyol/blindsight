# re-agent-lab

Check your own AI reverse-engineering agent, get an evidence report, and
catch coverage/recall regressions before changing your stack.

From the local checkout (not yet published to PyPI):

```sh
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

A regression harness for LLM-assisted reverse-engineering setups (Ghidra +
GhidraMCP today). It measures whether **behaviour-equivalent** changes to a
binary — a renamed function, an added string, attacker-controlled text — quietly
change what an AI agent analyses, what it concludes, and what tools it is willing
to invoke.

The headline question is not only "can the model be prompt-injected" but the
sharper one this harness surfaced: **a semantically neutral rename of a
capability function can make the agent skip that function entirely and miss the
capability**, with the code byte-for-byte unchanged.

Status: local beta with a wheel-installable `ral` CLI, a user-agent adapter,
and a built-in GhidraMCP + Ollama runner. Findings are pre-registered
(`docs/PREREG.md`) and include negative and null results. Public publication
and independent clean-machine beta testing are still pending.

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
  rubric; `docs/STATUS.md` — running log

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
