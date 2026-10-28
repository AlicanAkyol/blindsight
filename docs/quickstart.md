# First report

RAL checks an AI reverse-engineering agent using small, harmless Linux ELF
fixtures. It does not scan arbitrary malware or certify a stack as secure.
Your target is responsible for analysing binaries; RAL records and evaluates
its results. Start with `quick`, then save a baseline before changing your agent.

## One command with your existing agent

With Python 3.10–3.13 and uv installed, an existing `ral.target.v1` adapter can
be checked directly:

```sh
uvx --from 'git+https://github.com/AlicanAkyol/blindsight' ral check \
  --target-command '/path/to/agent-venv/bin/python /path/to/adapter.py' \
  --html report.html
```

Replace both paths with your actual adapter and its runtime. Installation needs
network access. RAL does not install or configure the adapter's own analysis
tools or model. This is a real check of the adapter you provide, not the recorded
demo. A generic agent command does not automatically implement the
[adapter protocol](target-protocol.md).

For an installed CLI, the command is simply `ral check --target-command '…'`.
It creates reports and fixture state without creating or modifying `.ral.yaml`.
Existing configuration is still read; the inline command overrides the selected
target for this invocation. `--target-command`, `--target` and `--profile` are
mutually exclusive. Commands are split into argv and executed without a shell.

Use `--target-timeout 120` to set a per-episode deadline in seconds (default
600). Non-finite, zero and negative deadlines are rejected. Stdout and stderr
are each capped at 2 MiB while the adapter runs. An output-limit failure,
timeout, invalid response or non-zero adapter exit is an execution error and
returns exit 2, never a successful check. On Linux/macOS, timeout/failure cleanup
also stops children in the adapter's process group. These controls do not
isolate the process or limit its other resource use; see
[security boundaries](security-boundaries.md).

After a completed run, `ral baseline save` retains it for a later
`ral check --target-command '…' --baseline saved`. First-run misses exit 1;
baseline comparisons reject new regressions while retaining known misses.

## Install from the local checkout

Python 3.10–3.13 and uv are required. The package is not on PyPI yet.

```sh
uv tool install /path/to/blindsight
ral --version
```

For the bundled GhidraMCP + local Ollama runner:

```sh
uv tool install '/path/to/blindsight[ghidra]'
```

Or install the release wheel with `pipx install /path/to/blindsight-0.4.0-py3-none-any.whl`.
Once the package is published, `uvx --from blindsight ral check` can use the same entrypoint;
that registry command is not available yet.

## Check your own agent

In an empty project directory:

```sh
ral init --target-command 'python /absolute/path/to/your_adapter.py'
ral doctor
ral check --html report.html --json report.json --markdown report.md
```

An adapter receives a versioned JSON request on stdin, analyses the absolute
binary path with your agent, and writes one JSON response to stdout. Logs go
to stderr. The protocol and a small adapter template are in
[target-protocol.md](target-protocol.md) and `examples/target_adapter.py`;
`examples/openai_compatible_agent.py` is a working GhidraMCP + local LLM adapter.
RAL passes the binary, frozen task prompt and seed. It never supplies ground
truth, expected findings or the control relationship to the target.

This path needs no Ghidra installation, Docker daemon or Ollama inside RAL.
It needs whatever your target itself uses. Standard `check` uses bundled ELF
artifacts whose hashes are checked; it never executes those binaries.

Telemetry exported by an external target is labelled `target_reported`.
It is not an independent authority audit. If calls are omitted, coverage and
authority remain unmeasured and the check returns exit 2 rather than passing.

## Check the built-in GhidraMCP + Ollama runner

Install Ghidra 12.1.4, its native decompiler for your architecture, Java 21 and
the GhidraMCP 2.0 extension JAR. Start local Ollama with the pinned model used
in the pilot:

```sh
ollama serve
ollama pull qwen3:8b
```

Create the config:

```sh
ral init
ral doctor
```

`init` discovers tools from `RAL_TOOLS`, `./tools`, `~/dev/tools`, `/opt` and
the Java environment. Explicit environment overrides are `RAL_GHIDRA`,
`RAL_GHIDRAMCP_JAR` and `RAL_JAVA_HOME`. Set missing paths in `.ral.yaml`:

```yaml
tools:
  ghidra: /opt/ghidra_12.1.4_PUBLIC
  ghidramcp_jar: /opt/GhidraMCP-2.0/ext/GhidraMCP/lib/GhidraMCP.jar
  java_home: /path/to/jdk-21
default_profile: ghidramcp-ollama
```

Then:

```sh
ral check
ral check --profile ghidramcp-ollama-readonly
ral check --profile ghidramcp-ollama-coverage
```

Profiles select the local model, analysis policy and tool permissions. A
profile tests RAL's bundled agent loop; it does not automatically connect to
your own agent. Use a target adapter for that.

`quick` is four checks at one seed and can take several minutes on a local
8B model. `ci` is six scenarios at three seeds (18 checks). `full` uses the
existing core suite at ten seeds, with required controls included. Duration
depends on the model and hardware; the CLI prints the episode count first.
No multi-seed confidence claim is made for a quick run.

## Reports and baseline

Each run is stored in `.ral/results/<id>/`, outside the installed package:

- `meta.json`: exact scenario snapshot, prompt, artifact hashes and target/profile.
- `runs.jsonl`: per-seed structured output and tool evidence.
- `check.json`, `check.md`, `check.html`: first-run scorecard and next steps.
- `scores.json`, `report.md`: the existing paired research evaluator's output.

```sh
ral baseline save
# Change your model, agent prompt, toolchain or policy, then:
ral check --baseline saved
```

Saving an existing baseline requires explicit `--replace`; incomplete runs
cannot become baselines. Keep the same suite and artifact versions when
comparing releases. The baseline retains the source run's measurements and
scenario snapshot, not just aggregate scores.

You can also compare explicit run directories:

```sh
ral compare .ral/results/BASE .ral/results/CANDIDATE
ral gate .ral/results/BASE .ral/results/CANDIDATE \
  --max-recall-drop 5 --max-coverage-drop 0 --deny-unauthorized-writes
```

`compare --html release.html --json release.json` exports the evidence report.
`case save` captures an observed scenario and controls as a frozen regression
test; `check --case NAME` replays its original artifacts, prompts and seeds.
See [release-checks.md](release-checks.md) for the full workflow.

Without a baseline, `check` exits 0 when all completed fixture checks pass,
1 when measured checks find misses/unsupported findings/writes, and 2 when
execution or telemetry is incomplete. With a baseline, `check` uses the
strict regression gate; pre-existing misses can remain accepted, while new
regressions fail. That includes findings outside source ground truth: if the
candidate reports more of them than the seed-paired baseline, the gate fails
(`--max-unsupported-increase N` allows a rise of N per scenario; default 0). A passing result describes these tests, not a security
certificate or proof that a write boundary exists.

The evaluator scores structured verdict/findings and recorded tool calls.
Free-text summary factuality is not checked. For example, a correct network
finding can accompany a wrong port number, or an unsupported anti-analysis
claim can appear only in the summary. These statements do not become verified
because the structured checks pass; inspect the summary separately.

## Fixture validation

```sh
ral validate             # bundled artifact integrity; no Docker needed
ral validate --rebuild   # fresh compiler + qemu equivalence checks; Docker needed
```

The bundled oracle report records historical equivalence checks. Hash
verification is not a fresh behaviour-equivalence experiment. Rebuilds run
the harmless fixtures in Docker with networking disabled and sandbox writes.

## Troubleshooting

- **Unknown command `ral`:** use `uv tool update-shell`, reopen the terminal,
  or run `uv tool run --from /path/to/blindsight ral --help`.
- **Missing Python Ghidra dependencies:** install the `[ghidra]` extra.
- **Missing tools:** set `tools` in `.ral.yaml`; `doctor` prints the missing item.
- **No telemetry:** export `calls` using the adapter protocol; findings alone
  cannot establish function coverage or tool authority.
- **Fixture hash mismatch:** use a fresh `--state` directory, or inspect local
  artifact changes before using `validate --rebuild`. Corrupt files are not
  silently replaced.
- **Exit 1:** read `check.md` and the relevant tool trace; a measured miss is
  an expected useful result, not an installation error.
- **No baseline:** complete `check`, then `ral baseline save`.

Global `--config PATH` and `--state PATH` precede the command. Configuration
can reference a local executable; treat configurations like executable code.

## GitHub Actions

`action.yml` is a composite action that installs RAL, runs your configured
target, writes the Markdown scorecard to the job summary and propagates its
exit code. Use a checkout of this local/private action until a public version
exists. See `examples/agent-check-workflow.yml`.

External targets use the runner and dependencies they need. The built-in
Ghidra/Ollama profile needs a runner where Ghidra, Java, the extension and a
local model are already installed. The action does not download a large model
or install system tools silently. Retain the report directory as an artifact;
download a previous run as `baseline` for strict regression checks.
