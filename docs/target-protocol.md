# User-owned agent adapter: ral.target.v1

RAL starts the configured argv list once per scenario/seed, with no shell.
The target controls its own analysis stack and accepts an absolute ELF path.
It must not execute the fixture on the host; static analysis is sufficient.

For a single invocation, no configuration file is necessary:

```sh
ral check --target-command '/path/to/agent-venv/bin/python /path/to/adapter.py' \
  --target-timeout 600 --html report.html
```

The command is held in memory and recorded in run metadata. The adapter is
trusted local code running with your permissions, not inside a RAL sandbox.
Use its own runtime if it needs libraries beyond RAL's dependencies.

`.ral.yaml`:

```yaml
default_target: my-agent
targets:
  my-agent:
    command: [python, /absolute/path/to/your_adapter.py]
    timeout: 600
    cwd: /path/to/agent
    env:
      MODEL: local-model
```

Environment values are passed to the process and are not copied into result
metadata. Do not put credentials in command arguments or target output.

One JSON request arrives on stdin:

```json
{
  "protocol": "ral.target.v1",
  "binary": "/absolute/path/.ral/build/clean/agent_fixture",
  "seed": 0,
  "task": {"id": "triage_readonly", "prompt": "<frozen task prompt>"}
}
```

No expected answer, ground truth or scenario ID is supplied. Current runs
send an opaque temporary `ral-input-<random>/sample.bin` path with identical
bytes; it is removed after each episode. Older evidence used variant names
in paths. This blinds path labels; it is not filesystem isolation.

The adapter emits exactly one JSON response on stdout and diagnostics on stderr:

```json
{
  "protocol": "ral.target.v1",
  "report": {
    "verdict": "suspicious",
    "findings": ["network_connection"],
    "summary": "Observed an outbound network connection."
  },
  "calls": [
    {
      "tool": "decompile_function",
      "args": {"name": "routine_b"},
      "write": false,
      "is_error": false,
      "result_chars": 200
    }
  ]
}
```

Valid verdicts: `malicious`, `suspicious`, `benign`. Findings are drawn from
`network_connection`, `persistence`, `host_info_collection`, `file_encryption`,
`process_injection`, `credential_access`, `anti_analysis`.

`calls` is optional but must be truthful when present. Omitting it leaves
coverage and authority unmeasured; the scorecard returns exit 2. Supplying an
empty list means no tools were invoked. A successful decompile needs positive
`result_chars` for the legacy successful-call proxy. Upgraded adapters should
also supply delivery fields from [measurement.md](measurement.md): only a
successful, positive-length, untruncated delivered output counts as complete
output coverage. Only results actually added to model context belong here.
Writes require `write: true`; refused writes use `is_error: true` and can
include `refused_read_only: true`.

External telemetry is self-reported, so it cannot prove that a malicious
agent did not hide a write. Independent execution-layer auditing remains
necessary for that claim. The built-in MCP runner records calls itself.
Prompt-injection delivery cannot currently be measured through this minimal
protocol; the report does not present an injection-resistance score.

Stdout and stderr are each limited to 2 MiB during execution. A limit violation,
malformed JSON, invalid enums, timeout, or a non-zero exit code produces a
recorded execution error, never a successful check. Captured stderr is discarded
and is not copied into reports; inspect the adapter locally for diagnostics.
See [security boundaries](security-boundaries.md) for the limits of subprocess
cleanup and self-reported telemetry.

See `examples/target_adapter.py` for the integration boundary; it deliberately
requires you to connect your actual agent rather than returning a fake pass.
`examples/openai_compatible_agent.py` is a complete adapter: an LLM on any
OpenAI-compatible endpoint drives GhidraMCP headless, every MCP call is
recorded, and `RAL_AGENT_READ_ONLY=1` refuses write tools before they reach
Ghidra. Its docstring has the `.ral.yaml` target configuration.
