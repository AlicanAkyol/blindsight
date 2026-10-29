# Optional integration: mcp-use MCPAgent

This example evaluates **mcp-use's MCPAgent orchestration**, rather than
Blindsight's packaged reference-agent loop. It configures that agent for
read-only Ghidra triage and runs it against the same harmless ELF fixtures.
It is an integration example, not evidence of independent adoption or a
validation of every mcp-use configuration.

## Setup

Use Python 3.11–3.13, uv, a running local Docker engine and Ollama. From a
Blindsight checkout:

```sh
uv venv --python 3.13 .venv
uv pip install '.[local]' -r examples/mcp-use-requirements.txt
```

The optional requirements pin the exercised external source commit and Ollama
integration package; they are not installed by the base Blindsight package.
The Docker recipe supplies the pinned Ghidra/JDK backend. No host Java/Ghidra
or API key is required. First use downloads substantial backend/model assets.

From a separate empty working directory, substitute the two checkout paths:

```sh
RAL_ADAPTER_LOG="$PWD/adapter.log" /path/to/blindsight/.venv/bin/ral check \
  --target-command '/path/to/blindsight/.venv/bin/python /path/to/blindsight/examples/mcp_use_agent.py' \
  --html report.html --json report.json
```

The helper sends exactly one protocol response on stdout. Private Python
library diagnostics are in `adapter.log` when enabled; inspect them if a check
reports an execution error. Do not publish that log without reviewing it.

## What is measured

The adapter uses MCPAgent's agent loop and a fixed RAL task prompt, with local
`qwen3:8b`, temperature 0.6, top_p 0.95, num_ctx 16384, num_predict 6144, the
requested seed and a 25-step limit. It does not ask a second model to repair an
invalid final answer. Invalid JSON remains an execution error. Changing the
agent/system prompt or selection policy changes what you are evaluating.

MCP middleware records actual tool calls and raw text. Framework-rejected
intents that never reach MCP are not a complete action-attempt audit. A LangChain callback
checks the tool messages accompanying a successful model response; only exact
text matches count as complete delivery. A tool result that was merely
returned, changed into a summary, or left unused at the step limit does not
count as fully delivered. This is request/context evidence, not proof of
comprehension. Error responses and bodies explicitly clipped by the backend never count as
successful complete-body coverage.

The example hides the eight write tools and refuses them in middleware before
calling the backend. This is an adapter policy, not the proposed upstream
GhidraMCP `--read-only` feature. Server-side protection must not be inferred
from this example. It does not isolate the host agent's Python process.

The model endpoint is fixed to loopback Ollama. mcp-use anonymized telemetry
and LangChain tracing are disabled; no user `.env` is loaded. The backend is
network-disabled and sees one opaque read-only input file. Existing Ollama is
left running; only an owned service and UUID-labelled containers are cleaned.

`.ral/mcp-use-setup/runtime.json` records model digest, requested options,
framework versions, adapter source hash and backend image identity. Keep it
with a run when sharing results; arbitrary external metadata is not auto-
discovered by RAL. An already configured agent can instead use its own runtime,
tools and instrumentation with [the adapter helper](target-protocol.md).

A quick suite has one seed per scenario. It can demonstrate that the adapter
works and expose misses; it cannot establish a stable accuracy rate or prove
that a model/software change caused a difference. Only structured findings,
decisions and recorded calls are scored; summary factuality is not verified.

## Local integration trial

The exercised source commit is pinned in the optional requirements. A developer-
run quick trial with Qwen3:8b produced four valid episodes, no execution errors,
and nine recorded MCP calls. All nine exact tool outputs were matched to a
successful subsequent model request. No function body was decompiled. Each
scenario found network/host-information capabilities but missed persistence,
so the scorecard returned FINDINGS (exit 1), not a fabricated pass.

This trial verifies this adapter/runtime path, not independent user adoption,
a stable failure rate, injection resistance, or a general quality ranking of
agent frameworks. A prior sandboxed attempt failed during Metal model startup
and was correctly reported as INCOMPLETE; it is not included among the four
valid episodes. The successful retry used the same prompt and model settings
with GPU access available.
