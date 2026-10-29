# First real local report, without an adapter or YAML

Use this workflow when you want to check a **local model inside Blindsight's
read-only reference agent**, save its current behavior, and compare a model
change. It does not automatically attach to your existing custom agent.

Prerequisites: uv/Python 3.10–3.13, a running local Docker engine, and Ollama
installed or already serving on 127.0.0.1:11434. Linux/macOS are supported by
this path; the analysis backend uses Linux/amd64 (emulated on Apple Silicon).
You do not need host Java, Ghidra, native decompiler builds, a JAR path, YAML
or a target adapter.

```sh
uvx --from 'blindsight[local] @ git+https://github.com/AlicanAkyol/blindsight' ral local
```

First use prepares a cached backend and, if missing, downloads `qwen3:8b`
weights through local Ollama. Downloads and disk use are substantial (model
weights can require several GB); later runs reuse them. No paid API is used.
If Ollama is stopped and its CLI is installed, RAL starts a loopback-only,
cloud-disabled service for the run and stops that owned service afterwards.
An already running service is left running. Cloud/remote model manifests
are refused. Missing Docker/Ollama produces an actionable setup error, never
a successful demo in place of a real check.

The command checks four harmless ELF fixture scenarios at one requested
seed each. It prints progress and writes `.ral/results/<id>/check.html`,
`check.json`, raw calls and scenario/model/runtime identity. Open the printed
HTML path. `quick` is a smoke test, not a confidence estimate. Expected
capabilities may be missed; that is a useful measured result, not a failed
installation.

| Exit | Meaning |
|---|---|
| 0 | The measured checks passed; this is not security certification |
| 1 | The run completed and measured a finding/coverage/decision issue |
| 2 | Setup, execution or telemetry was incomplete |

Only structured decisions/findings and recorded calls are scored. Summary
factuality is not verified; inspect its claims separately.

## Save a baseline and compare a change

Install once for repeated use:

```sh
uv tool install 'blindsight[local] @ git+https://github.com/AlicanAkyol/blindsight'
ral local
ral baseline save
# Select your actual local, tool-capable model name:
ral local --model MODEL --baseline saved
```

Replace MODEL with the model you intend to evaluate. Missing model weights
are downloaded. Qwen3:8b + Ollama is the exercised model/server combination;
other models are not claimed to be independently validated. The same suite
and seeds must be used on both sides. `--suite ci` runs the existing 18-episode
suite; save a new baseline with that suite before comparing it.

Baseline comparisons retain existing misses and reject observed regressions.
With `--baseline`, local `--html`/`--json`/`--markdown` outputs are the comparison
report; the candidate's own scorecard remains under its run directory.
One sampled comparison does not establish that the software change caused
the difference; requested seeds do not guarantee identical GPU/model output.

For dependency-only preparation, `ral local --prepare-only` prepares the
runtime/model and performs an actual backend read/decompile probe without
model inference. Setup metadata and diagnostics are under `.ral/setup/` and
`.ral/logs/`. Probe logs are separate for each invocation and retained.

## What runs where

Ollama and the fixed reference agent run on the host. Only the GhidraMCP
backend runs in Docker, communicating over MCP stdio. The backend receives
one opaque read-only file, has networking disabled and a temporary project,
and runs as an unprivileged user with a read-only root filesystem. The host
agent still has your user permissions; this workflow is not a general
sandbox for arbitrary agents or malware.

The image pins its Python base digest, official Ghidra/JDK/extension archive
SHA-256 values and Python backend requirements. Builds use a temporary
public-only Docker configuration rather than login/keychain credentials.
Image ID, recipe hash, backend package versions, model digest and reference
agent hash are saved. `container-fixed-v1` inputs require a fresh baseline
instead of silently comparing against native-path runs.

For your own agent loop, continue to use the existing target protocol and
`ral check --target-command ...`; the local reference run does not evaluate
that agent for you.
