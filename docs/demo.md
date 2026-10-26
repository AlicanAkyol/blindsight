# A short technical walkthrough

This is an RE-agent evaluation project, not a malware detector or security
certificate. The demonstration is a name-sensitive coverage failure and a
controlled recovery intervention, with explicit pilot limits.

## Reproduce published numbers without a model

From the checkout:

```sh
uv run python evidence/recompute.py
uv run python evidence/audit_delivery.py
```

The first command reproduces 28 headline values. The second audits saved
context, not a new agent run. Original pilot: Qwen3-8B Q4_K_M via Ollama,
Ghidra 12.1.4, GhidraMCP 2.0, two structurally different fixtures. The natural
name-effect contrast did not reach its pre-registered significance threshold.
The coverage policy was designed after the fixtures, not tested on a holdout.

## Open an actual historical comparison

```sh
uv tool install .
ral compare evidence/20261025T122507Z evidence/20261025T134206Z \
  --html comparison.html --json comparison.json
```

This compares published natural and coverage-aware runs, not two new releases.
Inspect paired recall, coverage and unsupported findings. Historical coverage
is a successful-call proxy; see [measurement.md](measurement.md).

With the current strict per-scenario gate, this comparison reports **FAIL**:
`health.h_neutral` gained a `credential_access` claim at seed 5. Across the
whole suite unsupported findings fell from 6 to 1, but a new per-scenario
error is still a regression. That is a useful honest demonstration, not a
reason to weaken the default threshold to manufacture a green report.

## Run a fresh check when the local stack is ready

Follow [quickstart.md](quickstart.md) for Ghidra, extension, Java and Ollama.
In a separate empty directory, after installing `.[ghidra]`:

```sh
ral init
ral doctor
ral check --html fresh.html
ral baseline save
ral check --profile ghidramcp-ollama-coverage --baseline saved
```

Use the same suite on both sides. A quick run is one seed: a smoke test, not
a stable rate estimate. A measured miss exits 1; missing execution/telemetry
exits 2. Baselines may retain known misses; comparisons gate new regressions.

## What to inspect

- Controlled binaries, machine-checkable findings and matched controls.
- Distinguishing absent code observations from a missed finding despite a
  recorded response, without treating logs as causal proof.
- Reproducible statistics, versioned measurements, failure-aware CI and
  deterministic read-only enforcement outside the model.

Only Qwen3:8b + Ollama has been exercised as the real-model combination.
Other compatible endpoints are possibilities, not validated configurations.
No Threat.Zone integration is implemented.
