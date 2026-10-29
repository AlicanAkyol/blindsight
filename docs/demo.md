# A short technical walkthrough

## One-command recorded demo

**[Open the hosted demo](https://alicanakyol.github.io/blindsight/)** to inspect
the reports without installing anything. The hosted view is a fixed snapshot
of the same recorded evidence; it does not run a model in the browser.

With Python 3.10–3.13 and uv installed:

```sh
uvx --from 'git+https://github.com/AlicanAkyol/blindsight' ral demo
```

Open the printed file URL, or `blindsight-demo/index.html`. For an existing
installation use `ral demo`; from a clone, use `uv run ral demo`. Installation
needs network access; the replay itself is offline and never executes fixture
binaries, starts Ghidra or calls a model. Use `--output NEW_DIRECTORY` for another
copy. Existing directories are refused rather than overwritten.

Three linked reports use all 40 episodes in each of two published runs:

| Report | Expected gate result | What it demonstrates |
|---|---|---|
| No change | PASS | The same imperfect run compared with itself has no new regression. |
| Natural → coverage policy | FAIL | Recall improves, but `health.h_neutral`, seed 5 adds `credential_access` outside ground truth. |
| Reverse comparison | FAIL | Reversing the same runs exposes finding and coverage loss. |

The no-change and reverse views are controls derived from the same evidence,
not additional experiments. `manifest.json` records input SHA-256 hashes and
the expected gate exits. The copied raw records and comparison JSON are linked
from the HTML reports. Demo exit 0 confirms replay consistency; real `ral gate`
still exits 1 for a measured regression, or 2 for incomplete/incompatible data.
All views visibly label legacy coverage as a successful-call proxy and state
the one-model, two-fixture, in-sample limits.

For a bounded real-stack trial and a short feedback checklist, see
[A focused first trial](try-it.md). CI also exports the generated demo as a
downloadable `recorded-demo-*` artifact; unzip it and open `index.html` locally.

## Video walkthrough

[Watch the 54-second English walkthrough (MP4)](https://github.com/AlicanAkyol/blindsight/releases/download/v0.4.0/blindsight-local-en.mp4).
Silent, with English on-screen explanations and screenshots of two real
Qwen3:8b/Ollama runs. This is an illustrated recorded-results walkthrough,
not a live terminal recording or a new inference run.

It shows the current `ral local` workflow: one command, the first report,
a saved baseline, and a paired comparison. All four scenarios produced valid
results on both runs. The baseline comparison passes while the existing
persistence misses remain visible; PASS does not mean the model is error-free.
The same model was used on both sides; backend Python and agent source identity
changed and were recorded. This is not a controlled model-change experiment.

The video demonstrates **current main after v0.4.0**, not the older wheel
attached to that release. Use the Git-based install in [Local setup](local.md).
Requires uv, a running Docker engine and Ollama; first use downloads substantial
backend/model assets. Your custom agent still needs a target adapter.
[Source run IDs and input hashes](https://github.com/AlicanAkyol/blindsight/releases/download/v0.4.0/blindsight-local-en.provenance.json)
are available with the video. Free-text summary accuracy is not scored;
this small fixture suite is not security certification.

The [previous Turkish video](https://github.com/AlicanAkyol/blindsight/releases/download/v0.4.0/blindsight-demo.mp4)
remains available as a walkthrough of the historical experiment.

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

## Run a fresh local check

With uv, a running Docker engine and Ollama installed, follow
[Local setup](local.md). No host Java/Ghidra, YAML or adapter is needed for
the bundled read-only reference agent:

```sh
uvx --from 'blindsight[local] @ git+https://github.com/AlicanAkyol/blindsight' ral local
```

For repeated use, install the CLI and save a baseline:

```sh
uv tool install 'blindsight[local] @ git+https://github.com/AlicanAkyol/blindsight'
ral local
ral baseline save
ral local --model MODEL --baseline saved
```

Replace MODEL with a local tool-capable model name. Use the same suite on
both sides. A quick run is one seed: a smoke test, not a stable rate estimate.
A measured miss exits 1; missing execution/telemetry exits 2. Baselines may
retain known misses; comparisons gate new regressions. For your own agent,
use the target adapter path in [Quickstart](quickstart.md).

## What to inspect

- Controlled binaries, machine-checkable findings and matched controls.
- Distinguishing absent code observations from a missed finding despite a
  recorded response, without treating logs as causal proof.
- Reproducible statistics, versioned measurements, failure-aware CI and
  deterministic read-only enforcement outside the model.

Only Qwen3:8b + Ollama has been exercised as the real-model combination.
Other compatible endpoints are possibilities, not validated configurations.
No Threat.Zone integration is implemented.
