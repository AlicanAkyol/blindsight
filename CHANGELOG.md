# Changelog

## 0.4.0 — 2026-10-26 (beta)

### Measurement corrections

- Explicit exhaustive/partial label scope. Extra findings on partial-label
  cases require review; they are not automatically false positives.
- Exact context text, raw/delivered lengths and hashes, and truncation are
  recorded by the built-in model loop and example adapter. Truncated or
  undelivered outputs do not count as complete-output coverage.
- The final tool batch at a step limit is not counted as delivered when no
  subsequent model request receives it.
- Built-in and external targets receive unchanged binary bytes at temporary
  opaque paths, rather than variant-revealing filenames.

### Compatibility / migration

- Measurement protocol, input-path protocol and label scope are comparison
  identities. **Create a new baseline after upgrading.** Old evidence remains
  reproducible, but is not a corrected-protocol experiment.
- Legacy/v1 adapter calls without delivery evidence remain explicitly labelled
  successful-call proxies. External telemetry is target-reported.

### Verification and presentation

- 40 product/release/measurement/example tests, plus statistics and legacy CLI
  checks; public evidence recomputes 28 headline values.
- Historical context audit: 230 episodes, 555 decompile messages, no harness
  truncation marker. Not a fresh experiment or a backend-truncation guarantee.
- Documentation narrows exercised real-model support to Qwen3:8b + Ollama.
- Walkthrough explains why historical aggregate improvement (unsupported
  findings 6 -> 1) still fails the strict per-scenario gate: a new claim in
  `health.h_neutral`, seed 5. The failure is not hidden.

The release is an experimental research/evaluation harness, not a malware
detector, sandbox, enterprise platform or security certification. Original
pilot: one model, two small fixtures, in-sample defense. No PyPI publication.
