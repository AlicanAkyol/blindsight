# Blindsight — technical project brief

Blindsight evaluates whether an AI-assisted reverse-engineering agent loses
capabilities, skips relevant code, or performs unauthorized writes after its
model, prompt, toolchain or analysis policy changes.

## Engineering work

- Controlled C/ELF fixtures and layered equivalence checks isolate metadata
  changes from observed program behaviour.
- GhidraMCP headless orchestration records tools and model context; local
  Ollama inference avoids requiring a paid model API.
- Seed-paired comparisons, exact McNemar tests and explicit error/exposure
  accounting separate pilot observations from broad claims.
- Installable CLI, portable baselines, evidence reports, frozen cases and a
  GitHub Action turn experiments into repeatable regression checks.
- Measurement corrections distinguish full delivered output from a successful
  tool call, partial labels from complete ground truth, and opaque inputs
  from variant-revealing paths.

## What the pilot shows — and does not show

On one fixture, a neutrally named persistence function was not decompiled in
10 natural runs and persistence was missed in all 10. Supplying code recovered
detection. A second fixture also showed recovery when its persistence body
was supplied. This supports a coverage explanation under the tested protocol.
The natural name-effect comparison was not statistically significant at the
pre-registered threshold. Two fixtures do not establish universal rates.

An import/xref-based policy improved coverage and aggregate recall, but was
developed in-sample. The current strict gate still rejects one newly introduced
unsupported finding, despite fewer unsupported findings overall.

The original statistics are public and reproducible. Original coverage was a
successful-call proxy; v0.4.0 records complete-output delivery and uses opaque
paths. Those are different measurement protocols, not interchangeable results.

## Inspect it

- [Runnable walkthrough](demo.md)
- [Published evidence](../evidence/README.md)
- [Measurement definitions](measurement.md)
- [Release notes](../CHANGELOG.md)

Scope today: Ghidra/GhidraMCP, Linux ELF, local-model pilot. No demonstrated
Threat.Zone integration, arbitrary-malware importer, or enterprise deployment.
