# Two-minute demo script

A live walkthrough or recording script, not a claim that a video is attached.
Prepare the installed CLI and generated comparison report before presenting.
Do not run a multi-minute model inference inside this two-minute slot.

## 0:00–0:25 — the question

Show README and the two fixture symbol names.

> Does an AI reversing agent inspect the relevant code, or only code whose
> function names look interesting? I built Blindsight to measure that and
> catch regressions when the agent's model, prompt or tools change.

## 0:25–0:50 — the controlled observation

Show the finding and pilot limitations.

> In this fixture, renaming the persistence function to routine_b left its
> implementation unchanged. Across ten natural runs the agent never
> decompiled it and missed persistence. Supplying code recovered detection.
> This is one model and two small fixtures; the natural name-effect test did
> not reach the pre-registered significance threshold.

## 0:50–1:15 — reproducible evidence

Run `python evidence/recompute.py`, then open a prepared comparison from
[the walkthrough](demo.md).

> These are raw run logs, not hand-entered totals. The script recomputes
> twenty-eight published values. The report pairs seeds and links losses to
> recorded tool evidence; it does not pretend that tool logs prove causality.

## 1:15–1:40 — a useful red result

Show the historical report's FAIL and `health.h_neutral` seed 5.

> Coverage and recall improved, and unsupported findings fell overall. But
> one scenario gained an unsupported credential-access claim. The strict
> gate fails it. An aggregate improvement must not hide a local regression.

## 1:40–2:00 — measurement integrity

Show measurement.md and the installed CLI test workflow.

> Version 0.4 separates complete delivered output from a successful call,
> blinds variant filenames, and treats partially labelled findings as
> unreviewed rather than false. Old rates stay historical; new measurements
> need a new baseline. This is an evaluation harness, not a security stamp.
