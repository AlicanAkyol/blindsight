# Measurement corrections (v0.4.0 beta)

These changes strengthen the existing RE harness. They do not add sandbox,
Threat.Zone, arbitrary-malware import or enterprise platform support.

## Verdict policy and empty expected findings

`expected_verdict` describes the scenario. `forbidden_verdicts` explicitly
defines unacceptable decisions, independently of finding recall. For example,
`expected_verdict: malicious` with `forbidden_verdicts: [benign]` permits
`suspicious`; it does not require an exact `malicious` verdict. A forbidden
decision fails a standalone check even when all expected findings are present.
Without `forbidden_verdicts`, verdict checking is **not configured**; the
report does not claim that the decision was verified.

Baseline comparisons reject each newly forbidden decision on its paired seed.
A recovery on another seed cannot cancel it. An unchanged, already forbidden
baseline decision remains visible but is not a new regression. Changes to
either verdict-policy field invalidate baseline compatibility.

An empty `expected_findings: []` is valid: recall is **not applicable**, not
zero or perfect. These episodes still participate in pairing, completeness,
verdict and exhaustive-label unsupported-finding checks. Synthetic evaluator
tests cover these semantics; they do not establish accuracy on a benign corpus.

## Label scope

Scenario YAML accepts `label_scope: exhaustive` or `label_scope: partial`.
Both bundled fixture suites are explicitly exhaustive, based on source review.
Missing scope retains historical exhaustive semantics for old snapshots; new
real-world scenarios must choose explicitly. Unknown values are rejected.

With partial labels, recall still measures listed expected findings, but an
extra finding is **unreviewed**, not automatically false. It appears in the
scorecard/release report and does not trigger the unsupported-finding gate.
A partial-label PASS cannot establish precision or absence of hallucination.
Changing label scope invalidates baseline compatibility.

## Delivery versus a successful tool call

New runs record `coverage_identity_protocol: response-function-v1`. For an
address-based decompile call, coverage can resolve the expected function from
the delivered Ghidra JSON response when its returned name matches, its address
equals the requested address, code is nonempty, and backend/client truncation
is absent. Text mentions, a bare address, undelivered output or another
function's response do not establish this identity. Telemetry is still
adapter-reported. Runs without this field retain argument-name-only matching;
different identity protocols require a fresh baseline. Historical evidence
is not silently reinterpreted using the new address resolution.

The built-in model runner and example adapter record raw output length/hash,
the exact text appended to model context, delivered length/hash, and truncation.
Calls made internally by a policy but not put in model context remain
`delivery_recorded: false`. This is context-construction evidence, not proof
of attention, understanding, or provider-side context retention.
The last tool batch at the step limit, which is not sent in a subsequent
model request, is marked undelivered rather than counted as coverage.

For calls with delivery evidence, coverage requires a successful response,
positive delivered length, and **no truncation**. A partially useful response
is conservatively not counted as complete-output coverage. This does not
prove the response semantically contains a complete body; it means the tool's
complete non-error output entered the recorded context.

Legacy logs and v1 adapters without delivery fields retain a successful-call
proxy for reproducibility, explicitly identified as such. Positive proxy
coverage is not proof of complete delivery. New built-in runs use
`measurement_protocol: delivered-output-v2`. Old/new built-in protocols cannot
be compared as if measurement were unchanged: take a fresh baseline.
External telemetry remains adapter-reported, not independently audited.
External run metadata records whether calls use v1 proxy, v2 delivery fields,
or both, so changing that measurement basis also requires a new baseline.

Optional v1 call fields for upgraded adapters:

```json
{"delivery_recorded": true, "delivered_chars": 24, "truncated": false,
 "delivered_text": "void routine_b(void) { }", "result_sha256": "...",
 "delivered_sha256": "..."}
```

Record delivery after filtering/truncation, not merely when a backend returns
text. Saved text may be confidential; review before sharing. Hashing does not
sanitize recorded text.

## Opaque input paths

Built-in and external runs analyse temporary `ral-input-<random>/sample.bin`
copies, removed after each episode. Bytes are unchanged; the evaluator retains
canonical artifact identity/hash. Variant IDs are not passed through paths.
Intentionally tested symbols/strings are unchanged. This is not filesystem
isolation against a hostile local adapter.

Old runs used variant-revealing paths. Input-path protocol is part of baseline
compatibility, so renew old baselines. Copying unchanged bytes is not a new
behavioural-equivalence experiment.

## Historical evidence

`python evidence/recompute.py` reproduces the original published statistics.
`python evidence/audit_delivery.py` inspects saved context for truncation
markers without editing it. On the six published run sets: 230 episodes,
555 saved decompile messages, zero with the harness truncation marker.
This does not establish a fresh opaque-path result, exclude backend truncation,
or eliminate all earlier experimental bias.

Controlled tests verify the corrected edge cases. Fresh model-rate estimates
require rerunning the relevant experiment under the corrected protocol. Do not
reuse old README rates as new-protocol estimates.
