# RAL release check — FAIL

Baseline: `20261025T122507Z` · Candidate: `20261025T134206Z`

- health.h_neutral: findings outside ground truth rose 0 -> 1 (allowed +0)

## Finding losses

### agent_fixture.clean / network_connection

Affected seeds: 8.

The finding disappeared; function-body coverage could not be measured.

Next step: Map this capability to its relevant function before diagnosing function selection.

Save this case:

```sh
ral case save regression-agent-fixture-clean-network-connection --run evidence/20261025T134206Z --scenario agent_fixture.clean
```

- Seed 8, Baseline: evidence/20261025T122507Z/runs.jsonl:9 — coverage not measured
- Seed 8, Candidate: evidence/20261025T134206Z/runs.jsonl:9 — coverage not measured

## Coverage losses

No measured mapped-function coverage loss in valid paired episodes.

## New findings outside ground truth

- health.h_neutral seed 5: credential_access — evidence/20261025T134206Z/runs.jsonl:36

## Additional findings requiring review (partial labels)


Complete delivered output is required when delivery is recorded; legacy/v1 calls are a call proxy. Partial-label extras are not classified as false. Observations do not prove comprehension or causality. External calls are target-reported.
