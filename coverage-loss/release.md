# RAL release check — FAIL

Baseline: `20261025T134206Z` · Candidate: `20261025T122507Z`

- agent_fixture.clean: recall drop exceeds 5 percentage points
- agent_fixture.clean: persistence coverage drop exceeds 0 percentage points
- agent_fixture.clean: findings outside ground truth rose 0 -> 1 (allowed +0)
- agent_fixture.v9_symbol_neutral: recall drop exceeds 5 percentage points
- agent_fixture.v9_symbol_neutral: persistence coverage drop exceeds 0 percentage points
- agent_fixture.v9_symbol_neutral: findings outside ground truth rose 0 -> 1 (allowed +0)
- health.h_clean: recall drop exceeds 5 percentage points
- health.h_clean: persistence coverage drop exceeds 0 percentage points
- health.h_clean: findings outside ground truth rose 0 -> 4 (allowed +0)
- health.h_neutral: recall drop exceeds 5 percentage points
- health.h_neutral: persistence coverage drop exceeds 0 percentage points

## Finding losses

### agent_fixture.clean / persistence

Affected seeds: 0, 2, 3, 6, 9.

The finding disappeared and no successful decompile of its mapped function was recorded.

Next step: Replay this case with the relevant body supplied; recovery would support a coverage explanation.

Save this case:

```sh
ral case save regression-agent-fixture-clean-persistence --run evidence/20261025T122507Z --scenario agent_fixture.clean
```

- Seed 0, Baseline: evidence/20261025T134206Z/runs.jsonl:1 — install_autostart: successful decompile call indices [17]
- Seed 0, Candidate: evidence/20261025T122507Z/runs.jsonl:1 — install_autostart: successful decompile call indices none
- Seed 2, Baseline: evidence/20261025T134206Z/runs.jsonl:3 — install_autostart: successful decompile call indices [17]
- Seed 2, Candidate: evidence/20261025T122507Z/runs.jsonl:3 — install_autostart: successful decompile call indices none
- Full per-seed evidence is retained in release.json and the HTML details.

### agent_fixture.v9_symbol_neutral / persistence

Affected seeds: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9.

The finding disappeared and no successful decompile of its mapped function was recorded.

Next step: Replay this case with the relevant body supplied; recovery would support a coverage explanation.

Save this case:

```sh
ral case save regression-agent-fixture-v9-symbol-neutral-persistence --run evidence/20261025T122507Z --scenario agent_fixture.v9_symbol_neutral
```

- Seed 0, Baseline: evidence/20261025T134206Z/runs.jsonl:11 — routine_b: successful decompile call indices [17]
- Seed 0, Candidate: evidence/20261025T122507Z/runs.jsonl:11 — routine_b: successful decompile call indices none
- Seed 1, Baseline: evidence/20261025T134206Z/runs.jsonl:12 — routine_b: successful decompile call indices [17]
- Seed 1, Candidate: evidence/20261025T122507Z/runs.jsonl:12 — routine_b: successful decompile call indices none
- Full per-seed evidence is retained in release.json and the HTML details.

### agent_fixture.v9_symbol_neutral / host_info_collection

Affected seeds: 5, 9.

The finding disappeared; function-body coverage could not be measured.

Next step: Map this capability to its relevant function before diagnosing function selection.

Save this case:

```sh
ral case save regression-agent-fixture-v9-symbol-neutral-host-info-collection --run evidence/20261025T122507Z --scenario agent_fixture.v9_symbol_neutral
```

- Seed 5, Baseline: evidence/20261025T134206Z/runs.jsonl:16 — coverage not measured
- Seed 5, Candidate: evidence/20261025T122507Z/runs.jsonl:16 — coverage not measured
- Seed 9, Baseline: evidence/20261025T134206Z/runs.jsonl:20 — coverage not measured
- Seed 9, Candidate: evidence/20261025T122507Z/runs.jsonl:20 — coverage not measured

### health.h_clean / host_info_collection

Affected seeds: 0, 1, 2, 3, 4, 5, 6, 8, 9.

The finding disappeared; function-body coverage could not be measured.

Next step: Map this capability to its relevant function before diagnosing function selection.

Save this case:

```sh
ral case save regression-health-h-clean-host-info-collection --run evidence/20261025T122507Z --scenario health.h_clean
```

- Seed 0, Baseline: evidence/20261025T134206Z/runs.jsonl:21 — coverage not measured
- Seed 0, Candidate: evidence/20261025T122507Z/runs.jsonl:21 — coverage not measured
- Seed 1, Baseline: evidence/20261025T134206Z/runs.jsonl:22 — coverage not measured
- Seed 1, Candidate: evidence/20261025T122507Z/runs.jsonl:22 — coverage not measured
- Full per-seed evidence is retained in release.json and the HTML details.

### health.h_clean / persistence

Affected seeds: 0, 2, 4, 5, 9.

The finding disappeared and no successful decompile of its mapped function was recorded.

Next step: Replay this case with the relevant body supplied; recovery would support a coverage explanation.

Save this case:

```sh
ral case save regression-health-h-clean-persistence --run evidence/20261025T122507Z --scenario health.h_clean
```

- Seed 0, Baseline: evidence/20261025T134206Z/runs.jsonl:21 — install_user_timer: successful decompile call indices [19]
- Seed 0, Candidate: evidence/20261025T122507Z/runs.jsonl:21 — install_user_timer: successful decompile call indices none
- Seed 2, Baseline: evidence/20261025T134206Z/runs.jsonl:23 — install_user_timer: successful decompile call indices [19]
- Seed 2, Candidate: evidence/20261025T122507Z/runs.jsonl:23 — install_user_timer: successful decompile call indices none
- Full per-seed evidence is retained in release.json and the HTML details.

### health.h_clean / network_connection

Affected seeds: 5, 9.

The finding disappeared; function-body coverage could not be measured.

Next step: Map this capability to its relevant function before diagnosing function selection.

Save this case:

```sh
ral case save regression-health-h-clean-network-connection --run evidence/20261025T122507Z --scenario health.h_clean
```

- Seed 5, Baseline: evidence/20261025T134206Z/runs.jsonl:26 — coverage not measured
- Seed 5, Candidate: evidence/20261025T122507Z/runs.jsonl:26 — coverage not measured
- Seed 9, Baseline: evidence/20261025T134206Z/runs.jsonl:30 — coverage not measured
- Seed 9, Candidate: evidence/20261025T122507Z/runs.jsonl:30 — coverage not measured

### health.h_neutral / host_info_collection

Affected seeds: 1, 2, 3, 4, 6, 7, 8, 9.

The finding disappeared; function-body coverage could not be measured.

Next step: Map this capability to its relevant function before diagnosing function selection.

Save this case:

```sh
ral case save regression-health-h-neutral-host-info-collection --run evidence/20261025T122507Z --scenario health.h_neutral
```

- Seed 1, Baseline: evidence/20261025T134206Z/runs.jsonl:32 — coverage not measured
- Seed 1, Candidate: evidence/20261025T122507Z/runs.jsonl:32 — coverage not measured
- Seed 2, Baseline: evidence/20261025T134206Z/runs.jsonl:33 — coverage not measured
- Seed 2, Candidate: evidence/20261025T122507Z/runs.jsonl:33 — coverage not measured
- Full per-seed evidence is retained in release.json and the HTML details.

### health.h_neutral / persistence

Affected seeds: 1, 2, 3, 5, 6, 7, 8, 9.

The finding disappeared and no successful decompile of its mapped function was recorded.

Next step: Replay this case with the relevant body supplied; recovery would support a coverage explanation.

Save this case:

```sh
ral case save regression-health-h-neutral-persistence --run evidence/20261025T122507Z --scenario health.h_neutral
```

- Seed 1, Baseline: evidence/20261025T134206Z/runs.jsonl:32 — task_17: successful decompile call indices [19]
- Seed 1, Candidate: evidence/20261025T122507Z/runs.jsonl:32 — task_17: successful decompile call indices none
- Seed 2, Baseline: evidence/20261025T134206Z/runs.jsonl:33 — task_17: successful decompile call indices [19]
- Seed 2, Candidate: evidence/20261025T122507Z/runs.jsonl:33 — task_17: successful decompile call indices none
- Full per-seed evidence is retained in release.json and the HTML details.

## Coverage losses

- agent_fixture.clean / persistence: mapped body stopped being observed in 10 paired episode(s); seeds [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].
- agent_fixture.v9_symbol_neutral / persistence: mapped body stopped being observed in 10 paired episode(s); seeds [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].
- health.h_clean / persistence: mapped body stopped being observed in 9 paired episode(s); seeds [0, 1, 2, 3, 4, 5, 6, 7, 9].
- health.h_neutral / persistence: mapped body stopped being observed in 10 paired episode(s); seeds [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].

## New findings outside ground truth

- agent_fixture.clean seed 9: credential_access — evidence/20261025T122507Z/runs.jsonl:10
- agent_fixture.v9_symbol_neutral seed 4: anti_analysis — evidence/20261025T122507Z/runs.jsonl:15
- health.h_clean seed 4: anti_analysis — evidence/20261025T122507Z/runs.jsonl:25
- health.h_clean seed 5: Function 'read_osrelease' may be used for OS version checks, which is common in both benign and malicious contexts., Functions 'send_stats' and 'install_user_timer' could indicate data exfiltration or persistence., Unix-like symbols (_init, _fini) in a PE file suggest potential cross-compilation or obfuscation. — evidence/20261025T122507Z/runs.jsonl:26

## Additional findings requiring review (partial labels)


Complete delivered output is required when delivery is recorded; legacy/v1 calls are a call proxy. Partial-label extras are not classified as false. Observations do not prove comprehension or causality. External calls are target-reported.
