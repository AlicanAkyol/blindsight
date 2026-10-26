# Find the regression, inspect the evidence, keep the test

RAL's release workflow answers: "After changing my reverse-engineering agent,
which expected capabilities did it stop finding, and what did it stop reading?"

## Compare two releases

Run the same suite before and after changing your agent or analysis policy:

```sh
ral check --suite ci
ral baseline save
# Change your agent/model/toolchain, then:
ral check --suite ci --baseline saved
```

Besides the scorecard, the comparison now writes `release.json`, `release.md`
and `release.html` under `.ral/reports/release-<timestamp>/`. For existing runs:

```sh
ral compare /path/to/baseline /path/to/candidate --html release.html --json release.json
ral gate /path/to/baseline /path/to/candidate \
  --max-recall-drop 5 --max-coverage-drop 0 --deny-unauthorized-writes
```

The HTML report starts with paired recall/coverage changes. It groups finding
losses by scenario and capability, and shows the next diagnostic step. Open
each group's details to inspect seed, original JSONL file/line and successful
decompile call indices. Raw measurements remain in the source run directories.
`release.json` retains every event even when Markdown groups examples.

The gate also fails when the candidate reports more findings outside source
ground truth than the seed-paired baseline did, even if recall and coverage are
unchanged. Each new unsupported finding is listed with its seed and JSONL line.
`--max-unsupported-increase N` allows a rise of N per scenario (default 0).

Three observations are kept distinct:

| Observation | What it supports | Next step |
|---|---|---|
| Finding lost; mapped function not decompiled | A coverage explanation is plausible | Repeat with that body explicitly supplied |
| Finding lost; function successfully decompiled | The recorded call alone did not ensure the finding | Inspect the actual text, truncation and subsequent analysis |
| No mapped function or unavailable telemetry | Coverage cannot explain the miss from these logs | Add an appropriate capability mapping or trustworthy telemetry |

This is diagnostic evidence, not automatic proof of cause. Body recovery is
only causally informative under a controlled intervention; running the same
case again is not itself that intervention. External target telemetry is
labelled as self-reported. Successful calls do not prove full model attention.

The gate uses per-scenario aggregate thresholds. Individual lost findings can
appear in the report even if the aggregate improves and the gate passes.
Run compatibility and missing episodes are checked before approving a release.

## Turn a discovered miss into a persistent case

Use the capture command included in the report, or:

```sh
ral case save neutral-persistence \
  --run /path/to/candidate \
  --scenario agent_fixture.v9_symbol_neutral
ral case list
ral case show neutral-persistence
ral check --case neutral-persistence
```

`--run` defaults to your last check. The case capsule includes:

- the exact scenario and recursively required matched controls;
- the source run's planned seed list, including non-zero seeds;
- source task prompts, expected findings and capability mappings;
- copies of the original ELF files with source SHA-256 hashes;
- selected source observations for provenance.

Capsules live in `.ral/cases/<name>/`. They contain no executable adapter
configuration and do not auto-run code when opened. A check statically analyses
the stored ELF using your selected target/profile. Modified or missing case
artifacts fail hash verification. Existing case names are not overwritten.
Source files in the shared fixture workspace can change without changing the
captured copy.

To check whether a mitigation improves a case:

```sh
ral check --case neutral-persistence
ral baseline save --replace
ral check --case neutral-persistence --profile ghidramcp-ollama-coverage --baseline saved
```

The built-in coverage profile tests RAL's Ghidra/Ollama runner. For your own
agent, implement the mitigation there and replay using your configured target.
The request to the target still contains only binary path, source task prompt
and seed. The adapter never receives the expected answer or control mapping.

Capture currently freezes scenarios already present in a RAL run. It is not
an arbitrary-malware importer or an automatic ground-truth generator. Both
the scenario and all matched controls must have valid results for every
planned seed; a partial run cannot silently become a complete regression case.

## Locality and reproducibility

The CLI does not upload capsules or reports. A case may contain private binary
bytes, tool output and analysis transcripts; sharing is an explicit team action.
The snapshot preserves test inputs, but local model/runtime nondeterminism can
still change the output at the same seed. Report fresh observations rather
than assuming bit-identical replay.
