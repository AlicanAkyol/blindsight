# Security boundaries

Blindsight evaluates a declared agent against controlled fixtures. It does not
certify that an agent or MCP server is safe, and it is not a containment system
for an untrusted agent or arbitrary malware. The supported real-model pilot is
GhidraMCP, Linux/x86-64 ELF and local Qwen3-8B via Ollama. Installed-CLI CI runs
on Linux/macOS with Python 3.10 and 3.13.

| Boundary | Implemented control | Limit |
|---|---|---|
| Fixture inputs | Bundled artifact hashes; opaque temporary input paths | Path blinding is not filesystem isolation. |
| Target launch | Explicit executable argv; fixture request on stdin; no implicit shell | The target has the user's permissions and inherits the environment. Only run adapters you trust. |
| Adapter I/O | Bounded in-memory capture; stdout and stderr each capped at 2 MiB during execution | Other files, process memory, network and CPU are not sandboxed or quota-controlled. |
| Adapter lifetime | Per-episode deadline; Linux/macOS process-group cleanup on completion or failure | Detached descendants can escape that process group. Windows descendant cleanup is not established. |
| Malformed/missing output | Invalid response, timeout, output overflow or non-zero exit records an error; incomplete checks exit 2 | This checks the response contract, not whether a target's claims are true. |
| External telemetry | Explicitly marked target-reported; missing telemetry cannot pass coverage/authority checks | A dishonest adapter can omit or falsify calls. Independent auditing must come from its execution layer. |
| Tool writes | Built-in read-only profile refuses configured write tools before invocation | An observed run with no writes is not proof that a write boundary exists. External targets enforce their own tool policy. |
| Coverage | Complete delivered output when recorded; legacy successful-call proxy separately labelled | Delivery is not comprehension, and observed calls do not establish causality. |
| Comparison | Versioned scenario/artifact compatibility, seed pairing and strict completeness | Synthetic fixtures and finite seeds do not establish general malware-analysis quality. |

Do not put API keys or other secrets in target argv: it is retained for
reproducibility. Configured environment values are not copied into metadata;
target-provided reports and call arguments can still contain sensitive data.
Review exports before publishing them. Blindsight does not upload run logs by
itself.

The recorded browser demo uses already-public historical pilot evidence. Its
PASS control is a run compared with itself. Demo exit 0 confirms the replay's
expected outcomes, not that an agent passed a new security evaluation.

`ral local` runs the read-only reference loop and model client on the host,
and only GhidraMCP in an unprivileged, read-only-root Docker container with
networking disabled and one opaque read-only input file. This does not sandbox
the host agent. Public pinned runtime assets are hash-checked; images are built
locally, not pulled from an unreviewed Blindsight image registry. The setup can
download large model weights, starts only a loopback-owned Ollama service if
needed, and removes only containers carrying that invocation's ownership label.
Existing Ollama services are not stopped. Custom agents still require their
own integration and enforcement.
