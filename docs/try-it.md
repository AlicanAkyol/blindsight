# A focused first trial

Start with `ral demo` ([instructions](demo.md)). Open the policy-change report
and check why improved recall still produces FAIL. This needs no RE stack and
tests the report's usefulness, not your agent's performance.

If you already use GhidraMCP and local Ollama, follow [quickstart.md](quickstart.md)
to install the `[ghidra]` extra and configure the existing stack. Then run:

```sh
ral doctor
ral check --suite quick --html first-check.html
```

The quick suite uses four variants and one seed. It can take several minutes;
it is not a reliable success-rate estimate. Exit 1 is a completed check with a
measured miss, unsupported finding or write; exit 2 means execution or telemetry
is incomplete. A report from this bundled loop does not evaluate another agent
you already use; that requires an [adapter](target-protocol.md).

Useful feedback fits in a short [GitHub issue](https://github.com/AlicanAkyol/blindsight/issues/new):

- OS, Python and `ral --version`.
- The command you tried and its exit code.
- The first setup step that blocked you, or the report detail that helped you
  understand a miss.

Share only public-safe details. There is no need to upload proprietary binaries,
API keys, private paths, or complete tool logs. The most useful first result is
an honest installation failure or a concrete report observation, not a star.
