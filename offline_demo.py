"""Re-score published pilot runs without an agent, binaries or network access."""
import hashlib
import html
import json
import shutil
from pathlib import Path

from . import diagnostics

NATURAL = "20261025T122507Z"
COVERAGE = "20261025T134206Z"
HASHES = {
    f"{NATURAL}/meta.json": "f8ee2045d463535a07ade25d0566e7cb2e1811f49e84fbc47c0b50de5f26d44a",
    f"{NATURAL}/runs.jsonl": "043f82b268c969d03faaf1019cfdffefe18f64a31b4e106ee29648134a265a65",
    f"{COVERAGE}/meta.json": "3fb0e7ba232da9ff5d0eb9f77aebb8ce8788d4b64aacd8dd59ff9baf9e282843",
    f"{COVERAGE}/runs.jsonl": "dae794101cd8fda0b0913121dc7c8b202fece625d3c9ce64809357b457802928",
}
NOTICE = ("Recorded pilot replay — no new model inference. Qwen3-8B, one toolchain, "
          "two synthetic ELF fixtures, ten seeds per scenario. Historical coverage is a "
          "successful-call proxy, not verified complete delivery or comprehension. "
          "The coverage policy was designed on these fixtures; there is no holdout.")


def _portable(value, root):
    if isinstance(value, dict):
        return {k: _portable(v, root) for k, v in value.items()}
    if isinstance(value, list):
        return [_portable(v, root) for v in value]
    return value.replace(str(root) + "/", "") if isinstance(value, str) else value


def render(output):
    """Create a new self-contained report directory; never overwrite user files."""
    source = Path(__file__).resolve().parent / "evidence"
    # Verify the complete input before creating an output directory.
    for name, expected in HASHES.items():
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Recorded demo evidence failed its checksum: {name}")
    output = Path(output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name in HASHES:
        destination = output / "evidence" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, destination)
    natural, coverage = (output / "evidence" / run for run in (NATURAL, COVERAGE))
    examples = [
        ("unchanged", natural, natural, "PASS", "No-change control",
         "The same recorded run compared with itself. PASS means no regression; it does not mean the agent found everything."),
        ("policy-change", natural, coverage, "FAIL", "Better recall, still a regression",
         "The policy improved recall, but health.h_neutral seed 5 added credential_access outside exhaustive ground truth. The strict gate catches it."),
        ("coverage-loss", coverage, natural, "FAIL", "Reverse comparison: lost coverage",
         "Reversing the same two runs exposes finding and function-selection regressions. This is a sensitivity check, not a third experiment."),
    ]
    cards, results = [], {}
    for name, base, candidate, expected, title, explanation in examples:
        report = _portable(diagnostics.release_report(base, candidate), output)
        if report["status"] != expected:
            raise ValueError(f"Demo replay changed: {name} expected {expected}, got {report['status']}")
        report["demo"] = {"notice": NOTICE, "explanation": explanation,
                          "source": "https://github.com/AlicanAkyol/blindsight/tree/b6b8e9e8db8badb4fae399b2425e478f86e16058/evidence"}
        directory = output / name
        diagnostics.write(report, directory)
        banner = ("<section class='overview'><a href='../index.html'>← Demo overview</a>"
                  f"<h2>{html.escape(title)}</h2><p>{html.escape(explanation)}</p>"
                  f"<p><strong>{html.escape(NOTICE)}</strong></p>"
                  "<p>Evidence paths are relative to the demo directory. "
                  "<a href='../evidence/" + candidate.name + "/runs.jsonl'>Candidate raw records</a> · "
                  "<a href='release.json'>Comparison JSON</a></p></section>")
        page = diagnostics.html_report(report).replace("<main>", "<main>" + banner, 1)
        (directory / "release.html").write_text(page)
        results[name] = {"status": report["status"], "gate_exit_code": report["exit_code"]}
        cards.append(f"<article><span class='{expected.lower()}'>{expected}</span><h2>{html.escape(title)}</h2>"
                     f"<p>{html.escape(explanation)}</p><a href='{name}/release.html'>Inspect report →</a></article>")
    index = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
             "<meta name='viewport' content='width=device-width,initial-scale=1'>"
             "<title>Blindsight — recorded demo</title><style>"
             "body{margin:0;background:#f3f6f5;color:#19332e;font:17px/1.6 system-ui}"
             "main{max-width:900px;margin:40px auto;padding:0 24px}article,header{background:white;"
             "border:1px solid #dce6e1;border-radius:14px;padding:24px;margin:20px 0}"
             "a{color:#165f63}h1{line-height:1.2}.pass,.fail{font-weight:bold;padding:4px 12px;"
             "border-radius:16px;color:white}.pass{background:#216649}.fail{background:#a13232}"
             "</style><main><header><p>BLINDSIGHT / RECORDED DEMO</p>"
             "<h1>Did your RE agent stop reading the relevant code?</h1>"
             "<p>Inspect three comparisons computed from published raw records. "
             "No Ghidra, model, API key or binary execution is needed.</p>"
             f"<p><strong>{html.escape(NOTICE)}</strong></p></header>" + "".join(cards) +
             "<footer><p>The demo command exits 0 when replay matches these expected outcomes. "
             "A real <code>ral gate</code> exits 1 for a measured regression and 2 for incompatible or incomplete evidence.</p>"
             "<p><a href='https://github.com/AlicanAkyol/blindsight/blob/main/docs/quickstart.md'>"
             "Next: test your own agent</a> · <a href='manifest.json'>Evidence checksums and outcomes</a></p></footer></main></html>")
    (output / "index.html").write_text(index)
    (output / "manifest.json").write_text(json.dumps({"kind": "recorded_pilot_replay", "notice": NOTICE,
                                                    "sha256": HASHES, "results": results}, indent=2) + "\n")
    print(NOTICE)
    for name, result in results.items():
        print(f"{name}: GATE {result['status']} (real gate exit {result['gate_exit_code']})")
    print("Replay verified. This command's exit 0 is not a security pass.")
    print(f"Open: {(output / 'index.html').as_uri()}")
    return 0
