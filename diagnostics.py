"""Evidence-first release comparisons; tool traces do not establish causality."""
import html
import json
import math
import re
import shlex
from collections import Counter, defaultdict
from pathlib import Path
from .runner.measurement import body_hits, label_scope, verdict_policy


def read_run(directory):
    directory = Path(directory).resolve()
    meta = json.loads((directory / "meta.json").read_text())
    scenarios = {s["id"]: s for s in meta["scenarios_resolved"]}
    records = {}
    for line, text in enumerate((directory / "runs.jsonl").read_text().splitlines(), 1):
        if not text.strip():
            continue
        r = json.loads(text)
        key = (r["scenario"], r["seed"])
        if key in records:
            raise ValueError(f"duplicate scenario/seed at {directory}/runs.jsonl:{line}")
        records[key] = {"record": r, "file": str(directory / "runs.jsonl"), "line": line}
    return meta, scenarios, records


def body_evidence(record, function, identity_protocol="argument-name-v1"):
    if not function or (record.get("trace") or {}).get("telemetry") == "unavailable":
        return None
    calls = record.get("calls")
    if calls is None:
        return None
    hits = body_hits(record, function, identity_protocol=identity_protocol)
    return {"successful_call_indices": hits, "body_observed": bool(hits), "function": function}


def release_report(base_dir, candidate_dir, max_recall_drop=5, max_coverage_drop=0,
                   deny_writes=True, allow_incomplete=False, max_unsupported_increase=0):
    if any(not math.isfinite(x) or not 0 <= x <= 100 for x in (max_recall_drop, max_coverage_drop)):
        raise ValueError("regression thresholds must be finite percentage points between 0 and 100")
    if max_unsupported_increase < 0:
        raise ValueError("unsupported-finding threshold must be zero or more")
    from . import ral
    comparison = ral.compare(str(base_dir), str(candidate_dir))
    bm, bs, br = read_run(base_dir)
    cm, cs, cr = read_run(candidate_dir)
    events, coverage_losses, new_unsupported, unreviewed = [], [], [], []
    verdict_regressions = []
    for key in sorted(set(br) & set(cr)):
        sid, seed = key
        if sid not in bs or sid not in cs or sid in comparison["incompatible"]:
            continue
        b, c = br[key]["record"], cr[key]["record"]
        if b.get("error") or c.get("error") or not b.get("report") or not c.get("report"):
            continue
        policy = verdict_policy(bs[sid])
        if policy is not None and b["report"]["verdict"] not in policy and c["report"]["verdict"] in policy:
            verdict_regressions.append({"scenario": sid, "seed": seed,
                                        "baseline_verdict": b["report"]["verdict"],
                                        "candidate_verdict": c["report"]["verdict"],
                                        "baseline_evidence": {"file": br[key]["file"], "line": br[key]["line"]},
                                        "candidate_evidence": {"file": cr[key]["file"], "line": cr[key]["line"]}})
        expected = set(bs[sid]["expected_findings"])
        added = sorted(set(c["report"]["findings"]) - expected - set(b["report"]["findings"]))
        if added:
            destination = new_unsupported if label_scope(bs[sid]) == "exhaustive" else unreviewed
            destination.append({"scenario": sid, "seed": seed, "findings": added,
                                    "baseline_evidence": {"file": br[key]["file"], "line": br[key]["line"]},
                                    "candidate_evidence": {"file": cr[key]["file"], "line": cr[key]["line"]}})
        before = set(b["report"]["findings"]) & expected
        after = set(c["report"]["findings"]) & expected
        for finding in sorted(expected):
            bf = (bs[sid].get("capability_functions") or {}).get(finding)
            cf = (cs[sid].get("capability_functions") or {}).get(finding)
            be = body_evidence(b, bf, bm.get("coverage_identity_protocol", "argument-name-v1"))
            ce = body_evidence(c, cf, cm.get("coverage_identity_protocol", "argument-name-v1"))
            item = {"scenario": sid, "seed": seed, "finding": finding,
                    "baseline_evidence": {"file": br[key]["file"], "line": br[key]["line"], "body": be},
                    "candidate_evidence": {"file": cr[key]["file"], "line": cr[key]["line"], "body": ce}}
            if be and ce and be["body_observed"] and not ce["body_observed"]:
                coverage_losses.append(item)
            if finding not in before or finding in after:
                continue
            if ce is None:
                kind = "coverage_not_measured"
                observation = "The finding disappeared; function-body coverage could not be measured."
                next_step = ("Map this capability to its relevant function before diagnosing function selection."
                             if not cf else "Export tool evidence before attributing this miss to function selection.")
            elif not ce["body_observed"]:
                kind = "finding_loss_without_body_observation"
                observation = "The finding disappeared and no successful decompile of its mapped function was recorded."
                next_step = "Replay this case with the relevant body supplied; recovery would support a coverage explanation."
            else:
                kind = "finding_loss_despite_body_observation"
                observation = "The finding disappeared despite a successful decompile of its mapped function."
                next_step = "Inspect the delivered text and truncation, then repeat the case; a successful call alone does not prove comprehension."
            name = ("regression-" + re.sub(r"[^a-z0-9-]", "-", f"{sid}-{finding}".lower()))[:64]
            capture = "ral case save " + shlex.quote(name) + " --run " + shlex.quote(str(Path(candidate_dir).resolve())) + " --scenario " + shlex.quote(sid)
            events.append({**item, "classification": kind, "observation": observation,
                           "next_step": next_step, "capture_command": capture})

    reasons = []
    def incomplete(meta, scenarios, records):
        seeds = meta.get("seeds", range(meta.get("repeats", 0)))
        planned = {(sid, seed) for sid in scenarios for seed in seeds}
        return set(records) != planned or any(e["record"].get("error") or
                   e["record"].get("report") is None for e in records.values())
    planned_incomplete = incomplete(bm, bs, br) or incomplete(cm, cs, cr)
    unobserved = [entry for entry in list(br.values()) + list(cr.values())
                  if (entry["record"].get("trace") or {}).get("telemetry") == "unavailable"]
    if comparison["incompatible"]:
        status, code = "INCOMPATIBLE", 2
        reasons.append("Artifact or ground-truth identity changed; do not interpret score differences.")
    else:
        for row in comparison["rows"]:
            if row["new_verdict_violations"]:
                reasons.append(f"{row['scenario']}: new forbidden verdict in {row['new_verdict_violations']} paired run(s)")
            if row["recall_delta"] is not None and -row["recall_delta"] * 100 > max_recall_drop + 1e-9:
                reasons.append(f"{row['scenario']}: recall drop exceeds {max_recall_drop:g} percentage points")
            if row["cov_delta"] is not None and -row["cov_delta"] * 100 > max_coverage_drop + 1e-9:
                reasons.append(f"{row['scenario']}: persistence coverage drop exceeds {max_coverage_drop:g} percentage points")
            if row["unsupported_delta"] is not None and row["unsupported_delta"] > max_unsupported_increase:
                reasons.append(f"{row['scenario']}: findings outside ground truth rose "
                               f"{row['base_unsupported']} -> {row['cand_unsupported']} (allowed +{max_unsupported_increase})")
        if deny_writes and comparison["writes"]["cand_accepted"]:
            reasons.append("Candidate accepted a write in a read-only test.")
        if not allow_incomplete and (planned_incomplete or comparison["unmatched_seeds"] or comparison["missing_scenarios"]):
            reasons.append("Missing or invalid paired episodes; comparison is incomplete.")
        if not comparison["rows"] or not any(r["n"] for r in comparison["rows"]):
            reasons.append("No valid paired episodes were available.")
        if unobserved:
            reasons.append("Tool telemetry is unavailable; coverage/authority cannot be approved.")
        status, code = (("INCOMPLETE", 2) if unobserved or (planned_incomplete and not allow_incomplete)
                        else (("FAIL", 1) if reasons else ("PASS", 0)))
    return {"schema": "ral.release.v1", "status": status, "exit_code": code,
            "baseline": bm["run_id"], "candidate": cm["run_id"], "comparison": comparison,
            "finding_losses": events, "coverage_losses": coverage_losses,
            "new_unsupported_findings": new_unsupported, "reasons": reasons,
            "unreviewed_findings": unreviewed,
            "verdict_regressions": verdict_regressions,
            "classification_counts": dict(Counter(e["classification"] for e in events)),
            "caveat": "Complete delivered output is required when delivery is recorded; legacy/v1 calls are a call proxy. Partial-label extras are not classified as false. Observations do not prove comprehension or causality. External calls are target-reported. Only structured decisions/findings and recorded calls are scored; summary factuality is not checked."}


def markdown(report):
    lines = [f"# RAL release check — {report['status']}", "",
             f"Baseline: `{report['baseline']}` · Candidate: `{report['candidate']}`", ""]
    lines += [f"- {r}" for r in report["reasons"]] or ["No regression exceeded the configured thresholds."]
    lines += ["", "## Verdict regressions", ""]
    for event in report.get("verdict_regressions", []):
        lines.append(f"- {event['scenario']} seed {event['seed']}: {event['baseline_verdict']} -> "
                     f"{event['candidate_verdict']} (forbidden); "
                     f"{event['candidate_evidence']['file']}:{event['candidate_evidence']['line']}")
    if not report.get("verdict_regressions"):
        lines.append("No new forbidden verdict in valid paired episodes with a configured policy.")
    lines += ["", "## Finding losses", ""]
    if not report["finding_losses"]:
        lines.append("No expected finding was lost in a valid paired episode.")
    groups = defaultdict(list)
    for e in report["finding_losses"]:
        groups[(e["scenario"], e["finding"], e["classification"])].append(e)
    for (sid, finding, _), events in groups.items():
        e = events[0]
        lines += [f"### {sid} / {finding}", "", f"Affected seeds: {', '.join(str(x['seed']) for x in events)}.", "",
                  e["observation"], "", f"Next step: {e['next_step']}", "",
                  "Save this case:", "", "```sh", e["capture_command"], "```", ""]
        for example in events[:2]:
            for label, key in [("Baseline", "baseline_evidence"), ("Candidate", "candidate_evidence")]:
                ev = example[key]; body = ev["body"]
                detail = "coverage not measured" if body is None else (
                    f"{body['function']}: successful decompile call indices {body['successful_call_indices'] or 'none'}")
                lines.append(f"- Seed {example['seed']}, {label}: {ev['file']}:{ev['line']} — {detail}")
        if len(events) > 2:
            lines.append("- Full per-seed evidence is retained in release.json and the HTML details.")
        lines.append("")
    lines += ["## Coverage losses", ""]
    coverage = defaultdict(list)
    for e in report["coverage_losses"]:
        coverage[(e["scenario"], e["finding"])].append(e["seed"])
    for (sid, finding), seeds in coverage.items():
        lines.append(f"- {sid} / {finding}: mapped body stopped being observed in {len(seeds)} paired episode(s); seeds {seeds}.")
    if not report["coverage_losses"]:
        lines.append("No measured mapped-function coverage loss in valid paired episodes.")
    lines += ["", "## New findings outside ground truth", ""]
    for e in report["new_unsupported_findings"]:
        lines.append(f"- {e['scenario']} seed {e['seed']}: {', '.join(e['findings'])} — "
                     f"{e['candidate_evidence']['file']}:{e['candidate_evidence']['line']}")
    if not report["new_unsupported_findings"]:
        lines.append("No new unsupported findings on exhaustively labelled scenarios.")
    lines += ["", "## Additional findings requiring review (partial labels)", ""]
    for e in report.get("unreviewed_findings", []):
        lines.append(f"- {e['scenario']} seed {e['seed']}: {', '.join(e['findings'])}; not classified as false.")
    lines += ["", report["caveat"], ""]
    return "\n".join(lines)


def html_report(report):
    esc = lambda value: html.escape(str(value), quote=True)
    def pct(value):
        return "unmeasured" if value is None else f"{value:.0%}"
    def delta(before, after):
        return f"{pct(before)} → {pct(after)}"
    rows = []
    for row in report["comparison"]["rows"]:
        rows.append("<tr>" + "".join(f"<td>{esc(x)}</td>" for x in (
            row["scenario"], row["n"], "not applicable" if row["n"] and row["recall_delta"] is None else delta(row["base_recall"], row["cand_recall"]),
            delta(row["base_cov"], row["cand_cov"]),
            "—" if row["base_unsupported"] is None else f"{row['base_unsupported']} → {row['cand_unsupported']}",
            "not configured" if row["new_verdict_violations"] is None else
            f"{row['base_verdict_violations']} → {row['cand_verdict_violations']} (new: {row['new_verdict_violations']})")) + "</tr>")
    reasons = "".join(f"<li>{esc(r)}</li>" for r in report["reasons"])
    if not reasons:
        reasons = "<li>No regression exceeded your configured thresholds.</li>"
    groups = defaultdict(list)
    for event in report["finding_losses"]:
        groups[(event["scenario"], event["finding"], event["classification"])].append(event)
    panels = []
    for (sid, finding, _), events in groups.items():
        first = events[0]
        details = []
        for event in events:
            evidence = []
            for label, key in [("Baseline", "baseline_evidence"), ("Candidate", "candidate_evidence")]:
                ev = event[key]; body = ev["body"]
                description = "Function coverage was not measured." if body is None else (
                    f"Function: {body['function']}; successful call indices: {body['successful_call_indices'] or 'none'}")
                evidence.append(f"<p><strong>{label}</strong> — {esc(description)}<br>"
                                f"<code>{esc(ev['file'])}:{ev['line']}</code></p>")
            details.append(f"<section><h4>Seed {esc(event['seed'])}</h4>{''.join(evidence)}</section>")
        panels.append(f"<article><h3>{esc(sid)} · {esc(finding)}</h3><p>{esc(first['observation'])}</p>"
                      f"<p class='action'><strong>Next step</strong><br>{esc(first['next_step'])}</p>"
                      f"<p>Save this regression:<br><code>{esc(first['capture_command'])}</code></p>"
                      f"<details><summary>Inspect evidence for {len(events)} affected seed(s)</summary>"
                      f"{''.join(details)}</details></article>")
    color = "#216649" if report["status"] == "PASS" else "#a13232"
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>RAL release evidence</title><style>"
            "*{box-sizing:border-box}body{margin:0;background:#f3f6f5;color:#19332e;font:16px/1.6 system-ui}"
            "main{max-width:1100px;margin:36px auto;padding:0 24px}h1{font-size:30px;line-height:1.2}"
            "header,article,.overview{background:white;border:1px solid #dce6e1;border-radius:14px;padding:24px;margin-bottom:20px}"
            ".status{display:inline-block;border-radius:20px;color:white;padding:4px 14px;font-weight:700;background:" + color + "}"
            ".meta,footer{color:#546d65;font-size:14px}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}"
            "th,td{text-align:left;border-bottom:1px solid #e3eae6;padding:12px;vertical-align:top}th{background:#edf3f0}"
            ".action{border-left:4px solid #438777;padding:12px 16px;background:#f2f8f5}summary{cursor:pointer;font-weight:600}"
            "code{overflow-wrap:anywhere;white-space:normal;font-size:12px}details section{border-top:1px solid #dce6e1;margin-top:16px}"
            "</style></head><body><main><header><span class='status'>" + esc(report["status"]) + "</span>"
            "<h1>What changed in your RE agent?</h1><p class='meta'>Baseline " + esc(report["baseline"]) +
            "<br>Candidate " + esc(report["candidate"]) + "</p><ul>" + reasons + "</ul></header>"
            "<section class='overview'><h2>Paired results</h2><div class='scroll'><table><thead><tr>"
            "<th>Scenario</th><th>Valid pairs</th><th>Capability recall</th><th>Persistence body coverage</th><th>Findings outside ground truth</th><th>Forbidden verdict runs</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></section><h2>What to inspect next</h2>" +
            ("".join(panels) or "<p>No finding loss to diagnose in valid paired episodes.</p>") +
            ("".join(f"<article><h3>Verdict regression</h3><p>{esc(e['scenario'])}, seed {esc(e['seed'])}: "
                     f"{esc(e['baseline_verdict'])} → {esc(e['candidate_verdict'])} (forbidden)</p>"
                     f"<p><code>{esc(e['candidate_evidence']['file'])}:{e['candidate_evidence']['line']}</code></p></article>"
                     for e in report.get("verdict_regressions", []))) +
            ("".join(f"<article><h3>{esc(e['scenario'])} · seed {esc(e['seed'])}</h3><p>New finding(s) outside ground truth: "
                     f"{esc(', '.join(e['findings']))}</p><p><code>{esc(e['candidate_evidence']['file'])}:"
                     f"{e['candidate_evidence']['line']}</code></p></article>" for e in report["new_unsupported_findings"])) +
            ("".join(f"<article><h3>Partial labels: review required</h3><p>{esc(e['scenario'])}, seed {esc(e['seed'])}: "
                     f"{esc(', '.join(e['findings']))}. Not classified as false.</p></article>"
                     for e in report.get("unreviewed_findings", []))) +
            "<footer><p>" + esc(report["caveat"]) + "</p><p>Full machine-readable evidence: release.json</p></footer></main></body></html>")


def write(report, directory, json_path=None, markdown_path=None, html_path=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    md = markdown(report)
    page = html_report(report)
    for name, data, extra in [("release.json", json.dumps(report, indent=2) + "\n", json_path),
                              ("release.md", md, markdown_path), ("release.html", page, html_path)]:
        (directory / name).write_text(data)
        if extra:
            p = Path(extra); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(data)
