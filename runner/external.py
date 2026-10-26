"""Versioned stdin/stdout adapter for user-owned agents. No shell execution."""
import json
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from tasks import FINDINGS, TASKS, VERDICTS

PROTOCOL = "ral.target.v1"
MAX_OUTPUT = 2 * 1024 * 1024


def validate_response(obj):
    if not isinstance(obj, dict) or obj.get("protocol") != PROTOCOL:
        raise ValueError(f"target must return protocol={PROTOCOL}")
    report = obj.get("report")
    if not isinstance(report, dict) or report.get("verdict") not in VERDICTS:
        raise ValueError("target report.verdict must be malicious, suspicious or benign")
    fs = report.get("findings")
    if not isinstance(fs, list) or any(not isinstance(f, str) or f not in FINDINGS for f in fs):
        raise ValueError("target report.findings must be a list of supported finding names")
    if not isinstance(report.get("summary"), str):
        raise ValueError("target report.summary must be a string")
    if "calls" in obj:
        if not isinstance(obj["calls"], list):
            raise ValueError("calls must be a list")
        for c in obj["calls"]:
            if not isinstance(c, dict) or not isinstance(c.get("tool"), str):
                raise ValueError("each call needs a tool name")
            if not isinstance(c.get("args"), dict):
                raise ValueError("each call needs an args object")
            if any(not isinstance(c.get(k), bool) for k in ("write", "is_error")):
                raise ValueError("each call needs boolean write and is_error fields")
            if not isinstance(c.get("result_chars"), int) or c["result_chars"] < 0:
                raise ValueError("each call needs non-negative result_chars")
    return obj


def run_one(target, scenario, binary, seed, prompt=None):
    started = time.monotonic()
    record = {"agent": "external", "scenario": scenario["id"], "seed": seed,
              "repeat": seed, "calls": [], "report": None,
              "trace": {"telemetry": "unavailable"}}
    request = {"protocol": PROTOCOL, "binary": str(Path(binary).resolve()), "seed": seed,
               "task": {"id": scenario["task"], "prompt": prompt if prompt is not None else TASKS[scenario["task"]]["prompt"]}}
    try:
        command = target.get("command")
        if not isinstance(command, list) or not command or any(not isinstance(x, str) for x in command):
            raise ValueError("target.command must be a non-empty argv list")
        env = dict(os.environ, **target.get("env", {}))
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err,
                                    cwd=target.get("cwd"), env=env, start_new_session=True)
            try:
                proc.communicate((json.dumps(request) + "\n").encode(), timeout=target.get("timeout", 600))
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
                proc.communicate()
                raise ValueError("target timed out")
            if proc.returncode:
                raise ValueError(f"target exited with code {proc.returncode}; inspect the adapter locally")
            out.seek(0)
            data = out.read(MAX_OUTPUT + 1)
            if len(data) > MAX_OUTPUT:
                raise ValueError("target response exceeds 2 MiB")
            obj = validate_response(json.loads(data))
        record["report"] = obj["report"]
        record["calls"] = obj.get("calls", [])
        record["trace"] = {"telemetry": "target_reported" if "calls" in obj else "unavailable"}
    except (OSError, ValueError, TypeError) as e:
        record["error"] = f"{type(e).__name__}: {e}"
    record["seconds"] = round(time.monotonic() - started, 3)
    return record
