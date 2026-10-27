"""Versioned stdin/stdout adapter for user-owned agents. No shell execution."""
import json
import math
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from tasks import FINDINGS, TASKS, VERDICTS
from inputs import opaque_binary

PROTOCOL = "ral.target.v1"
MAX_OUTPUT = 2 * 1024 * 1024


def _capture(command, payload, *, cwd=None, env=None, timeout=600):
    """Bound both pipes while running; adapter processes are still trusted code."""
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("target timeout must be finite and positive")
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=cwd, env=env,
                            start_new_session=True, bufsize=0)
    deadline = time.monotonic() + timeout
    failed = threading.Event()
    failures = []
    response = bytearray()

    def stop():
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            elif proc.poll() is None:
                proc.kill()
        except ProcessLookupError:
            pass

    def read(stream, name, retain=False):
        size = 0
        try:
            while chunk := stream.read(min(65536, MAX_OUTPUT + 1 - size)):
                size += len(chunk)
                if size > MAX_OUTPUT:
                    failures.append(f"target {name} exceeds 2 MiB")
                    failed.set()
                    break
                if retain:
                    response.extend(chunk)
        except OSError:
            failures.append(f"could not capture target {name}")
            failed.set()
        finally:
            stream.close()

    def write():
        try:
            view = memoryview(payload)
            while view:
                written = proc.stdin.write(view)
                if not written:
                    break
                view = view[written:]
        except (BrokenPipeError, OSError):
            pass
        finally:
            proc.stdin.close()

    workers = [threading.Thread(target=read, args=(proc.stdout, "response", True), daemon=True),
               threading.Thread(target=read, args=(proc.stderr, "stderr"), daemon=True),
               threading.Thread(target=write, daemon=True)]
    try:
        for worker in workers:
            worker.start()
        while proc.poll() is None:
            if failed.is_set():
                raise ValueError(failures[0])
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("target timed out")
            failed.wait(min(0.05, remaining))
        # An episode owns its subprocess group. Stop children that outlive the adapter.
        stop()
        for worker in workers:
            worker.join(timeout=1)
        if failed.is_set():
            raise ValueError(failures[0])
        if any(worker.is_alive() for worker in workers):
            raise ValueError("target output capture did not complete")
        if proc.returncode:
            raise ValueError(f"target exited with code {proc.returncode}; inspect the adapter locally")
        return bytes(response)
    finally:
        stop()
        proc.wait(timeout=2)
        for worker in workers:
            worker.join(timeout=1)


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
            if type(c.get("result_chars")) is not int or c["result_chars"] < 0:
                raise ValueError("each call needs non-negative result_chars")
            if "delivery_recorded" in c:
                if type(c["delivery_recorded"]) is not bool:
                    raise ValueError("delivery_recorded must be boolean")
                if c["delivery_recorded"] and (type(c.get("delivered_chars")) is not int
                        or c["delivered_chars"] < 0 or type(c.get("truncated")) is not bool):
                    raise ValueError("delivery evidence needs delivered_chars and truncated")
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
        with opaque_binary(binary) as opaque:
            request["binary"] = str(opaque)
            data = _capture(command, (json.dumps(request) + "\n").encode(),
                            cwd=target.get("cwd"), env=env, timeout=target.get("timeout", 600))
            obj = validate_response(json.loads(data))
        record["report"] = obj["report"]
        record["calls"] = obj.get("calls", [])
        record["trace"] = {"telemetry": "target_reported" if "calls" in obj else "unavailable"}
    except (OSError, ValueError, TypeError) as e:
        record["error"] = f"{type(e).__name__}: {e}"
    record["seconds"] = round(time.monotonic() - started, 3)
    return record
