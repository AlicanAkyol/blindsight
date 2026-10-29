"""Small stdin/stdout boundary for adapters around an existing agent."""
import asyncio
from contextlib import redirect_stdout, redirect_stderr
import inspect
import json
import os
from pathlib import Path
import stat
import sys
import traceback


def serve(analyse):
    """Call analyse(binary, frozen_prompt, seed), returning (report, actual_calls).

    Supports sync and async callbacks. Library prints go to stderr, never the
    JSON response. Set RAL_ADAPTER_LOG to retain private local diagnostics;
    the harness deliberately does not include stderr in public reports.
    """
    response_stream = sys.stdout
    log = None
    if path := os.environ.get("RAL_ADAPTER_LOG"):
        path = Path(path).expanduser()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError("RAL_ADAPTER_LOG must be a regular file")
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        log = os.fdopen(fd, "a")
    diagnostic_stream = log or sys.stderr
    try:
        with redirect_stdout(diagnostic_stream), redirect_stderr(diagnostic_stream):
            try:
                request = json.load(sys.stdin)
                if not isinstance(request, dict) or request.get("protocol") != "ral.target.v1":
                    raise ValueError("unsupported RAL protocol; expected ral.target.v1")
                binary, task, seed = request.get("binary"), request.get("task"), request.get("seed")
                if not isinstance(binary, str) or not Path(binary).is_absolute() or not Path(binary).is_file():
                    raise ValueError("binary must be an existing absolute file path")
                if not isinstance(task, dict) or not isinstance(task.get("prompt"), str):
                    raise ValueError("task.prompt must be a string")
                if type(seed) is not int:
                    raise ValueError("seed must be an integer")
                result = analyse(binary, task["prompt"], seed)
                if inspect.isawaitable(result):
                    result = asyncio.run(result)
                report, calls = result
                response = {"protocol": "ral.target.v1", "report": report}
                if calls is not None:
                    response["calls"] = calls
                # Use the same response validation as the installed harness.
                from . import product  # establishes the runner's legacy import path
                from .runner.external import validate_response
                validate_response(response)
                response_text = json.dumps(response, allow_nan=False)
            except Exception:
                traceback.print_exc(file=diagnostic_stream)
                raise SystemExit(1) from None
        response_stream.write(response_text)
        response_stream.write("\n")
    finally:
        if log:
            log.close()
