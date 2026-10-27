"""Subprocess I/O boundary tests; generated targets are simulated, not RE results."""
import copy
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from blindsight import product  # establishes the installed runner import path
from blindsight.runner.external import _capture, MAX_OUTPUT, validate_response


class ExternalBoundaryTests(unittest.TestCase):
    def capture(self, code, payload=b"{}", timeout=10):
        return _capture([sys.executable, "-c", code], payload, timeout=timeout)

    def test_large_stdin_and_both_output_pipes_are_drained(self):
        data = b"x" * (3 * 1024 * 1024)
        result = self.capture("import sys; data=sys.stdin.buffer.read(); "
                              "sys.stderr.write('log'*100000); print(len(data))", data)
        self.assertEqual(int(result), len(data))

    def test_exact_output_limit_is_accepted(self):
        result = self.capture(f"import sys; sys.stdout.buffer.write(b'x'*{MAX_OUTPUT})")
        self.assertEqual(len(result), MAX_OUTPUT)

    def test_unending_stdout_is_stopped_at_output_limit(self):
        with self.assertRaisesRegex(ValueError, "response exceeds 2 MiB"):
            self.capture("import os\nwhile True: os.write(1,b'x'*65536)")

    def test_unending_stderr_is_stopped_even_with_a_valid_stdout_reply(self):
        with self.assertRaisesRegex(ValueError, "stderr exceeds 2 MiB"):
            self.capture("import os\nos.write(1,b'{}')\nwhile True: os.write(2,b'x'*65536)")

    def test_timeout_stops_process_that_never_reads_stdin(self):
        with self.assertRaisesRegex(ValueError, "timed out"):
            self.capture("import time; time.sleep(30)", b"x" * MAX_OUTPUT, timeout=0.1)

    def test_nonzero_exit_does_not_leak_stderr(self):
        with self.assertRaisesRegex(ValueError, "exited with code 7") as error:
            self.capture("import sys; print('private diagnostic',file=sys.stderr); sys.exit(7)")
        self.assertNotIn("private diagnostic", str(error.exception))

    @unittest.skipUnless(os.name == "posix", "process-group cleanup is POSIX-only")
    def test_timeout_stops_children_in_the_same_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            code = ("import subprocess,sys,time,pathlib; "
                    "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                    f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid)); time.sleep(30)")
            with self.assertRaisesRegex(ValueError, "timed out"):
                self.capture(code, timeout=1)
            pid = pid_file.read_text()
            for _ in range(20):
                state = subprocess.run(["ps", "-o", "stat=", "-p", pid],
                                       capture_output=True, text=True).stdout.strip()
                if not state or state.startswith("Z"):
                    break
                time.sleep(0.05)
            else:
                self.fail("target child survived process-group cleanup")

    def test_invalid_timeouts_are_refused_before_process_creation(self):
        for value in (0, -1, True, float("nan"), float("inf"), "10"):
            with self.subTest(timeout=value):
                with self.assertRaisesRegex(ValueError, "timeout"):
                    self.capture("raise RuntimeError('must not run')", timeout=value)

    def test_boolean_result_length_is_not_evidence(self):
        response = {"protocol": "ral.target.v1", "report": {"verdict": "suspicious",
                    "findings": [], "summary": "Simulated test only"}, "calls": [{
                    "tool": "decompile_function", "args": {"name": "routine_b"},
                    "write": False, "is_error": False, "result_chars": True}]}
        with self.assertRaisesRegex(ValueError, "result_chars"):
            validate_response(response)
        valid = copy.deepcopy(response)
        valid["calls"][0]["result_chars"] = 1
        self.assertEqual(validate_response(valid), valid)


if __name__ == "__main__":
    unittest.main()
