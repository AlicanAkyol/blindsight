"""Adapter helper and MCP context accounting; simulations, not model results."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from blindsight.adapter import serve
from blindsight.runner.measurement import complete_output

spec = importlib.util.spec_from_file_location("mcp_use_example", Path(__file__).resolve().parent.parent / "examples/mcp_use_agent.py")
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)
REPORT = {"verdict": "suspicious", "findings": [], "summary": "Simulated test only"}


class AdapterTests(unittest.TestCase):
    def invoke(self, callback, request=None, log=None):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sample.bin"; binary.write_bytes(b"fixture")
            request = request if request is not None else {"protocol": "ral.target.v1", "binary": str(binary), "seed": 0,
                                                          "task": {"prompt": "frozen"}}
            output, errors = io.StringIO(), io.StringIO()
            env = {"RAL_ADAPTER_LOG": str(log) if log else ""}
            with patch.dict(os.environ, env), patch.object(sys, "stdin", io.StringIO(json.dumps(request))), \
                 patch.object(sys, "stdout", output), patch.object(sys, "stderr", errors):
                serve(callback)
            return json.loads(output.getvalue()), errors.getvalue()

    def test_library_prints_do_not_corrupt_response(self):
        def analyse(binary, prompt, seed):
            self.assertEqual((prompt, seed), ("frozen", 0))
            print("library diagnostic")
            return REPORT, []
        response, errors = self.invoke(analyse)
        self.assertEqual(response["report"], REPORT)
        self.assertEqual(response["calls"], [])
        self.assertIn("library diagnostic", errors)

    def test_async_callback_and_unavailable_calls(self):
        async def analyse(*args):
            return REPORT, None
        response, _ = self.invoke(analyse)
        self.assertNotIn("calls", response)  # Missing telemetry is not invented as zero calls.

    def test_bad_protocol_never_calls_agent(self):
        def analyse(*args):
            self.fail("must reject before invoking agent")
        with self.assertRaises(SystemExit):
            self.invoke(analyse, request={"protocol": "wrong"})

    def test_exception_has_private_opt_in_diagnostics(self):
        def analyse(*args):
            raise RuntimeError("debugging detail")
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "adapter.log"
            with self.assertRaises(SystemExit):
                self.invoke(analyse, log=log)
            self.assertIn("RuntimeError: debugging detail", log.read_text())
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)

    def test_invalid_report_is_not_repaired(self):
        with self.assertRaises(SystemExit):
            self.invoke(lambda *args: ({**REPORT, "verdict": "safe"}, []))

    def test_nonserializable_extra_does_not_write_partial_json(self):
        with self.assertRaises(SystemExit):
            self.invoke(lambda *args: ({**REPORT, "extra": object()}, []))


class ContextTests(unittest.TestCase):
    def message(self, text, ident="call-1", name="decompile_function"):
        return SimpleNamespace(type="tool", content=text, tool_call_id=ident, name=name)

    def test_output_is_not_delivered_until_successful_model_response(self):
        recorder = example.DeliveryRecorder()
        recorder.add("decompile_function", {"name": "routine_b"}, "body")
        self.assertFalse(complete_output(recorder.calls[0]))
        recorder.start([[self.message("body")]], "model-1")
        self.assertFalse(complete_output(recorder.calls[0]))
        recorder.end("model-1")
        self.assertTrue(complete_output(recorder.calls[0]))
        self.assertEqual(recorder.calls[0]["delivered_text"], "body")

    def test_failed_request_and_final_unused_batch_do_not_count(self):
        recorder = example.DeliveryRecorder(); recorder.add("decompile_function", {}, "body")
        recorder.start([[self.message("body")]], "model-1"); recorder.fail("model-1")
        recorder.end("model-1")
        self.assertFalse(complete_output(recorder.calls[0]))

    def test_changed_or_summary_content_is_not_full_delivery(self):
        recorder = example.DeliveryRecorder(); recorder.add("decompile_function", {}, "long body")
        recorder.start([[self.message("long")]], "model-1"); recorder.end("model-1")
        self.assertFalse(complete_output(recorder.calls[0]))

    def test_duplicate_outputs_and_repeated_history_match_once_per_call(self):
        recorder = example.DeliveryRecorder()
        recorder.add("decompile_function", {"name": "a"}, "same")
        recorder.add("decompile_function", {"name": "b"}, "same")
        messages = [[self.message("same", "a"), self.message("same", "b")]]
        recorder.start(messages, "model-1"); recorder.end("model-1")
        recorder.start(messages, "model-2"); recorder.end("model-2")
        self.assertEqual(recorder.message_calls, {"a": 0, "b": 1})
        self.assertTrue(all(complete_output(c) for c in recorder.calls))

    def test_complete_delivery_of_backend_clipped_body_is_not_full_coverage(self):
        recorder = example.DeliveryRecorder()
        text = json.dumps({"code": "partial body", "truncated": True})
        recorder.add("decompile_function", {"name": "routine_b"}, text)
        recorder.start([[self.message(text)]], "model-1"); recorder.end("model-1")
        self.assertEqual(recorder.calls[0]["delivered_chars"], len(text))
        self.assertTrue(recorder.calls[0]["backend_truncated"])
        self.assertFalse(complete_output(recorder.calls[0]))

    def test_delivered_error_is_not_counted_as_body_coverage(self):
        recorder = example.DeliveryRecorder()
        recorder.add("decompile_function", {}, "error response", is_error=True)
        recorder.start([[self.message("error response")]], "model-1")
        recorder.end("model-1")
        self.assertGreater(recorder.calls[0]["delivered_chars"], 0)
        self.assertFalse(complete_output(recorder.calls[0]))



if __name__ == "__main__":
    unittest.main()
