"""examples/openai_compatible_agent.py against a scripted model and a fake MCP server.

No model or Ghidra needed. Checks that every tool call is reported truthfully,
that read-only mode refuses writes outside the model, and that a missing final
answer is not turned into a report.
Run: python tests/test_example_agent.py
"""
import asyncio
import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location(
    "example_agent", Path(__file__).resolve().parent.parent / "examples" / "openai_compatible_agent.py")
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)


class FakeMCP:
    def __init__(self):
        self.received = []

    async def list_tools(self):
        return SimpleNamespace(tools=[SimpleNamespace(name=n, description="", inputSchema={"type": "object"})
                                      for n in ("decompile_function", "rename_function")])

    async def call_tool(self, name, args):
        self.received.append(name)
        return SimpleNamespace(content=[SimpleNamespace(text="void routine_b(void) { }")], isError=False)


def tool_call(name, args):
    return {"role": "assistant", "content": "", "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


class ExampleAgentTests(unittest.TestCase):
    def run_agent(self, replies, read_only=False):
        replies = list(replies)
        example.chat = lambda messages, tools, seed: replies.pop(0)
        example.READ_ONLY = read_only
        mcp, calls = FakeMCP(), []
        report = asyncio.run(example.agent(mcp, "prompt", 0, calls))
        return report, calls, mcp

    def test_calls_are_recorded_as_delivered(self):
        final = {"role": "assistant", "content": '<think>{"verdict": "x"}</think>'
                 '{"verdict": "malicious", "findings": ["persistence"], "summary": "s"}'}
        report, calls, _ = self.run_agent([tool_call("decompile_function", {"name": "routine_b"}), final])
        self.assertEqual(report["findings"], ["persistence"])
        self.assertEqual(calls, [{"tool": "decompile_function", "args": {"name": "routine_b"},
                                  "write": False, "is_error": False, "result_chars": 24}])

    def test_read_only_refuses_write_before_it_reaches_ghidra(self):
        final = {"role": "assistant", "content": '{"verdict": "benign", "findings": []}'}
        _, calls, mcp = self.run_agent([tool_call("rename_function", {"old_name": "a", "new_name": "b"}), final],
                                       read_only=True)
        self.assertEqual(mcp.received, [])
        self.assertTrue(calls[0]["write"] and calls[0]["is_error"] and calls[0]["refused_read_only"])

    def test_no_final_json_is_not_a_report(self):
        report, _, _ = self.run_agent([{"role": "assistant", "content": "I could not decide."}])
        self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main()
