"""Start GhidraMCP headless on one binary and record every MCP tool call.

The recording is the ground truth for action checks: the evaluator never
trusts an agent's own account of what it did.
"""
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOOLS = Path(os.environ.get("RAL_TOOLS", "/opt/re-agent-lab/tools"))
GHIDRA_DIR = TOOLS / "ghidra_12.1.4_PUBLIC"
EXTENSION_JAR = TOOLS / "GhidraMCP-2.0/ext/GhidraMCP/lib/GhidraMCP.jar"
JAVA_HOME = os.environ.get("RAL_JAVA_HOME", "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home")

# GhidraMCP 2.0 tools that change the program database.
WRITE_TOOLS = {
    "rename_function", "rename_function_by_address", "rename_data", "rename_variable",
    "set_function_prototype", "set_local_variable_type",
    "set_decompiler_comment", "set_disassembly_comment",
}


class RecordingSession:
    """Thin wrapper over ClientSession that logs each call_tool."""

    def __init__(self, session: ClientSession):
        self._s = session
        self.calls = []
        self.extra = {}  # agent-specific trace (e.g. LLM transcript)

    async def list_tools(self):
        return (await self._s.list_tools()).tools

    async def call(self, name: str, args: dict | None = None, forced: bool = False) -> str:
        """forced=True marks calls made by the harness, not the agent."""
        args = args or {}
        started = time.time()
        res = await self._s.call_tool(name, args)
        text = "".join(getattr(c, "text", "") for c in res.content)
        self.calls.append({
            "tool": name, "args": args, "is_error": bool(res.isError),
            "result_chars": len(text), "write": name in WRITE_TOOLS,
            "forced": forced, "t": round(time.time() - started, 3),
        })
        return text

    async def call_json(self, name: str, args: dict | None = None):
        text = await self.call(name, args)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_raw": text}


@asynccontextmanager
async def ghidra(binary: Path, ready_timeout: int = 300):
    env = dict(os.environ, GHIDRA_INSTALL_DIR=str(GHIDRA_DIR), JAVA_HOME=JAVA_HOME,
               GHIDRA_MCP_EXTENSION_JAR=str(EXTENSION_JAR))
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ghidra_mcp", "--headless", "--binary", str(binary),
              "--ready-timeout", str(ready_timeout), "--discard"],
        env=env)
    with open(os.devnull, "w") as devnull:
        async with stdio_client(params, errlog=devnull) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                yield RecordingSession(s)
