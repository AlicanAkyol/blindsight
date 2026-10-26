"""Start GhidraMCP headless on one binary and record every MCP tool call.

The recording is the ground truth for action checks: the evaluator never
trusts an agent's own account of what it did.
"""
from __future__ import annotations
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from environment import discover
from measurement import delivery_fields

_paths = discover()
GHIDRA_DIR = Path(_paths["ghidra"] or "/nonexistent/ral/ghidra")
EXTENSION_JAR = Path(_paths["ghidramcp_jar"] or "/nonexistent/ral/GhidraMCP.jar")
JAVA_HOME = _paths["java_home"] or "/nonexistent/ral/java"

# GhidraMCP 2.0 tools that change the program database.
WRITE_TOOLS = {
    "rename_function", "rename_function_by_address", "rename_data", "rename_variable",
    "set_function_prototype", "set_local_variable_type",
    "set_decompiler_comment", "set_disassembly_comment",
}


class RecordingSession:
    """Thin wrapper over ClientSession that logs each call_tool."""

    def __init__(self, session: ClientSession, read_only: bool = False):
        self._s = session
        self.calls = []
        self.extra = {}  # agent-specific trace (e.g. LLM transcript)
        self.read_only = read_only  # server-side defense: refuse write tools

    def record_delivery(self, raw, delivered):
        self.calls[-1].update(delivery_fields(raw, delivered))

    async def list_tools(self):
        tools = (await self._s.list_tools()).tools
        if self.read_only:
            tools = [t for t in tools if t.name not in WRITE_TOOLS]
        return tools

    async def call(self, name: str, args: dict | None = None, forced: bool = False) -> str:
        """forced=True marks calls made by the harness, not the agent."""
        args = args or {}
        started = time.time()
        # read-only is enforced here, deterministically, not via the prompt:
        # the write never reaches the backend, and the refusal is recorded.
        if self.read_only and name in WRITE_TOOLS:
            self.calls.append({
                "tool": name, "args": args, "is_error": True, "refused_read_only": True,
                "result_chars": 0, "write": True, "forced": forced, "t": 0.0,
            })
            return "error: this tool is disabled in read-only mode"
        res = await self._s.call_tool(name, args)
        text = "".join(getattr(c, "text", "") for c in res.content)
        self.calls.append({
            "tool": name, "args": args, "is_error": bool(res.isError),
            "result_chars": len(text), "write": name in WRITE_TOOLS,
            "delivery_recorded": False,
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
async def ghidra(binary: Path, ready_timeout: int = 300, read_only: bool = False):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
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
                yield RecordingSession(s, read_only=read_only)
