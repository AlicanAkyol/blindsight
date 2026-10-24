"""Dev helper: print what an MCP client sees for a binary.

usage: uv run python runner/peek.py build/v1_direct/agent_fixture '[["list_strings", {"filter": "AI"}]]'
"""
import asyncio
import json
import sys
from pathlib import Path

from ghidra_session import ghidra


async def main(binary, calls):
    async with ghidra(Path(binary)) as s:
        for name, args in calls:
            print(f"### {name} {args}\n{(await s.call(name, args))[:1500]}\n")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], json.loads(sys.argv[2])))
