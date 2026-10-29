"""Give the unprivileged backend a writable temporary home, then start MCP."""
import os
from pathlib import Path
import sys

Path(os.environ["HOME"]).mkdir(parents=True,exist_ok=True)
os.execv(sys.executable,[sys.executable,"-m","ghidra_mcp",*sys.argv[1:]])
