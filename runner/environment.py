"""Resolve installed tools without machine-specific absolute paths."""
import os
import shutil
import subprocess
import sys
from pathlib import Path


def discover():
    roots = [Path(os.environ["RAL_TOOLS"])] if os.environ.get("RAL_TOOLS") else [
        Path.cwd() / "tools", Path.home() / "dev/tools", Path(sys.prefix) / "share/ral/tools",
        Path("/opt/re-agent-lab/tools"), Path("/opt"),
    ]
    def locate(pattern):
        return next((p for root in roots for p in sorted(root.glob(pattern)) if p.exists()), None)

    ghidra = os.environ.get("RAL_GHIDRA") or locate("ghidra_12.1.4_PUBLIC")
    jar = os.environ.get("RAL_GHIDRAMCP_JAR") or locate("GhidraMCP*/ext/GhidraMCP/lib/GhidraMCP.jar")
    java = os.environ.get("RAL_JAVA_HOME") or os.environ.get("JAVA_HOME")
    if not java and sys.platform == "darwin":
        try:
            p = subprocess.run(["/usr/libexec/java_home", "-v", "21"], capture_output=True,
                               text=True, timeout=5)
            if p.returncode == 0:
                java = p.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not java and shutil.which("java"):
        java = str(Path(shutil.which("java")).resolve().parent.parent)
    return {"ghidra": str(ghidra) if ghidra else None,
            "ghidramcp_jar": str(jar) if jar else None, "java_home": java}
