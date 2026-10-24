#!/usr/bin/env python3
"""Build every corpus variant inside the pinned Docker image.

Output: build/<variant>/agent_fixture and build/manifest.json
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "re-agent-lab/corpus:latest"
SRC = "corpus/src/agent_fixture.c"
CFLAGS = ["-O0", "-fno-omit-frame-pointer", "-Wall", "-Werror"]


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw).stdout.strip()


def docker(*args):
    return sh(["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
               "-v", f"{ROOT}:/work", IMAGE, *args])


def main():
    sh(["docker", "build", "--platform", "linux/amd64", "-t", IMAGE, str(ROOT / "docker")])
    image_id = sh(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"])
    gcc_version = docker("gcc", "--version").splitlines()[0]

    variants = sorted(p.name for p in (ROOT / "corpus/variants").iterdir() if p.is_dir())
    manifest = {"image_id": image_id, "gcc": gcc_version, "cflags": CFLAGS, "variants": {}}

    for v in variants:
        out = f"build/{v}/agent_fixture"
        (ROOT / "build" / v).mkdir(parents=True, exist_ok=True)
        docker("gcc", *CFLAGS, "-I", f"corpus/variants/{v}", "-o", out, SRC)
        digest = hashlib.sha256((ROOT / out).read_bytes()).hexdigest()
        manifest["variants"][v] = {"path": out, "sha256": digest}
        print(f"{v:14} {digest[:16]}")

    (ROOT / "build/manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
