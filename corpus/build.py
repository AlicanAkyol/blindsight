#!/usr/bin/env python3
"""Build every corpus variant inside the pinned Docker image.

Output: build/<variant>/agent_fixture and build/manifest.json
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import variant_src, variants  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "blindsight/corpus:latest"
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

    manifest = {"image_id": image_id, "gcc": gcc_version, "cflags": CFLAGS, "variants": {}}

    for v in variants():
        src = variant_src(v)              # e.g. agent_fixture.c
        stem = Path(src).stem             # e.g. agent_fixture -> binary name
        out = f"build/{v}/{stem}"
        (ROOT / "build" / v).mkdir(parents=True, exist_ok=True)
        docker("gcc", *CFLAGS, "-I", f"corpus/variants/{v}", "-o", out, f"corpus/src/{src}")
        digest = hashlib.sha256((ROOT / out).read_bytes()).hexdigest()
        manifest["variants"][v] = {"path": out, "src": src, "sha256": digest}
        print(f"{v:18} {digest[:16]}")

    (ROOT / "build/manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
