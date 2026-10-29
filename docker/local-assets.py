"""Official, hash-checked runtime assets; used only while building the image."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile

ASSETS = {
    "ghidra": ("https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip",
               "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"),
    "mcp": ("https://github.com/LaurieWired/GhidraMCP/releases/download/2.0/GhidraMCP-release-2-0.zip",
            "ebf904fd6782e429e95a60a24fe0724b20c0acb2dedb304135a5281f6b5f2e72"),
    "java": ("https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz",
             "d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c"),
}

def download(name, dest):
    url, expected = ASSETS[name]
    if dest.is_file() and hashlib.sha256(dest.read_bytes()).hexdigest()==expected:
        print(f"Using verified cached {name} asset",flush=True)
        return
    digest = hashlib.sha256()
    print(f"Downloading pinned {name} asset", flush=True)
    partial=dest.with_suffix(".part")
    with urllib.request.urlopen(url, timeout=180) as response, partial.open("wb") as out:
        while block := response.read(1024*1024):
            digest.update(block); out.write(block)
    if digest.hexdigest() != expected:
        partial.unlink()
        raise ValueError(f"{name} SHA-256 mismatch; refusing installation")
    partial.replace(dest)

def extract_zip(z, root):
    root = root.resolve()
    for item in z.infolist():
        if not (root/item.filename).resolve().is_relative_to(root):
            raise ValueError("archive path escapes destination")
        path = Path(z.extract(item, root))
        mode = (item.external_attr >> 16) & 0o777
        if mode:
            path.chmod(mode)

def main():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        cache=Path("/var/cache/blindsight"); cache.mkdir(parents=True,exist_ok=True)
        archives={name:cache/spec[1] for name,spec in ASSETS.items()}
        for name in ASSETS:
            download(name,archives[name])
        with zipfile.ZipFile(archives["ghidra"]) as z:
            extract_zip(z,Path("/opt"))
        # The official MCP asset contains an extension zip and a Python wheel.
        with zipfile.ZipFile(archives["mcp"]) as outer:
            extension=next(n for n in outer.namelist() if n.endswith("_GhidraMCP.zip"))
            with zipfile.ZipFile(io.BytesIO(outer.read(extension))) as inner:
                Path("/opt/GhidraMCP.jar").write_bytes(inner.read("GhidraMCP/lib/GhidraMCP.jar"))
            wheel=next(n for n in outer.namelist() if n.endswith("-py3-none-any.whl"))
            Path("/opt/wheels").mkdir()
            Path("/opt/wheels",Path(wheel).name).write_bytes(outer.read(wheel))
        jre=root/"jre"; jre.mkdir()
        with tarfile.open(archives["java"]) as archive:
            archive.extractall(jre,filter="data")
        shutil.move(str(next(jre.iterdir())),"/opt/java")
    for name in ["decompile","sleigh"]:
        Path("/opt/ghidra_12.1.4_PUBLIC/Ghidra/Features/Decompiler/os/linux_x86_64",name).chmod(0o755)

if __name__=="__main__":
    main()
