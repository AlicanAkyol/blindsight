"""Opaque ephemeral input paths; not an isolation boundary for hostile adapters."""
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def opaque_binary(source):
    with tempfile.TemporaryDirectory(prefix="ral-input-") as directory:
        dest = Path(directory) / "sample.bin"
        shutil.copyfile(source, dest)
        yield dest
