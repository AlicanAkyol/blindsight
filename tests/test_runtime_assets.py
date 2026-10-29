"""Pinned asset handling must reject corruption and archive path escapes."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from blindsight import local_workflow

spec=importlib.util.spec_from_file_location("runtime_assets",local_workflow.ASSETS/"docker/local-assets.py")
assets=importlib.util.module_from_spec(spec); spec.loader.exec_module(assets)

class RuntimeAssetTests(unittest.TestCase):
    def test_verified_download_is_cached_without_network(self):
        data=b"verified runtime bytes"; digest=hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmp,patch.dict(assets.ASSETS,{"test":("https://example.invalid/asset",digest)}):
            target=Path(tmp)/"asset"
            with patch.object(assets.urllib.request,"urlopen",return_value=io.BytesIO(data)):
                assets.download("test",target)
            with patch.object(assets.urllib.request,"urlopen") as request:
                assets.download("test",target); request.assert_not_called()
            self.assertEqual(target.read_bytes(),data)

    def test_corrupt_download_is_not_installed(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(assets.ASSETS,{"test":("https://example.invalid/asset","0"*64)}),patch.object(assets.urllib.request,"urlopen",return_value=io.BytesIO(b"wrong")):
            target=Path(tmp)/"asset"
            with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"): assets.download("test",target)
            self.assertFalse(target.exists()); self.assertFalse(target.with_suffix(".part").exists())

    def test_archive_path_cannot_escape(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w") as z: z.writestr("../escape","data")
        stream.seek(0)
        with tempfile.TemporaryDirectory() as tmp,zipfile.ZipFile(stream) as z,self.assertRaises(ValueError):
            assets.extract_zip(z,Path(tmp))

if __name__=="__main__": unittest.main()
