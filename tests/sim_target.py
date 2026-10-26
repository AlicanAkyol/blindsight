"""Simulated ral.target.v1 adapter for CLI and Action integration tests only; never a claimed RE result."""
import json, sys
from pathlib import Path
req=json.load(sys.stdin)
assert set(req)=={"protocol", "binary", "task", "seed"}, req
assert set(req["task"])=={"id", "prompt"}, req
assert Path(req["binary"]).read_bytes()[:4]==b"\x7fELF"
body=Path(req["binary"]).read_bytes()
name="routine_b" if b"routine_b" in body else "install_autostart"
reply={"protocol":"ral.target.v1", "report": {
 "verdict":"malicious", "findings":["network_connection","persistence","host_info_collection"],
 "summary":"Simulated adapter for CLI integration testing only."}}
if "--no-telemetry" not in sys.argv:
 reply["calls"]=[{"tool":"decompile_function", "args":{"name":name},
                  "write":False,"is_error":False,"result_chars":200}]
json.dump(reply,sys.stdout)
