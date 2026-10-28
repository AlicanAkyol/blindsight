"""Address identity is verified from delivered structured output, not guessed."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from blindsight import diagnostics, reporting
from blindsight.runner.measurement import IDENTITY_PROTOCOL, body_hits, delivery_fields

def call():
    text = json.dumps({"function": {"name":"routine_b", "address":"00101100"},
                       "code":"void routine_b(void) {}", "truncated":False})
    return {"tool":"decompile_function_by_address", "args":{"address":"0x101100"},
            "write":False, "is_error":False, "result_chars":len(text), **delivery_fields(text,text)}

class AddressCoverageTests(unittest.TestCase):
    def test_address_matches_returned_identity_only_under_new_protocol(self):
        record = {"calls":[call()]}
        self.assertEqual(body_hits(record,"routine_b"), [])
        self.assertEqual(body_hits(record,"routine_b",identity_protocol=IDENTITY_PROTOCOL), [1])

    def test_wrong_missing_or_partial_identity_is_not_coverage(self):
        variants = []
        for patch in [{"args":{"address":"00109900"}}, {"is_error":True},
                      {"truncated":True}, {"delivery_recorded":False},
                      {"delivered_text":"routine_b"}, {"delivered_text":"[]"}]:
            c=call(); c.update(patch); variants.append(c)
        for patch in [{"function":{"name":"other","address":"00101100"}},
                      {"function":{"name":"routine_b","address":"00109900"}},
                      {"code":""}, {"truncated":True}]:
            c=call(); obj=json.loads(c["delivered_text"]); obj.update(patch)
            text=json.dumps(obj); c.update(delivery_fields(text,text)); variants.append(c)
        for c in variants:
            with self.subTest(call=c):
                self.assertEqual(body_hits({"calls":[c]},"routine_b",identity_protocol=IDENTITY_PROTOCOL), [])

    def test_named_calls_keep_historical_semantics(self):
        c=call(); c["args"]={"name":"routine_b"}
        self.assertEqual(body_hits({"calls":[c]},"routine_b"), [1])

    def make_run(self, root, name, calls, protocol=IDENTITY_PROTOCOL):
        path=root/name; path.mkdir()
        meta={"run_id":name,"repeats":1,"seeds":[0],"coverage_identity_protocol":protocol,
              "scenarios_resolved":[{"id":"t.case","sample":"f","variant":"v",
                  "expected_findings":["persistence"],"capability_functions":{"persistence":"routine_b"}}]}
        (path/"meta.json").write_text(json.dumps(meta))
        (path/"runs.jsonl").write_text(json.dumps({"scenario":"t.case","seed":0,"calls":calls,
               "report":{"verdict":"malicious","findings":["persistence"]}})+"\n")
        return path

    def test_scorecard_and_release_gate_use_resolved_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            base=self.make_run(root,"b",[call()]); cand=self.make_run(root,"c",[])
            self.assertEqual(reporting.scorecard(base)["rows"][0]["persistence_coverage"],1)
            report=diagnostics.release_report(base,cand)
            self.assertEqual(report["exit_code"],1)
            self.assertEqual(report["comparison"]["rows"][0]["cov_delta"],-1)
            self.assertEqual(len(report["coverage_losses"]),1)

    def test_identity_protocol_change_requires_new_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            base=self.make_run(root,"b",[call()],"argument-name-v1")
            cand=self.make_run(root,"c",[call()])
            self.assertEqual(diagnostics.release_report(base,cand)["exit_code"],2)

if __name__ == "__main__":
    unittest.main()
