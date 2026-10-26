"""Methodology regressions: no model, sandbox or network needed."""
import asyncio
import hashlib
import importlib.util
import json
import sys
import blindsight
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from blindsight import diagnostics, reporting
from blindsight.runner.measurement import body_hits, delivery_fields, label_scope
from blindsight.runner.inputs import opaque_binary

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(blindsight.__file__).resolve().parent / 'runner'))
from ghidra_session import RecordingSession
import llm_agent
from external import run_one

spec = importlib.util.spec_from_file_location('release_tests', REPO/'tests/test_release.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReleaseTests()
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    def change_scope(self, directory, scope):
        p = directory/'meta.json'
        m = json.loads(p.read_text())
        m['scenarios_resolved'][0]['label_scope'] = scope
        p.write_text(json.dumps(m))

    def test_partial_extras_are_not_false_positives(self):
        base = self.fixture.run_dir('b', ['persistence'])
        cand = self.fixture.run_dir('c', ['persistence', 'credential_access'])
        for d in (base, cand):
            self.change_scope(d, 'partial')
        report = diagnostics.release_report(base, cand)
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['new_unsupported_findings'], [])
        self.assertEqual(report['unreviewed_findings'][0]['findings'], ['credential_access'])
        card = reporting.scorecard(cand)
        self.assertEqual(card['rows'][0]['unsupported_findings'], 0)
        self.assertEqual(card['rows'][0]['unreviewed_findings'], 1)

    def test_scope_change_is_incompatible(self):
        base = self.fixture.run_dir('b', ['persistence'])
        cand = self.fixture.run_dir('c', ['persistence'])
        self.change_scope(cand, 'partial')
        self.assertEqual(diagnostics.release_report(base, cand)['status'], 'INCOMPATIBLE')
        with self.assertRaises(ValueError):
            label_scope({'label_scope': 'typo'})

    def test_truncated_output_fails_coverage_gate(self):
        base = self.fixture.run_dir('b', ['persistence'])
        cand = self.fixture.run_dir('c', ['persistence'])
        for d, raw, delivered in [(base, 'whole body', 'whole body'),
                                   (cand, 'header plus persistence body', 'header')]:
            p = d/'runs.jsonl'
            r = json.loads(p.read_text())
            r['calls'][0].update(delivery_fields(raw, delivered))
            p.write_text(json.dumps(r)+'\n')
        report = diagnostics.release_report(base, cand)
        self.assertEqual(report['exit_code'], 1)
        self.assertEqual(len(report['coverage_losses']), 1)
        self.assertEqual(reporting.scorecard(cand)['rows'][0]['persistence_coverage'], 0)

    def test_unrecorded_delivery_is_not_coverage(self):
        r = {'calls':[{'tool':'decompile_function', 'args':{'name':'f'},
                       'is_error':False, 'result_chars':999, 'delivery_recorded':False}]}
        self.assertEqual(body_hits(r, 'f'), [])

    def test_changed_protocol_requires_new_baseline(self):
        base = self.fixture.run_dir('b', ['persistence'])
        cand = self.fixture.run_dir('c', ['persistence'])
        p = cand/'meta.json'; m = json.loads(p.read_text())
        m['measurement_protocol'] = 'delivered-output-v2'
        p.write_text(json.dumps(m))
        self.assertEqual(diagnostics.release_report(base, cand)['status'], 'INCOMPATIBLE')

    def test_opaque_copy_preserves_bytes_and_is_removed(self):
        src = self.fixture.root/'v9_symbol_neutral.elf'
        src.write_bytes(b'\x7fELF payload routine_b')
        with opaque_binary(src) as dest:
            self.assertNotIn('v9_symbol_neutral', str(dest))
            self.assertEqual(dest.name, 'sample.bin')
            self.assertEqual(dest.read_bytes(), src.read_bytes())
        self.assertFalse(dest.exists())
        self.assertTrue(src.exists())

    def test_external_target_only_receives_opaque_path(self):
        src = self.fixture.root/'v9_symbol_neutral.elf'; src.write_bytes(b'\x7fELF')
        code = ('import json,sys; from pathlib import Path; r=json.load(sys.stdin); '
                'assert Path(r["binary"]).name=="sample.bin"; '
                'assert "v9_symbol_neutral" not in r["binary"]; '
                'assert Path(r["binary"]).read_bytes()==b"\\x7fELF"; '
                'print(json.dumps({"protocol":"ral.target.v1","report":'
                '{"verdict":"suspicious","findings":[],"summary":"ok"},"calls":[]}))')
        r = run_one({'command':[sys.executable,'-c',code]},
                    {'id':'t','task':'triage_readonly'}, src, 0)
        self.assertNotIn('error', r)

    def test_forced_prefix_records_only_delivered_text(self):
        raw = 'x'*9000 + 'PERSISTENCE_AT_END'
        class Backend:
            async def call_tool(self, name, args):
                return SimpleNamespace(content=[SimpleNamespace(text=raw)], isError=False)
        session = RecordingSession(Backend())
        messages = asyncio.run(llm_agent.forced_prefix(session, only=['routine_b']))
        call = session.calls[0]
        self.assertTrue(call['truncated'])
        self.assertNotIn('PERSISTENCE_AT_END', call['delivered_text'])
        self.assertEqual(call['delivered_text'], messages[-1]['content'])
        self.assertEqual(call['delivered_sha256'], hashlib.sha256(messages[-1]['content'].encode()).hexdigest())
        self.assertEqual(body_hits({'calls':session.calls}, 'routine_b'), [])

    def test_natural_loop_records_truncation(self):
        class Backend:
            async def list_tools(self):
                return SimpleNamespace(tools=[])

            async def call_tool(self, name, args):
                return SimpleNamespace(content=[SimpleNamespace(text='x'*9000)], isError=False)
        session = RecordingSession(Backend())
        replies = iter([{'message':{'role':'assistant','content':'','tool_calls':[
            {'function':{'name':'decompile_function','arguments':{'name':'routine_b'}}}]}},
            {'message':{'role':'assistant','content':json.dumps({'verdict':'suspicious',
                'findings':['persistence'],'summary':'test'})}}])
        with patch.object(llm_agent, '_post', side_effect=lambda *args: next(replies)):
            report = asyncio.run(llm_agent.make_agent('test')(session, {'prompt':'test'}))
        self.assertEqual(report['findings'], ['persistence'])
        self.assertTrue(session.calls[0]['truncated'])
        self.assertEqual(session.calls[0]['delivered_text'], session.extra['messages'][3]['content'])

    def test_natural_step_limit_marks_last_batch_undelivered(self):
        class Backend:
            async def list_tools(self):
                return SimpleNamespace(tools=[])

            async def call_tool(self, name, args):
                return SimpleNamespace(content=[SimpleNamespace(text='whole body')], isError=False)
        session = RecordingSession(Backend())
        reply = {'message':{'role':'assistant','content':'','tool_calls':[
            {'function':{'name':'decompile_function','arguments':{'name':'routine_b'}}}]}}
        with patch.object(llm_agent, '_post', return_value=reply), patch.object(llm_agent, 'MAX_STEPS', 1):
            report = asyncio.run(llm_agent.make_agent('test')(session, {'prompt':'test'}))
        self.assertIsNone(report)
        self.assertFalse(session.calls[0]['delivery_recorded'])
        self.assertEqual(body_hits({'calls':session.calls}, 'routine_b'), [])


if __name__ == '__main__':
    unittest.main()
