"""First-use orchestration contracts; mocks are not real model acceptance data."""
import argparse
from contextlib import nullcontext
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import urllib.error
from blindsight import local_workflow as local, product
from blindsight.runner.local_agent import container_args

class LocalWorkflowTests(unittest.TestCase):
    def test_model_validation_and_canonical_tag(self):
        self.assertEqual(local.model_name("qwen3"),"qwen3:latest")
        for bad in ["--help","qwen3:cloud","model-cloud","model-cloud:latest","https://example/model","a b",""]:
            with self.subTest(model=bad),self.assertRaises(ValueError): local.model_name(bad)

    def test_remote_metadata_and_non_tool_models_are_refused(self):
        for show in [{"remote_host":"remote"},{"capabilities":["completion"]}]:
            def api(path,data=None,**kw):
                return {"models":[{"name":"qwen3:8b","size":2*1024*1024}]} if path=="tags" else show
            with patch.object(local,"api",side_effect=api),self.assertRaises(ValueError):
                local.prepare_model("qwen3:8b")

    def test_existing_local_model_needs_no_pull(self):
        def api(path,data=None,**kw):
            return {"tags":{"models":[{"name":"qwen3:8b","digest":"verified","size":2*1024*1024}]},
                    "show":{"capabilities":["tools"],"parameters":"test"},
                    "version":{"version":"test"}}[path]
        with patch.object(local.importlib.metadata,"version",return_value="test"),patch.object(local,"api",side_effect=api),patch.object(local.urllib.request,"urlopen") as request:
            result=local.prepare_model("qwen3:8b")
            self.assertEqual(result["digest"],"verified"); request.assert_not_called()

    def test_missing_model_pull_is_local_and_errors_are_not_successes(self):
        for failed in [False,True]:
            calls=[]
            def api(path,data=None,**kw):
                calls.append(path)
                if path=="tags":
                    return {"models":[] if calls.count("tags")==1 else [{"name":"test:1","size":2000000}]}
                return {"capabilities":["tools"]} if path=="show" else {"version":"test"}
            stream=io.BytesIO(json.dumps({"error":"download failed"} if failed else {"status":"success"}).encode()+b"\n")
            with patch.object(local,"api",side_effect=api),patch.object(local.urllib.request,"urlopen",return_value=stream) as request,patch.object(local.importlib.metadata,"version",return_value="test"):
                if failed:
                    with self.assertRaises(ValueError): local.prepare_model("test:1")
                else:
                    self.assertEqual(local.prepare_model("test:1")["name"],"test:1")
                self.assertEqual(request.call_args.args[0].full_url,"http://127.0.0.1:11434/api/pull")

    def test_missing_docker_is_actionable_before_any_download(self):
        with patch.object(local.shutil,"which",return_value=None),self.assertRaisesRegex(ValueError,"Docker is missing"):
            with local.public_docker(): pass

    def test_public_docker_uses_local_context_without_account_config(self):
        calls=[]
        def call(args,env,**kw):
            calls.append((args,env))
            return subprocess.CompletedProcess(args,0,"unix:///tmp/docker.sock\n" if args[0]=="context" else "test","")
        with patch.object(local.shutil,"which",return_value="/usr/bin/docker"),patch.object(local,"docker_call",side_effect=call),patch.dict(os.environ,{"DOCKER_CONTEXT":"my-local-context"},clear=True):
            with local.public_docker() as env:
                self.assertEqual(env["DOCKER_HOST"],"unix:///tmp/docker.sock")
                self.assertNotIn("DOCKER_CONTEXT",env)
                self.assertNotIn("auths",json.loads((Path(env["DOCKER_CONFIG"])/"config.json").read_text()))
                directory=Path(env["DOCKER_CONFIG"])
            self.assertFalse(directory.exists())

    def test_container_has_no_network_and_only_opaque_read_only_mount(self):
        args=container_args("/tmp/opaque/sample.bin","sha256:"+"a"*64,"b"*32)
        self.assertEqual(args[args.index("--network")+1],"none")
        self.assertIn("--read-only",args)
        self.assertIn("source=/tmp/opaque/sample.bin,target=/input/sample.bin,readonly",args[args.index("--mount")+1])
        self.assertNotIn("-p",args)
        with self.assertRaises(ValueError): container_args("x","latest","b"*32)

    def test_existing_ollama_server_is_not_stopped(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(local,"api",return_value={"version":"test"}),patch.object(local.subprocess,"Popen") as start,patch.object(local.os,"killpg") as stop:
            with local.ollama_service(Path(tmp)): pass
            start.assert_not_called(); stop.assert_not_called()

    def test_owned_ollama_server_is_loopback_cloud_disabled_and_cleaned(self):
        process=MagicMock(); process.poll.return_value=None; process.pid=123456
        with tempfile.TemporaryDirectory() as tmp,patch.object(local,"api",side_effect=[urllib.error.URLError("offline"),{"version":"test"}]),patch.object(local.shutil,"which",return_value="/bin/ollama"),patch.object(local.subprocess,"Popen",return_value=process) as start,patch.object(local.os,"killpg") as stop:
            with local.ollama_service(Path(tmp)): pass
            env=start.call_args.kwargs["env"]
            self.assertEqual(env["OLLAMA_HOST"],"127.0.0.1:11434")
            self.assertEqual(env["OLLAMA_NO_CLOUD"],"1")
            stop.assert_called_once_with(process.pid,signal.SIGTERM)

    def test_zero_yaml_preparation_does_not_read_local_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/".ral.yaml").write_text("broken: [yaml")
            state=root/"state"
            argv=["--state",str(state),"--config",str(root/".ral.yaml"),"local","--prepare-only"]
            env={"DOCKER_CONFIG":str(root),"DOCKER_HOST":"unix:///tmp/docker.sock"}
            with patch.object(local.importlib.util,"find_spec",return_value=True),patch.object(local,"public_docker",return_value=nullcontext(env)),patch.object(local,"ollama_service",return_value=nullcontext()),patch.object(local,"prepare_model",return_value={"digest":"test"}),patch.object(local,"prepare_backend",return_value={"image_id":"sha256:"+"a"*64}),patch("blindsight.runner.local_agent.probe",new_callable=AsyncMock,return_value={"decompile_main":True}),patch.object(local,"docker_call",return_value=subprocess.CompletedProcess([],0,"","")):
                self.assertEqual(product.main(argv),0)
            self.assertEqual((root/".ral.yaml").read_text(),"broken: [yaml")
            self.assertTrue((state/"setup/local-runtime.json").is_file())

    def test_invalid_timeout_fails_before_any_service(self):
        with patch.object(local,"public_docker") as docker:
            self.assertEqual(product.main(["local","--target-timeout","nan"]),2)
            docker.assert_not_called()

    def test_missing_or_incompatible_baseline_fails_before_download(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(local,"public_docker") as docker:
            args=["--state",tmp,"local","--baseline","saved"]
            self.assertEqual(product.main(args),2)
            root=Path(tmp)/"baseline"; root.mkdir()
            (root/"runs.jsonl").write_text("")
            for meta in [{"input_paths":"opaque-v1","suite":"quick"},
                         {"input_paths":"container-fixed-v1","suite":"ci"}]:
                (root/"meta.json").write_text(json.dumps(meta))
                self.assertEqual(product.main(args),2)
            docker.assert_not_called()

    def test_invalid_thresholds_fail_before_any_service(self):
        with patch.object(local,"public_docker") as docker:
            for options in [["--max-recall-drop","nan"],["--max-coverage-drop","101"],["--max-unsupported-increase","-1"]]:
                self.assertEqual(product.main(["local",*options]),2)
            docker.assert_not_called()

    def test_prepare_then_check_reuses_existing_evaluator_and_records_identity(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{},clear=False):
            root=Path(tmp)
            env={"DOCKER_CONFIG":tmp,"DOCKER_HOST":"unix:///tmp/docker.sock"}
            runtime={"image_id":"sha256:"+"a"*64,"recipe_sha256":"test"}
            with patch.object(local.importlib.util,"find_spec",return_value=True),patch.object(local,"public_docker",return_value=nullcontext(env)),patch.object(local,"ollama_service",return_value=nullcontext()),patch.object(local,"prepare_model",return_value={"digest":"model-test"}),patch.object(local,"prepare_backend",return_value=runtime),patch("blindsight.runner.local_agent.probe",new_callable=AsyncMock,return_value={"decompile_main":True}),patch.object(local,"docker_call",return_value=subprocess.CompletedProcess([],0,"","")),patch.object(product,"check",return_value=1) as check:
                self.assertEqual(product.main(["--state",tmp,"local"]),1)
                args,cfg,state=check.call_args.args
                target=cfg["targets"]["local-reference-agent"]
                self.assertEqual(target["input_paths"],"container-fixed-v1")
                self.assertEqual(target["model_info"]["digest"],"model-test")
                self.assertEqual(target["command"][-1],"blindsight.runner.local_agent")

if __name__=="__main__": unittest.main()
