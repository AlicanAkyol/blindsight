"""Zero-YAML reference-agent workflow. Docker + local Ollama are prerequisites."""
import asyncio
from contextlib import contextmanager
import hashlib
import importlib.util
import importlib.metadata
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ASSETS=Path(__file__).resolve().parent
RECIPES=["Dockerfile.local","local-assets.py","local-requirements.txt","local-entry.py"]
URL="http://127.0.0.1:11434"

def open_local(request,timeout):
    # A local-model request must not be routed through HTTP_PROXY.
    return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=timeout)

def api(path,data=None,timeout=10):
    req=urllib.request.Request(URL+"/api/"+path,None if data is None else json.dumps(data).encode(),
                               {"Content-Type":"application/json"})
    with open_local(req,timeout) as response:
        return json.load(response)

def model_name(value):
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*",value) or "://" in value
            or value.lower().endswith(("-cloud",":cloud"))
            or value.rsplit("/",1)[-1].split(":",1)[0].lower().endswith("-cloud")):
        raise ValueError("ral local needs a local Ollama model name, e.g. qwen3:8b; cloud models are not supported")
    return value if ":" in value.rsplit("/",1)[-1] else value+":latest"

def docker_call(args,env,timeout=30,check=True):
    try:
        result=subprocess.run(["docker",*args],env=env,text=True,capture_output=True,timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("Docker did not respond; check that the local Docker engine is running") from exc
    if check and result.returncode:
        raise ValueError("Docker command failed: "+result.stderr.strip()[-1000:])
    return result

@contextmanager
def public_docker():
    if sys.platform not in ("darwin","linux"):
        raise ValueError("ral local is currently verified on Linux/macOS; use a target adapter on other systems")
    executable=shutil.which("docker")
    if not executable:
        raise ValueError("Docker is missing. Install/start Docker, then rerun ral local. No host Java/Ghidra is needed.")
    original=dict(os.environ)
    endpoint=original.get("DOCKER_HOST")
    if not endpoint:
        endpoint=docker_call(["context","inspect","--format","{{.Endpoints.docker.Host}}"],original).stdout.strip()
    if not endpoint.startswith("unix://"):
        raise ValueError("ral local needs a local Docker context with a Unix socket, not a remote daemon")
    # All images are public. Avoid keychain/login helpers and retain the chosen
    # local engine explicitly; no account credentials enter the build context.
    with tempfile.TemporaryDirectory(prefix="ral-public-docker-") as tmp:
        dirs=[Path.home()/".docker/cli-plugins",Path(executable).resolve().parent.parent/"cli-plugins"]
        (Path(tmp)/"config.json").write_text(json.dumps({"cliPluginsExtraDirs":[str(p) for p in dirs if p.is_dir()]}))
        env={**original,"DOCKER_CONFIG":tmp,"DOCKER_HOST":endpoint,"DOCKER_BUILDKIT":"1"}
        for key in ["DOCKER_CONTEXT","BUILDX_BUILDER","BUILDKIT_HOST"]:
            env.pop(key,None)
        docker_call(["info","--format","{{.ServerVersion}}"],env)
        yield env

def prepare_backend(env,state):
    digest=hashlib.sha256()
    for name in RECIPES:
        digest.update(name.encode()+b"\0"+(ASSETS/"docker"/name).read_bytes())
    recipe_hash=digest.hexdigest()
    tag="blindsight/ghidra-mcp:local-"+recipe_hash[:12]
    inspected=docker_call(["image","inspect",tag],env,check=False)
    if inspected.returncode:
        print("Preparing pinned GhidraMCP backend (first run downloads Java/Ghidra; cached afterwards).",flush=True)
        with tempfile.TemporaryDirectory(prefix="ral-runtime-build-") as tmp:
            for name in RECIPES:
                shutil.copyfile(ASSETS/"docker"/name,Path(tmp)/name)
            try:
                result=subprocess.run(["docker","build","--platform","linux/amd64","-t",tag,
                                       "-f",str(Path(tmp)/"Dockerfile.local"),tmp],env=env,
                                      stdout=sys.stderr,stderr=sys.stderr,timeout=1800)
            except subprocess.TimeoutExpired as exc:
                raise ValueError("backend build timed out; rerun ral local to reuse completed cached layers") from exc
            if result.returncode:
                raise ValueError("backend build failed; see Docker output above. No fixture result was produced")
        inspected=docker_call(["image","inspect",tag],env)
    info=json.loads(inspected.stdout)[0]
    image=info["Id"]
    code=('import importlib.metadata as m,json,platform,subprocess,hashlib; from pathlib import Path; '
          'print(json.dumps({"python":platform.python_version(),"machine":platform.machine(),'
          '"packages":{p:m.version(p) for p in ["ghidra-mcp","mcp","pyghidra","jpype1"]},'
          '"java":subprocess.run(["/opt/java/bin/java","-version"],capture_output=True,text=True).stderr,'
          '"ghidra_properties":Path("/opt/ghidra_12.1.4_PUBLIC/Ghidra/application.properties").read_text(),'
          '"jar_sha256":hashlib.sha256(Path("/opt/GhidraMCP.jar").read_bytes()).hexdigest()}))')
    result=docker_call(["run","--rm","--platform","linux/amd64","--network","none","--read-only",
                        "--entrypoint","python",image,"-c",code],env,timeout=60)
    versions=json.loads(result.stdout)
    if versions["packages"]["ghidra-mcp"]!="2.0.0" or "application.version=12.1.4" not in versions["ghidra_properties"]:
        raise ValueError("unexpected backend versions; refusing to run fixtures")
    return {"image_id":image,"recipe_sha256":recipe_hash,"platform":"linux/amd64",**versions}

@contextmanager
def ollama_service(state):
    process=None
    log=None
    try:
        try:
            api("version")
        except urllib.error.URLError:
            executable=shutil.which("ollama")
            if not executable:
                raise ValueError("Ollama is missing/not running. Install Ollama (https://ollama.com/download), then rerun ral local")
            folder=state/"setup"; folder.mkdir(parents=True,exist_ok=True)
            log=(folder/"ollama.log").open("ab")
            env={**os.environ,"OLLAMA_HOST":"127.0.0.1:11434","OLLAMA_NO_CLOUD":"1","OLLAMA_NOPRUNE":"1"}
            process=subprocess.Popen([executable,"serve"],env=env,stdout=log,stderr=log,start_new_session=True)
            print("Starting local Ollama for this run; the owned service will stop afterwards.",flush=True)
            deadline=time.monotonic()+30
            while True:
                if process.poll() is not None:
                    raise ValueError(f"Ollama startup failed; inspect {folder/'ollama.log'}")
                try:
                    api("version"); break
                except urllib.error.URLError:
                    if time.monotonic()>=deadline:
                        raise ValueError(f"Ollama did not become ready; inspect {folder/'ollama.log'}")
                    time.sleep(0.2)
        yield
    finally:
        if process is not None and process.poll() is None:
            try: os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError: pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try: os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait(timeout=5)
        if log:
            log.close()

def prepare_model(name):
    name=model_name(name)
    tags=api("tags").get("models",[])
    if not any(m.get("name")==name for m in tags):
        print(f"Downloading local model {name}; weights can require several GB and are cached by Ollama.",flush=True)
        req=urllib.request.Request(URL+"/api/pull",json.dumps({"model":name,"stream":True}).encode(),
                                  {"Content-Type":"application/json"})
        last=None
        with open_local(req,900) as response:
            for line in response:
                item=json.loads(line)
                if item.get("error"):
                    raise ValueError("Ollama model download failed: "+item["error"])
                status=item.get("status")
                if status and status!=last:
                    print("  "+status,flush=True); last=status
        tags=api("tags").get("models",[])
    model=next((m for m in tags if m.get("name")==name),None)
    if not model:
        raise ValueError(f"Ollama did not install {name}")
    if type(model.get("size")) is not int or model["size"]<1024*1024:
        raise ValueError("ral local requires locally stored model weights, not a remote model manifest")
    show=api("show",{"model":name})
    if show.get("remote_host") or show.get("remote_model"):
        raise ValueError("remote/cloud models are not supported by ral local")
    if "tools" not in show.get("capabilities",[]):
        raise ValueError(f"{name} does not advertise tool calling; use a local tool-capable model such as qwen3:8b")
    return {"name":name,"digest":model.get("digest"),"details":model.get("details"),"size":model.get("size"),
            "declared_parameters":show.get("parameters"),"capabilities":show.get("capabilities"),
            "ollama_version":api("version"),"request_options":{"temperature":0.6},
            "reference_agent_sha256":hashlib.sha256((ASSETS/"runner/local_agent.py").read_bytes()).hexdigest(),
            "host_client":{"mcp":importlib.metadata.version("mcp"),"python":sys.version.split()[0]},
            "scope":"reference agent; non-explicit sampler/context options inherit server defaults"}

@contextmanager
def environment(values):
    old={k:os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key,value in old.items():
            if value is None: os.environ.pop(key,None)
            else: os.environ[key]=value

def run(args,state):
    from . import product
    args.model=model_name(args.model)
    if not math.isfinite(args.target_timeout) or args.target_timeout <= 0:
        raise ValueError("episode timeout must be finite and positive")
    if any(not math.isfinite(v) or not 0<=v<=100 for v in [args.max_recall_drop,args.max_coverage_drop]) or args.max_unsupported_increase<0:
        raise ValueError("regression thresholds must be finite percentage points 0–100; unsupported increase must be non-negative")
    if args.baseline:
        baseline=state/"baseline" if args.baseline=="saved" else Path(args.baseline).expanduser().resolve()
        if not (baseline/"meta.json").is_file() or not (baseline/"runs.jsonl").is_file():
            raise ValueError("Baseline missing. First run ral local, then ral baseline save; no new checks started")
        old=json.loads((baseline/"meta.json").read_text())
        if old.get("input_paths")!="container-fixed-v1":
            raise ValueError("Baseline uses a different input-path protocol; create a fresh ral local baseline")
        suite=f"case:{args.case}" if args.case else args.suite
        if old.get("suite")!=suite:
            raise ValueError(f"Baseline suite is {old.get('suite')!r}; use the same suite or save a new baseline")
    if not importlib.util.find_spec("mcp"):
        raise ValueError("Install the local extra: uvx --from 'blindsight[local] @ git+https://github.com/AlicanAkyol/blindsight' ral local")
    state.mkdir(parents=True,exist_ok=True)
    owner=uuid.uuid4().hex
    print("Checking Blindsight's read-only reference agent, not an existing custom agent. No YAML/adapter required.",flush=True)
    with public_docker() as docker_env, ollama_service(state):
        model=prepare_model(args.model)
        runtime=prepare_backend(docker_env,state)
        values={k:docker_env[k] for k in ["DOCKER_CONFIG","DOCKER_HOST"]}
        values["DOCKER_CONTEXT"]=""
        logs=state/"logs"; logs.mkdir(parents=True,exist_ok=True)
        values["RAL_LOCAL_LOG"]=str(logs/(owner+".log"))
        values.update(RAL_LOCAL_IMAGE=runtime["image_id"],RAL_LOCAL_OWNER=owner,RAL_AGENT_MODEL=args.model)
        try:
            with environment(values):
                from .runner.local_agent import probe
                print("Verifying backend read/decompile (setup probe; no model inference).",flush=True)
                folder=state/"setup"; folder.mkdir(parents=True,exist_ok=True)
                probe_log=logs/(owner+"-probe.log")
                try:
                    with probe_log.open("w") as log:
                        runtime["smoke"]=asyncio.run(probe(ASSETS/"corpus/artifacts/clean/agent_fixture",runtime["image_id"],owner,log))
                except Exception as exc:
                    raise ValueError(f"backend preflight failed; inspect {probe_log}") from exc
                (folder/"local-runtime.json").write_text(json.dumps({"backend":runtime,"model":model,"agent_log":values["RAL_LOCAL_LOG"],"probe_log":str(probe_log)},indent=2)+"\n")
                if args.prepare_only:
                    print("Local runtime ready. Next: ral local",flush=True)
                    return 0
                cfg=product.default_config()
                name="local-reference-agent"
                cfg["targets"]={name:{"command":[sys.executable,"-m","blindsight.runner.local_agent"],
                    "timeout":args.target_timeout,"env":values,"model_info":model,"runtime_info":runtime,
                    "input_paths":"container-fixed-v1"}}
                args.target=name; args.profile=None
                product._environment(cfg,state)
                code=product.check(args,cfg,state)
                if code==1:
                    print("Setup succeeded; measured fixture issues are shown above (exit 1).",flush=True)
                if code in (0,1):
                    print("Next: ral baseline save\nAfter a model change: ral local --model MODEL --baseline saved",flush=True)
                if code==2:
                    print(f"Execution incomplete; backend diagnostics: {values['RAL_LOCAL_LOG']}",flush=True)
                return code
        finally:
            found=docker_call(["ps","-aq","--filter",f"label=org.blindsight.owner={owner}"],docker_env)
            ids=found.stdout.split()
            if ids:
                docker_call(["rm","-f",*ids],docker_env)
