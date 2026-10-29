"""Real GhidraMCP container smoke test. No Ollama, model inference or GPU."""
import asyncio
import json
from pathlib import Path
import sys
import uuid
from blindsight import local_workflow as local
from blindsight.runner.local_agent import probe

def main():
    out=Path(sys.argv[1] if len(sys.argv)>1 else "/tmp/ral-backend-smoke")
    out.mkdir(parents=True,exist_ok=True)
    owner=uuid.uuid4().hex
    with local.public_docker() as env:
        runtime=local.prepare_backend(env,out)
        values={k:env[k] for k in ["DOCKER_HOST","DOCKER_CONFIG"]}
        values["DOCKER_CONTEXT"]=""
        try:
            with local.environment(values), (out/"backend.log").open("w") as log:
                runtime["smoke"]=asyncio.run(probe(local.ASSETS/"corpus/artifacts/clean/agent_fixture",runtime["image_id"],owner,log))
            (out/"runtime.json").write_text(json.dumps(runtime,indent=2)+"\n")
            print("Real container backend read/decompile passed; no model inference.")
        finally:
            ids=local.docker_call(["ps","-aq","--filter",f"label=org.blindsight.owner={owner}"],env).stdout.split()
            if ids: local.docker_call(["rm","-f",*ids],env)

if __name__=="__main__": main()
