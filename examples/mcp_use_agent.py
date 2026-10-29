"""Experimental mcp-use MCPAgent adapter, local Ollama + pinned Docker Ghidra.

See docs/mcp-use.md. This runs the external MCPAgent loop, not Blindsight's
reference loop. Raw MCP output and successful model-request context are
recorded separately. No cloud provider, web tools or tracing is configured.
"""
import json
import logging
import os
from pathlib import Path
import tempfile
import uuid

# Set before importing the external framework. Do not load a user's .env file.
os.environ["MCP_USE_ANONYMIZED_TELEMETRY"] = "false"
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"

from blindsight.adapter import serve
from blindsight.local_workflow import public_docker, prepare_backend, ollama_service, prepare_model
from blindsight.runner.measurement import delivery_fields

WRITE_TOOLS = {
    "rename_function", "rename_function_by_address", "rename_data", "rename_variable",
    "set_function_prototype", "set_local_variable_type",
    "set_decompiler_comment", "set_disassembly_comment",
}


class DeliveryRecorder:
    """Match actual tool messages after a successful model response, not at call time."""
    def __init__(self):
        self.calls = []
        self.pending = {}
        self.message_calls = {}

    def add(self, name, arguments, text, is_error=False, refused=False):
        entry = {"tool": name, "args": arguments, "write": name in WRITE_TOOLS,
                 "is_error": is_error, "result_chars": len(text),
                 "raw_text": text, **delivery_fields(text, ""), "truncated": False}
        if refused:
            entry["refused_read_only"] = True
        self.calls.append(entry)

    def start(self, messages, run_id):
        self.pending[run_id] = [msg for batch in messages for msg in batch
                                if getattr(msg, "type", None) == "tool"]

    def end(self, run_id):
        used = set(self.message_calls.values())
        for msg in self.pending.pop(run_id, []):
            ident = getattr(msg, "tool_call_id", None)
            text = getattr(msg, "content", None)
            if not ident or not isinstance(text, str):
                continue  # Never infer delivery from summaries or unrecognized blocks.
            if ident in self.message_calls:
                continue
            for i, call in enumerate(self.calls):
                if i in used or (getattr(msg, "name", None) and msg.name != call["tool"]):
                    continue
                # raw_text is the MCP text before the framework's conversion.
                if text == call["raw_text"]:
                    call.update(delivery_fields(call["raw_text"], text))
                    self.message_calls[ident] = i
                    used.add(i)
                    break

    def fail(self, run_id):
        self.pending.pop(run_id, None)


def callbacks(recorder):
    from langchain_core.callbacks import BaseCallbackHandler

    class DeliveryCallback(BaseCallbackHandler):
        def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
            recorder.start(messages, run_id)

        def on_llm_end(self, response, *, run_id, **kwargs):
            recorder.end(run_id)

        def on_llm_error(self, error, *, run_id, **kwargs):
            recorder.fail(run_id)

    return DeliveryCallback()


async def analyse(binary, prompt, seed):
    from langchain_ollama import ChatOllama
    from mcp.types import CallToolResult, TextContent
    from mcp_use import MCPAgent, MCPClient
    from mcp_use.client.middleware import Middleware
    from blindsight.runner.local_agent import container_args

    logging.basicConfig(level=logging.WARNING)
    recorder = DeliveryRecorder()

    class RecordCalls(Middleware):
        async def on_call_tool(self, context, call_next):
            name, arguments = context.params.name, context.params.arguments or {}
            if name in WRITE_TOOLS:
                text = "Write tool refused by adapter read-only policy"
                recorder.add(name, arguments, text, is_error=True, refused=True)
                return CallToolResult(isError=True, content=[TextContent(type="text", text=text)])
            try:
                result = await call_next(context)
            except Exception as exc:
                recorder.add(name, arguments, str(exc), is_error=True)
                raise
            text = "\n".join(c.text for c in result.content if c.type == "text")
            recorder.add(name, arguments, text, is_error=bool(result.isError))
            return result

    state = Path(".ral/mcp-use-setup").resolve()
    state.mkdir(parents=True, exist_ok=True)
    owner = uuid.uuid4().hex
    with public_docker() as env, ollama_service(state), tempfile.TemporaryDirectory(prefix="ral-mcp-use-", dir="/tmp") as tmp:
        from shutil import copyfile
        sample = Path(tmp) / "sample.bin"
        copyfile(binary, sample); sample.chmod(0o444)
        model = prepare_model("qwen3:8b")
        model.pop("reference_agent_sha256", None)
        model["scope"] = "mcp-use MCPAgent with explicit Ollama sampler options"
        model["request_options"] = {"temperature": 0.6, "seed": seed, "num_ctx": 16384,
                                    "num_predict": 6144, "top_p": 0.95}
        import hashlib, importlib.metadata
        model["adapter_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        model["agent_packages"] = {p: importlib.metadata.version(p) for p in
                                   ["mcp-use", "langchain", "langchain-core", "langchain-ollama"]}
        runtime = prepare_backend(env, state)
        (state / "runtime.json").write_text(json.dumps({"model": model, "backend": runtime}, indent=2)+"\n")
        config = {"mcpServers": {"ghidra": {"command": "docker",
                    "args": container_args(sample, runtime["image_id"], owner), "env": env}}}
        client = MCPClient(config=config, middleware=[RecordCalls()])
        llm = ChatOllama(model="qwen3:8b", base_url="http://127.0.0.1:11434",
                         temperature=0.6, seed=seed, num_ctx=16384, num_predict=6144, top_p=0.95,
                         client_kwargs={"trust_env": False}, async_client_kwargs={"trust_env": False})
        agent = MCPAgent(llm=llm, client=client, system_prompt=prompt,
                         max_steps=25, memory_enabled=False, retry_on_error=False,
                         disallowed_tools=sorted(WRITE_TOOLS), callbacks=[callbacks(recorder)],
                         pretty_print=False, verbose=False)
        try:
            text = await agent.run("The binary is loaded. Begin the triage.")
            # Do not ask another model to repair an invalid answer into a passing report.
            report = json.loads(text)
            return report, recorder.calls
        finally:
            await client.close_all_sessions()
            from blindsight.local_workflow import docker_call
            ids = docker_call(["ps", "-aq", "--filter", "label=org.blindsight.owner="+owner], env).stdout.split()
            if ids:
                docker_call(["rm", "-f", *ids], env)


if __name__ == "__main__":
    serve(analyse)
