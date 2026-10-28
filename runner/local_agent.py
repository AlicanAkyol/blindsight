"""Local read-only reference agent. Only the backend runs in Docker; model calls stay on loopback."""
import asyncio
import json
import os
import re
import sys
import time
import urllib.request
from contextlib import asynccontextmanager, nullcontext
from pathlib import Path
import shutil
import tempfile
from blindsight.runner.measurement import delivery_fields

BASE_URL = "http://127.0.0.1:11434/v1"
MODEL = os.environ.get("RAL_AGENT_MODEL")
READ_ONLY = True
MAX_STEPS = 25
MAX_TOOL_CHARS = 8000

# GhidraMCP 2.0 tools that change the program database.
WRITE_TOOLS = {
    "rename_function", "rename_function_by_address", "rename_data", "rename_variable",
    "set_function_prototype", "set_local_variable_type",
    "set_decompiler_comment", "set_disassembly_comment",
}


def chat(messages, tools, seed):
    headers = {"Content-Type": "application/json"}
    body = {"model": MODEL, "messages": messages, "tools": tools, "seed": seed, "temperature": 0.6}
    req = urllib.request.Request(BASE_URL + "/chat/completions", json.dumps(body).encode(), headers)
    with urllib.request.urlopen(req, timeout=900) as r:
        return json.loads(r.read())["choices"][0]["message"]


def final_report(text):
    """Last JSON object with a verdict in the model's answer; RAL validates the enums."""
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S)
    for m in reversed(list(re.finditer(r"\{.*\}", text, re.S))):
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "verdict" in obj:
            return {"verdict": obj["verdict"], "findings": obj.get("findings", []),
                    "summary": str(obj.get("summary", ""))}
    return None


async def agent(mcp, prompt, seed, calls):
    listed = (await mcp.list_tools()).tools
    tools = [{"type": "function", "function": {"name": t.name, "description": t.description or "",
                                               "parameters": t.inputSchema}}
             for t in listed if not (READ_ONLY and t.name in WRITE_TOOLS)]
    messages = [{"role": "system", "content": prompt},
                {"role": "user", "content": "The binary is loaded. Begin the triage."}]
    last_batch_start = len(calls)
    for _ in range(MAX_STEPS):
        last_batch_start = len(calls)
        msg = chat(messages, tools, seed)
        messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
        if not msg.get("tool_calls"):
            return final_report(msg.get("content"))
        for tc in msg["tool_calls"]:
            name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            result, is_error, refused = await call_tool(mcp, name, args)
            delivered = result[:MAX_TOOL_CHARS] + ("\n...[truncated]" if len(result) > MAX_TOOL_CHARS else "")
            call = {"tool": name, "args": args, "write": name in WRITE_TOOLS, "is_error": is_error,
                    "result_chars": 0 if is_error else len(result),
                    **delivery_fields(result, delivered)}
            if refused:
                call["refused_read_only"] = True
            calls.append(call)
            messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": delivered})
    for call in calls[last_batch_start:]:
        call["delivery_recorded"] = False
    return None


async def call_tool(mcp, name, args):
    # Read-only is enforced here, outside the model: the write never reaches Ghidra.
    if READ_ONLY and name in WRITE_TOOLS:
        return "error: this tool is disabled in read-only mode", True, True
    try:
        res = await mcp.call_tool(name, args)
    except Exception as e:  # unknown tool or bad arguments: tell the model and continue
        return f"error: {type(e).__name__}: {e}", True, False
    return "".join(getattr(c, "text", "") for c in res.content), bool(res.isError), False


def container_args(binary, image, owner):
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image or ""):
        raise ValueError("prepare the pinned backend with ral local first")
    if not re.fullmatch(r"[a-f0-9]{32}", owner or ""):
        raise ValueError("missing local container ownership token")
    return ["run", "--rm", "-i", "--platform", "linux/amd64", "--network", "none",
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=512m", "--label", f"org.blindsight.owner={owner}",
            "--mount", f"type=bind,source={binary},target=/input/sample.bin,readonly", image,
            "--headless", "--binary", "/input/sample.bin", "--ready-timeout", "300", "--discard"]


@asynccontextmanager
async def connection(binary, image=None, owner=None, errlog=None):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    # Bind only a readable opaque file, never the caller's project directory.
    with tempfile.TemporaryDirectory(prefix="ral-container-input-", dir="/tmp") as tmp:
        staged=Path(tmp)/"sample.bin"
        shutil.copyfile(binary, staged); staged.chmod(0o444)
        params=StdioServerParameters(command="docker",env=dict(os.environ),args=container_args(
            staged.resolve(),image or os.environ.get("RAL_LOCAL_IMAGE"),owner or os.environ.get("RAL_LOCAL_OWNER")))
        log_path=os.environ.get("RAL_LOCAL_LOG")
        log=open(log_path,"a") if log_path and errlog is None else nullcontext(errlog or sys.stderr)
        with log as stream:
            async with stdio_client(params, errlog=stream) as (r,w):
                async with ClientSession(r,w) as mcp:
                    await mcp.initialize()
                    yield mcp


async def probe(binary,image,owner,errlog=None):
    async with connection(binary,image,owner,errlog) as mcp:
        info=await mcp.call_tool("get_program_info",{})
        result=await mcp.call_tool("decompile_function",{"name":"main"})
        if info.isError or result.isError:
            raise ValueError("backend preflight failed to read/decompile the fixture")
        text="".join(getattr(c,"text","") for c in result.content)
        payload=json.loads(text)
        if (payload.get("function",{}).get("name")!="main" or not payload.get("code","").strip()
                or payload.get("truncated") is not False):
            raise ValueError("backend preflight did not return a complete main body")
        return {"program_info":True,"decompile_main":True,"decompile_chars":len(text)}


async def run(request):
    calls = []
    async with connection(request["binary"]) as mcp:
        report = await agent(mcp, request["task"]["prompt"], request["seed"], calls)
    return report, calls


def main():
    request = json.load(sys.stdin)
    if request.get("protocol") != "ral.target.v1":
        raise ValueError("unsupported RAL protocol")
    if not MODEL:
        raise ValueError("set RAL_AGENT_MODEL in the target's env")
    started = time.time()
    report, calls = asyncio.run(run(request))
    print(f"{len(calls)} tool call(s) in {time.time() - started:.0f}s", file=sys.stderr)
    if report is None:
        # No valid final answer: fail loudly so RAL records an execution error, not a result.
        sys.exit("agent produced no JSON report with a verdict")
    json.dump({"protocol": "ral.target.v1", "report": report, "calls": calls}, sys.stdout)


if __name__ == "__main__":
    main()
