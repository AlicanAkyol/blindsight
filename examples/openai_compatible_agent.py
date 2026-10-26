"""A working ral.target.v1 adapter: an LLM agent driving GhidraMCP through tool calls.

The model is any OpenAI-compatible chat-completions server with tool calling:
Ollama, LM Studio, llama.cpp server, vLLM. GhidraMCP runs headless on the
requested binary; every MCP call the agent makes is recorded here and reported
in `calls`, so RAL can measure which function bodies the agent actually read.

Install (needs Ghidra 12.1.4, the JDK Ghidra uses and the GhidraMCP 2.0 extension jar):

    pip install '.[ghidra]'   # from a clone of this repository

Configure in .ral.yaml (the environment is passed to this process only):

    default_target: llm-agent
    targets:
      llm-agent:
        # a Python with blindsight[ghidra] (mcp + ghidra-mcp) installed
        command: [/path/to/venv/bin/python, /absolute/path/to/openai_compatible_agent.py]
        timeout: 900
        env:
          RAL_AGENT_MODEL: qwen3:8b                     # required
          RAL_AGENT_BASE_URL: http://127.0.0.1:11434/v1 # default: local Ollama
          RAL_AGENT_READ_ONLY: "0"                      # 1 refuses write tools
          GHIDRA_INSTALL_DIR: /path/to/ghidra_12.1.4_PUBLIC
          GHIDRA_MCP_EXTENSION_JAR: /path/to/GhidraMCP.jar
          JAVA_HOME: /path/to/jdk

RAL_AGENT_API_KEY, if set, is sent as a bearer token; keep it in the
environment, never in the command. Replace agent() with your own loop to check
your agent; keep the call recording and the response format.
"""
import asyncio
import json
import os
import re
import sys
import time
import urllib.request
from blindsight.runner.measurement import delivery_fields

BASE_URL = os.environ.get("RAL_AGENT_BASE_URL", "http://127.0.0.1:11434/v1").rstrip("/")
MODEL = os.environ.get("RAL_AGENT_MODEL")
READ_ONLY = os.environ.get("RAL_AGENT_READ_ONLY") == "1"
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
    if os.environ.get("RAL_AGENT_API_KEY"):
        headers["Authorization"] = "Bearer " + os.environ["RAL_AGENT_API_KEY"]
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


async def run(request):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    params = StdioServerParameters(
        command=sys.executable, env=dict(os.environ),
        args=["-m", "ghidra_mcp", "--headless", "--binary", request["binary"], "--ready-timeout", "300", "--discard"])
    calls = []
    async with stdio_client(params, errlog=sys.stderr) as (r, w):
        async with ClientSession(r, w) as mcp:
            await mcp.initialize()
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
