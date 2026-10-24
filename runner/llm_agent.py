"""LLM agent backed by a local Ollama model, with GhidraMCP tools exposed as-is.

No defence is applied here: the model sees raw tool output and every tool,
including write tools. This is the "no defence" condition.

The full transcript (messages, thinking, tool calls) is kept on
session.extra so the evaluator and humans can inspect what happened.
"""
import json
import re
import urllib.request

OLLAMA_URL = "http://127.0.0.1:11434"
MAX_STEPS = 25
MAX_TOOL_CHARS = 8000
OPTIONS = {"temperature": 0.6, "top_p": 0.95, "num_ctx": 16384}


def _post(path, body):
    req = urllib.request.Request(OLLAMA_URL + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=900) as r:
        return json.loads(r.read())


def model_info(model):
    show = _post("/api/show", {"model": model})
    with urllib.request.urlopen(OLLAMA_URL + "/api/tags") as r:
        tags = json.loads(r.read())
    digest = next((m["digest"] for m in tags["models"] if m["name"] == model), None)
    return {"model": model, "digest": digest, "details": show.get("details"), "options": OPTIONS}


def _tools_for_ollama(mcp_tools):
    return [{"type": "function", "function": {
        "name": t.name, "description": t.description or "", "parameters": t.inputSchema}}
        for t in mcp_tools]


def parse_report(text):
    """Last top-level JSON object in the final answer, or None."""
    for m in reversed(list(re.finditer(r"\{.*\}", text or "", re.S))):
        try:
            obj = json.loads(m.group(0))
            if isinstance(obj, dict) and "verdict" in obj:
                return obj
        except json.JSONDecodeError:
            continue
    return None


def make_agent(model):
    async def agent(session, task, seed=0):
        tools = _tools_for_ollama(await session.list_tools())
        messages = [{"role": "system", "content": task["prompt"]},
                    {"role": "user", "content": "The binary is loaded. Begin the triage."}]
        steps = 0
        final = None
        while steps < MAX_STEPS:
            steps += 1
            resp = _post("/api/chat", {"model": model, "messages": messages, "tools": tools,
                                       "think": True, "stream": False,
                                       "options": {**OPTIONS, "seed": seed}})
            msg = resp["message"]
            messages.append(msg)
            calls = msg.get("tool_calls") or []
            if not calls:
                final = msg.get("content", "")
                break
            for c in calls:
                fn = c["function"]
                args = fn.get("arguments") or {}
                try:
                    result = await session.call(fn["name"], args)
                except Exception as e:  # unknown tool or bad args: tell the model, keep going
                    result = f"error: {type(e).__name__}: {e}"
                if len(result) > MAX_TOOL_CHARS:
                    result = result[:MAX_TOOL_CHARS] + "\n...[truncated]"
                messages.append({"role": "tool", "tool_name": fn["name"], "content": result})
        session.extra = {"messages": messages, "steps": steps, "hit_step_limit": final is None}
        return parse_report(final)
    return agent
