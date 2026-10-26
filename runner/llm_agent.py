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
# num_predict caps one model turn: an uncapped thinking loop once ran into the
# 900 s HTTP timeout (results/20261024T185609Z, v3 r2). Added after that run.
OPTIONS = {"temperature": 0.6, "top_p": 0.95, "num_ctx": 16384, "num_predict": 6144}


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
    """Validate the final answer against the report contract.

    Returns (report, meta). report is None if nothing valid was found. meta
    records contract violations so they are visible in the logs rather than
    silently coerced: unknown verdict, non-list or unknown findings, extra
    keys, or trailing text after the JSON object.
    """
    from tasks import FINDINGS, VERDICTS
    for m in reversed(list(re.finditer(r"\{.*\}", text or "", re.S))):
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            continue
        if not (isinstance(obj, dict) and "verdict" in obj):
            continue
        issues = []
        if obj.get("verdict") not in VERDICTS:
            issues.append(f"verdict not in enum: {obj.get('verdict')!r}")
        f = obj.get("findings")
        if not isinstance(f, list):
            issues.append(f"findings not a list: {type(f).__name__}")
        elif [x for x in f if x not in FINDINGS]:
            issues.append(f"unknown findings: {[x for x in f if x not in FINDINGS]}")
        if set(obj) - {"verdict", "findings", "summary"}:
            issues.append(f"extra keys: {sorted(set(obj) - {'verdict', 'findings', 'summary'})}")
        if (text or "")[m.end():].strip():
            issues.append("non-whitespace text after the JSON object")
        return obj, {"contract_issues": issues}
    return None, {"contract_issues": ["no JSON object with a verdict found"]}


# Compiler/runtime helpers skipped by the forced-decompile arm (docs/PREREG.md).
RUNTIME_FUNCS = {"_init", "_fini", "_start", "frame_dummy", "register_tm_clones",
                 "deregister_tm_clones", "__do_global_dtors_aux"}


async def forced_prefix(session, only=None):
    """Harness-made tool calls inserted before the model's first turn.

    only=None (forced_decompile arm): call list_functions, then decompile
    every user function; the full inventory enters the context.

    only=[names] (forced_one arm): decompile JUST those functions by name and
    do NOT add list_functions to the context. This keeps the intervention
    minimal, so a recall change is attributable to showing one function body,
    not to also revealing the whole symbol inventory. Identical for every seed.
    """
    msgs = []

    async def add(name, args):
        result = await session.call(name, args, forced=True)
        raw = result
        if len(result) > MAX_TOOL_CHARS:
            result = result[:MAX_TOOL_CHARS] + "\n...[truncated]"
        session.record_delivery(raw, result)
        msgs.append({"role": "assistant", "content": "",
                     "tool_calls": [{"function": {"name": name, "arguments": args}}]})
        msgs.append({"role": "tool", "tool_name": name, "content": result})
        return result

    if only is not None:
        for n in only:                       # decompile by name; no list_functions
            await add("decompile_function", {"name": n})
        return msgs

    listing = json.loads(await add("list_functions", {"limit": 500}))
    names = [f["name"] for f in listing.get("items", [])
             if not f["name"].startswith(("<EXTERNAL>", "FUN_")) and f["name"] not in RUNTIME_FUNCS]
    for n in names:
        await add("decompile_function", {"name": n})
    return msgs


def make_agent(model, arm="natural"):
    async def agent(session, task, seed=0, force_functions=None):
        tools = _tools_for_ollama(await session.list_tools())
        messages = [{"role": "system", "content": task["prompt"]},
                    {"role": "user", "content": "The binary is loaded. Begin the triage."}]
        cov_trace = None
        if arm == "forced_decompile":
            messages += await forced_prefix(session)
        elif arm == "forced_one":
            messages += await forced_prefix(session, only=force_functions or [])
        elif arm == "coverage_aware":
            import coverage_policy
            selected, cov_trace = await coverage_policy.select(session)
            messages += await forced_prefix(session, only=[n for n, _ in selected])
        steps = 0
        final = None
        last_batch_start = len(session.calls)
        while steps < MAX_STEPS:
            last_batch_start = len(session.calls)
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
                before = len(session.calls)
                try:
                    result = await session.call(fn["name"], args)
                except Exception as e:  # unknown tool or bad args: tell the model, keep going
                    result = f"error: {type(e).__name__}: {e}"
                raw = result
                if len(result) > MAX_TOOL_CHARS:
                    result = result[:MAX_TOOL_CHARS] + "\n...[truncated]"
                if len(session.calls) > before:
                    session.record_delivery(raw, result)
                messages.append({"role": "tool", "tool_name": fn["name"], "content": result})
        # The last tool batch at the step limit is never sent in a next request.
        if final is None and steps >= MAX_STEPS:
            for call in session.calls[last_batch_start:]:
                call["delivery_recorded"] = False
        report, pmeta = parse_report(final)
        session.extra = {"messages": messages, "steps": steps, "hit_step_limit": final is None,
                         "coverage_policy": cov_trace, **pmeta}
        return report
    return agent
