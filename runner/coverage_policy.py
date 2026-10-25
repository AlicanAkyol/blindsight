"""Coverage-aware function selection: pick functions to decompile from
behaviour signals (imported risky APIs and their xrefs), never from the
program's own symbol names.

Chain (see docs/PREREG.md 2026-10-25):
    risky import  ->  its PLT stub (<EXTERNAL>::name with callers)
                  ->  xref  ->  user function that calls it
                  ->  xref  ->  one level of callers
    -> budgeted set of user functions to decompile.

A neutrally named persistence function (routine_b, task_17) is reached because
it calls fopen/mkdir/socket etc., regardless of what it is named.
"""

# Curated risky EXTERNAL APIs: libc/syscall IMPORT names, not the program's own
# function names. A binary author still controls which imports/calls exist, so this
# is a coverage heuristic (resists symbol renaming), not a security boundary.
RISKY_APIS = {
    "fs": ["open", "openat", "fopen", "mkdir", "unlink", "rename", "creat", "fwrite"],
    "net": ["socket", "connect", "sendto", "send", "recv", "bind", "listen"],
    "proc": ["execve", "execl", "fork", "system", "popen", "ptrace", "clone"],
}
ALL_RISKY = {name for group in RISKY_APIS.values() for name in group}


def _user(fn):
    return fn and not fn["name"].startswith("<EXTERNAL>")


async def select(session, budget=20, expand_callers=True):
    """Return (ordered list of (name,address) to decompile, trace dict).

    session: a RecordingSession. Uses list_functions, get_xrefs_to.
    """
    fns = (await session.call_json("list_functions", {"limit": 500})).get("items", [])
    # PLT stubs for risky APIs: <EXTERNAL>::<api> entries that have real callers.
    ext = [f for f in fns if f["name"].startswith("<EXTERNAL>::")]
    risky_stubs = [f for f in ext if f["name"].split("::", 1)[1] in ALL_RISKY]

    selected = {}          # addr -> name
    reason = {}            # addr -> which api pulled it in
    seeds = []
    for stub in risky_stubs:
        api = stub["name"].split("::", 1)[1]
        x = await session.call_json("get_xrefs_to", {"address": stub["address"]})
        for it in x.get("items", []):
            ff = it.get("from_function")
            if _user(ff) and ff["address"] not in selected:
                selected[ff["address"]] = ff["name"]
                reason[ff["address"]] = api
                seeds.append(ff)

    # one level of callers: the function that calls the API-using helper
    if expand_callers:
        for fn in list(seeds):
            x = await session.call_json("get_xrefs_to", {"address": fn["address"]})
            for it in x.get("items", []):
                ff = it.get("from_function")
                if _user(ff) and ff["address"] not in selected:
                    selected[ff["address"]] = ff["name"]
                    reason[ff["address"]] = f"caller of {fn['name']}"

    ordered = sorted(selected.items())[:budget]
    trace = {
        "risky_stubs": sorted({s["name"].split("::", 1)[1] for s in risky_stubs}),
        "selected": [{"name": n, "address": a, "reason": reason[a]} for a, n in ordered],
        "user_function_count": sum(1 for f in fns
                                   if not f["name"].startswith(("<EXTERNAL>", "FUN_"))),
        "budget": budget,
    }
    return [(n, a) for a, n in ordered], trace
