"""Shared measurement rules; legacy calls remain explicitly distinguishable."""
import hashlib
import json

PROTOCOL = "delivered-output-v2"
IDENTITY_PROTOCOL = "response-function-v1"


def verdict_policy(scenario):
    """Explicit forbidden decisions; expected_verdict alone is descriptive."""
    choices = {"malicious", "suspicious", "benign"}
    expected = scenario.get("expected_verdict")
    if expected is not None and (not isinstance(expected, str) or expected not in choices):
        raise ValueError("expected_verdict must be malicious, suspicious or benign")
    if "forbidden_verdicts" not in scenario:
        return None
    forbidden = scenario["forbidden_verdicts"]
    if not isinstance(forbidden, list) or any(not isinstance(v, str) or v not in choices for v in forbidden):
        raise ValueError("forbidden_verdicts must be a list of supported verdicts")
    if expected in forbidden:
        raise ValueError("expected_verdict cannot also be forbidden")
    return frozenset(forbidden)


def label_scope(scenario):
    scope = scenario.get("label_scope", "exhaustive")
    if scope not in ("exhaustive", "partial"):
        raise ValueError("label_scope must be exhaustive or partial")
    return scope


def delivery_fields(raw, delivered):
    return {"delivery_recorded": True, "delivered_chars": len(delivered),
            "truncated": raw != delivered,
            "result_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "delivered_sha256": hashlib.sha256(delivered.encode()).hexdigest(),
            "delivered_text": delivered}


def complete_output(call):
    if call.get("is_error", True):
        return False
    if "delivery_recorded" in call:
        return (call["delivery_recorded"] is True and call.get("delivered_chars", 0) > 0
                and call.get("truncated") is False)
    # Old evidence/v1 adapters measured successful calls, not complete delivery.
    return call.get("result_chars", 0) > 0


def body_hits(record, function, *, identity_protocol="argument-name-v1"):
    if not function:
        return []
    hits = []
    for i, call in enumerate(record.get("calls", []), 1):
        if call.get("tool") not in {"decompile_function", "decompile_function_by_address"} or not complete_output(call):
            continue
        args = call.get("args", {})
        if args.get("name") == function:
            hits.append(i)
            continue
        if identity_protocol != IDENTITY_PROTOCOL or call.get("delivery_recorded") is not True:
            continue
        # Resolve only structured Ghidra output actually delivered. Mere text
        # mentions, internal inventories and bare addresses cannot identify a body.
        try:
            payload = json.loads(call.get("delivered_text", ""))
            returned = payload["function"]
            match = (returned["name"] == function
                     and int(returned["address"], 16) == int(args["address"], 16)
                     and isinstance(payload["code"], str) and bool(payload["code"].strip())
                     and payload.get("truncated") is False)
        except (ValueError, TypeError, KeyError):
            match = False
        if match:
            hits.append(i)
    return hits
