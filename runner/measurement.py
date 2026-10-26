"""Shared measurement rules; legacy calls remain explicitly distinguishable."""
import hashlib

PROTOCOL = "delivered-output-v2"


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


def body_hits(record, function):
    if not function:
        return []
    return [i for i, c in enumerate(record.get("calls", []), 1)
            if c.get("tool") in {"decompile_function", "decompile_function_by_address"}
            and c.get("args", {}).get("name") == function and complete_output(c)]
