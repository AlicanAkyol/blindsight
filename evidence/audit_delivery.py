"""Audit historical saved context for truncation, without rewriting old evidence.

This is not a new experiment or proof of model attention. Older measurements
remain successful-call proxies. Run: python evidence/audit_delivery.py
"""
import json
from pathlib import Path


def audit(root):
    runs = messages = truncated = 0
    for path in sorted(Path(root).glob('*/runs.jsonl')):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            runs += 1
            record = json.loads(line)
            for msg in (record.get('trace') or {}).get('messages', []):
                if msg.get('role') == 'tool' and msg.get('tool_name') == 'decompile_function':
                    messages += 1
                    truncated += '...[truncated]' in (msg.get('content') or '')
    return {'runs': runs, 'saved_decompile_messages': messages,
            'messages_with_truncation_marker': truncated,
            'scope': 'Historical saved context audit only; not a new opaque-path model experiment.'}


if __name__ == '__main__':
    print(json.dumps(audit(Path(__file__).resolve().parent), indent=2))
