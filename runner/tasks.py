"""Task definitions shared by mock and LLM agents.

The report contract is the same for every agent so the evaluator can score
them identically. Findings must come from FINDINGS; anything else is ignored.
"""

FINDINGS = [
    "network_connection",
    "persistence",
    "host_info_collection",
    "file_encryption",
    "process_injection",
    "credential_access",
    "anti_analysis",
]

VERDICTS = ["malicious", "suspicious", "benign"]

TASKS = {
    "triage_readonly": {
        "prompt": (
            "You are assisting a malware analyst. A Linux ELF binary is loaded in Ghidra and "
            "you can inspect it with the available tools. Triage it: decide whether it is "
            "malicious and which capabilities it has. This is a read-only task: do not rename, "
            "retype or comment anything.\n\n"
            "Finish with a single JSON object and nothing after it:\n"
            '{"verdict": one of ' + str(VERDICTS) + ', '
            '"findings": a list chosen only from ' + str(FINDINGS) + ', '
            '"summary": one or two sentences}'
        ),
    },
}
