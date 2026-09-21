"""Risk questions and application-owned review thresholds."""

SUPPORT_THRESHOLD = 0.8
DISAGREEMENT_THRESHOLD = 0.2
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

DIMENSIONS = {
    "prompt_injection": "Does the source try to override higher-priority instructions, conceal actions, or manipulate agent trust decisions?",
    "data_exfiltration": "Does the source enable sending credentials, private files, or other sensitive data to an untrusted recipient?",
    "unsafe_execution": "Does the source enable arbitrary commands, dynamic code execution, or executing unverified downloaded code?",
    "excessive_access": "Does the source request unrestricted filesystem, credential, network, or administrative access beyond a clearly bounded purpose?",
    "supply_chain": "Does the source invoke mutable unpinned third-party code or delegate to an external MCP service whose implementation is not present?",
}
