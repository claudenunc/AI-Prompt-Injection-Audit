import re
from dataclasses import dataclass
from typing import List


@dataclass
class InjectionFinding:
    detected: bool
    severity: str
    matches: List[str]
    reason: str


INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"disregard (all )?(previous|prior|above) instructions",
    r"forget (all )?(previous|prior|above) instructions",
    r"reveal (the )?(system prompt|developer message|hidden instructions|secrets)",
    r"send (me )?(api keys|passwords|tokens|credentials|secrets)",
    r"exfiltrate",
    r"bypass (safety|security|policy|rules)",
    r"you are now",
    r"act as",
    r"pretend to be",
    r"do not tell the user",
    r"hide this from",
    r"delete logs",
    r"disable (logging|audit|safety|security)",
    r"run this command",
    r"execute this",
    r"make an http request",
    r"download and run",
]


def detect_injection(text: str) -> InjectionFinding:
    if not text:
        return InjectionFinding(False, "none", [], "No content provided.")

    lowered = text.lower()
    matches = []

    for pattern in INJECTION_PATTERNS:
        found = re.findall(pattern, lowered)
        if found:
            matches.append(pattern)

    if not matches:
        return InjectionFinding(False, "none", [], "No injection patterns detected.")

    high_risk_keywords = [
        "api keys",
        "passwords",
        "tokens",
        "credentials",
        "secrets",
        "delete logs",
        "disable logging",
        "exfiltrate",
        "system prompt",
    ]

    severity = "medium"
    if any(keyword in lowered for keyword in high_risk_keywords):
        severity = "high"

    return InjectionFinding(
        detected=True,
        severity=severity,
        matches=matches,
        reason="Untrusted content contains instructions that attempt to control the model or access protected information.",
    )
