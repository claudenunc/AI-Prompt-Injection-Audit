import json
import re
from datetime import datetime, timezone
from pathlib import Path


LOG_FILE = Path("logs/security_events.jsonl")
REDACTION_PATTERNS = [
    re.compile(r"\bapi keys?\b", re.IGNORECASE),
    re.compile(r"\bpasswords?\b", re.IGNORECASE),
    re.compile(r"\btokens?\b", re.IGNORECASE),
    re.compile(r"\bcredentials?\b", re.IGNORECASE),
    re.compile(r"\bsecrets?\b", re.IGNORECASE),
]


def sanitize_for_log(value):
    if isinstance(value, dict):
        return {key: sanitize_for_log(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_for_log(item) for item in value]
    if isinstance(value, str):
        sanitized = value
        for pattern in REDACTION_PATTERNS:
            sanitized = pattern.sub("[REDACTED]", sanitized)
        return sanitized
    return value


def log_event(event: dict) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    event = sanitize_for_log(event)
    event["timestamp"] = datetime.now(timezone.utc).isoformat()

    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def read_recent_events(limit: int = 20) -> list[dict]:
    if limit < 1:
        return []

    if not LOG_FILE.exists():
        return []

    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    recent_lines = lines[-limit:]
    structured = []

    for line in recent_lines:
        if not line.strip():
            continue

        event = json.loads(line)
        security_analysis = event.get("security_analysis", {})
        council_summary = event.get("council_review", {}).get("council_summary", {})

        structured.append(
            {
                "timestamp": event.get("timestamp"),
                "mode": event.get("mode"),
                "source_type": event.get("untrusted_source_type"),
                "injection_detected": security_analysis.get("injection_detected"),
                "severity": security_analysis.get("severity"),
                "decision": council_summary.get("decision"),
                "average_confidence": council_summary.get("average_confidence"),
            }
        )

    return list(reversed(structured))
