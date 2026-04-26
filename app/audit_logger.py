import json
from datetime import datetime, timezone
from pathlib import Path


LOG_FILE = Path("logs/security_events.jsonl")


def log_event(event: dict) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    event["timestamp"] = datetime.now(timezone.utc).isoformat()

    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def read_recent_events(limit: int = 10) -> list[dict]:
    if limit < 1:
        return []

    if not LOG_FILE.exists():
        return []

    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    recent_lines = lines[-limit:]
    events = []

    for line in reversed(recent_lines):
        if not line.strip():
            continue

        event = json.loads(line)
        security_analysis = event.get("security_analysis", {})
        council_summary = event.get("council_review", {}).get("council_summary", {})

        events.append(
            {
                "timestamp": event.get("timestamp"),
                "mode": event.get("mode"),
                "source_type": event.get("untrusted_source_type"),
                "injection_detected": security_analysis.get("injection_detected"),
                "severity": security_analysis.get("severity"),
                "decision": council_summary.get("decision"),
                "highest_risk": council_summary.get("highest_risk"),
                "user_instruction": event.get("user_instruction"),
            }
        )

    return events
