import json
from collections import Counter
from datetime import datetime
from pathlib import Path


REPORTS_DIR = Path("reports")


def build_report_content(result: dict, client_name: str = "Demo Client") -> str:
    analysis = result["security_analysis"]

    return f"""# AI Prompt Injection Audit Report

## Client
{client_name}

## Date
{datetime.now().isoformat()}

## Result
**Mode:** {result.get("mode", "relaxed")}  
**Injection detected:** {analysis["injection_detected"]}  
**Severity:** {analysis["severity"]}  
**Action taken:** {analysis["action_taken"]}

## Findings
```json
{json.dumps(analysis, indent=2)}
```

## Sibling Council Review
```json
{json.dumps(result.get("council_review", {}), indent=2)}
```

## Safe Output
{result["safe_output"]}

## Recommendation
- Keep trusted user instructions separated from untrusted content.
- Never allow emails, websites, PDFs, or documents to directly issue commands to an AI agent.
- Route all tool use through a permission gate.
- Log all blocked injection attempts.
"""


def generate_report(result: dict, client_name: str = "Demo Client") -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    report_path = REPORTS_DIR / f"prompt_injection_audit_{timestamp}.md"
    content = build_report_content(result, client_name)

    report_path.write_text(content, encoding="utf-8")
    return report_path


def build_session_report_content(
    events: list[dict],
    client_name: str = "Demo Client",
    session_title: str = "Audit Session",
) -> str:
    severity_counts = Counter()
    decision_counts = Counter()
    pattern_counts = Counter()

    for event in events:
        analysis = event.get("security_analysis", {})
        council_summary = event.get("council_review", {}).get("council_summary", {})

        severity = analysis.get("severity", "unknown")
        decision = council_summary.get("decision", "unknown")
        severity_counts[severity] += 1
        decision_counts[decision] += 1

        for match in analysis.get("matches", []):
            pattern_counts[match] += 1

    top_patterns = pattern_counts.most_common(5)
    recent_runs = []
    for event in events:
        analysis = event.get("security_analysis", {})
        council_summary = event.get("council_review", {}).get("council_summary", {})
        recent_runs.append(
            "| {timestamp} | {mode} | {source_type} | {severity} | {decision} | {avg_confidence} |".format(
                timestamp=event.get("timestamp", ""),
                mode=event.get("mode", ""),
                source_type=event.get("untrusted_source_type", ""),
                severity=analysis.get("severity", ""),
                decision=council_summary.get("decision", ""),
                avg_confidence=council_summary.get("average_confidence", ""),
            )
        )

    pattern_lines = [
        f"- `{pattern}`: {count} occurrence(s)" for pattern, count in top_patterns
    ] or ["- No recurring injection patterns detected."]

    severity_lines = [
        f"- {severity}: {count}" for severity, count in sorted(severity_counts.items())
    ] or ["- No runs recorded."]

    decision_lines = [
        f"- {decision}: {count}" for decision, count in sorted(decision_counts.items())
    ] or ["- No decisions recorded."]

    recent_runs_table = "\n".join(recent_runs) or "| No runs | - | - | - | - | - |"

    recommendations = [
        "- Use `strict` mode for customer data, tools, memory, and automation workflows.",
        "- Use `relaxed` mode only for low-risk summarization tasks where extracted safe context is acceptable.",
        "- Review blocked or flagged sessions for repeated injection patterns and add targeted controls.",
        "- Keep API authentication enabled before sharing the hosted dashboard publicly.",
    ]

    return f"""# AI Prompt Injection Audit Session Report

## Session
{session_title}

## Client
{client_name}

## Date
{datetime.now().isoformat()}

## Summary
**Run count:** {len(events)}

### Severity Breakdown
{chr(10).join(severity_lines)}

### Decision Breakdown
{chr(10).join(decision_lines)}

## Top Recurring Patterns
{chr(10).join(pattern_lines)}

## Recent Runs
| Timestamp | Mode | Source Type | Severity | Decision | Avg Confidence |
| --- | --- | --- | --- | --- | --- |
{recent_runs_table}

## Recommended Fixes
{chr(10).join(recommendations)}
"""


def generate_session_report(
    events: list[dict],
    client_name: str = "Demo Client",
    session_title: str = "Audit Session",
) -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    report_path = REPORTS_DIR / f"audit_session_{timestamp}.md"
    content = build_session_report_content(events, client_name, session_title)

    report_path.write_text(content, encoding="utf-8")
    return report_path
