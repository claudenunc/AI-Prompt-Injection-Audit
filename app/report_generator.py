import json
from datetime import datetime
from pathlib import Path


REPORTS_DIR = Path("reports")


def generate_report(result: dict, client_name: str = "Demo Client") -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    report_path = REPORTS_DIR / f"prompt_injection_audit_{timestamp}.md"

    analysis = result["security_analysis"]

    content = f"""# AI Prompt Injection Audit Report

## Client
{client_name}

## Date
{datetime.now().isoformat()}

## Result
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

    report_path.write_text(content, encoding="utf-8")
    return report_path
