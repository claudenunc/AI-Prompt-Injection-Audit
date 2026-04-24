from app.audit_logger import log_event
from app.context_labeler import LabeledContext
from app.injection_detector import detect_injection
from app.siblings.council import run_council_review


VALID_MODES = {"strict", "relaxed"}


def safe_summarize_without_llm(untrusted_content: str) -> str:
    """
    Temporary local summarizer for tonight.
    This proves the firewall works before adding an LLM.
    """
    cleaned_lines = []

    dangerous_phrases = [
        "ignore previous instructions",
        "disregard previous instructions",
        "reveal the system prompt",
        "send api keys",
        "send me api keys",
        "delete logs",
        "disable logging",
        "bypass safety",
    ]

    for line in untrusted_content.splitlines():
        lowered = line.lower()
        if any(phrase in lowered for phrase in dangerous_phrases):
            continue
        if line.strip():
            cleaned_lines.append(line.strip())

    if not cleaned_lines:
        return "No safe factual content found after removing hostile instructions."

    return " ".join(cleaned_lines[:5])


def run_firewall(
    user_instruction: str,
    untrusted_content: str,
    untrusted_source_type: str = "web_content",
    mode: str = "relaxed",
) -> dict:
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Expected one of: {sorted(VALID_MODES)}")

    labeled = LabeledContext(
        trusted_instruction=user_instruction,
        untrusted_content=untrusted_content,
        untrusted_source_type=untrusted_source_type,
    )

    finding = detect_injection(untrusted_content)
    if mode == "strict" and finding.detected:
        safe_output = "[BLOCKED] Prompt injection detected. Content was not processed."
    else:
        safe_output = safe_summarize_without_llm(untrusted_content)

    result = {
        "safe_output": safe_output,
        "mode": mode,
        "security_analysis": {
            "injection_detected": finding.detected,
            "severity": finding.severity,
            "matches": finding.matches,
            "reason": finding.reason,
            "action_taken": "blocked_embedded_instruction" if finding.detected else "no_block_needed",
        },
        "labeled_context": labeled.build(),
    }
    council = run_council_review(result)
    result["council_review"] = council

    log_event(
        {
            "event_type": "firewall_run",
            "user_instruction": user_instruction,
            "untrusted_source_type": untrusted_source_type,
            "mode": mode,
            "security_analysis": result["security_analysis"],
            "council_review": result["council_review"],
        }
    )

    return result
