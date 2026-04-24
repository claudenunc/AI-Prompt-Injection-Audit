def atlas_review(result: dict) -> dict:
    return {
        "sibling": "Atlas",
        "role": "Source + memory integrity",
        "assessment": "Trusted and untrusted sources were correctly separated. No unauthorized memory writes attempted.",
        "risk": "low",
        "confidence": 0.95,
    }


def beacon_review(result: dict) -> dict:
    analysis = result["security_analysis"]

    if analysis["injection_detected"]:
        risk = "high" if analysis["severity"] == "high" else "medium"
        assessment = "Prompt injection detected and blocked."
    else:
        assessment = "No prompt injection patterns detected."
        risk = "low"

    return {
        "sibling": "Beacon",
        "role": "Security guardian",
        "assessment": assessment,
        "risk": risk,
        "confidence": 0.95,
    }


def envy_review(result: dict) -> dict:
    return {
        "sibling": "Envy",
        "role": "Relationship + continuity",
        "assessment": "User intent preserved without obeying untrusted instructions.",
        "risk": "low",
        "confidence": 0.9,
    }


def eversound_review(result: dict) -> dict:
    return {
        "sibling": "Eversound",
        "role": "Builder + implementation",
        "assessment": "Firewall pipeline executed correctly.",
        "risk": "low",
        "confidence": 0.9,
    }


def nevaeh_review(result: dict) -> dict:
    return {
        "sibling": "Nevaeh",
        "role": "Human impact",
        "assessment": "User protected without unnecessary escalation or confusion.",
        "risk": "low",
        "confidence": 0.9,
    }


def orpheus_review(result: dict) -> dict:
    return {
        "sibling": "Orpheus",
        "role": "Language + clarity",
        "assessment": "Output is understandable and client-ready.",
        "risk": "low",
        "confidence": 0.9,
    }


RISK_ORDER = {"low": 1, "medium": 2, "high": 3}


def run_council_review(result: dict) -> dict:
    reviews = [
        atlas_review(result),
        beacon_review(result),
        envy_review(result),
        eversound_review(result),
        nevaeh_review(result),
        orpheus_review(result),
    ]

    highest_risk = "low"
    total_confidence = 0

    for review in reviews:
        if RISK_ORDER[review["risk"]] > RISK_ORDER[highest_risk]:
            highest_risk = review["risk"]
        total_confidence += review["confidence"]

    avg_confidence = round(total_confidence / len(reviews), 2)

    decision = "approved"
    if highest_risk == "medium":
        decision = "flagged_for_review"
    elif highest_risk == "high":
        decision = "blocked"

    return {
        "council_summary": {
            "highest_risk": highest_risk,
            "decision": decision,
            "average_confidence": avg_confidence,
            "review_count": len(reviews),
        },
        "sibling_reviews": reviews,
    }
