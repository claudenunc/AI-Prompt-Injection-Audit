TRUST_LEVELS = {
    "direct_user": 100,
    "signed_continuity_packet": 90,
    "approved_memory": 80,
    "local_file": 50,
    "web_content": 30,
    "email_content": 30,
    "unknown": 10,
}


def get_trust_level(source_type: str) -> int:
    return TRUST_LEVELS.get(source_type, TRUST_LEVELS["unknown"])


def can_override(source_a: str, source_b: str) -> bool:
    """
    Returns True if source_a is allowed to override source_b.
    """
    return get_trust_level(source_a) >= get_trust_level(source_b)
