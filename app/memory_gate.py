import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


MEMORY_LEDGER = Path("data/memory_ledger.jsonl")


def make_checksum(record: dict) -> str:
    clean = dict(record)
    clean.pop("checksum", None)
    payload = json.dumps(clean, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def propose_memory(content: str, source_type: str, approved_by_human: bool = False) -> dict:
    record = {
        "memory_id": f"mem_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        "content": content,
        "source_type": source_type,
        "approved_by_human": approved_by_human,
        "status": "approved" if approved_by_human and source_type == "direct_user" else "rejected",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reason": "",
    }

    if source_type != "direct_user":
        record["reason"] = "Rejected: only direct user statements can become memory."
    elif not approved_by_human:
        record["reason"] = "Rejected: human approval required."
    else:
        record["reason"] = "Approved: direct user source and human approval present."

    record["checksum"] = make_checksum(record)
    return record


def write_memory_if_allowed(record: dict) -> bool:
    if record.get("status") != "approved":
        return False

    MEMORY_LEDGER.parent.mkdir(parents=True, exist_ok=True)

    with MEMORY_LEDGER.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")

    return True
