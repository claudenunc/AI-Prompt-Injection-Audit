import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.audit_logger import sanitize_for_log


APPROVAL_QUEUE_FILE = Path("data/approval_queue.jsonl")
VALID_APPROVAL_STATUSES = {"pending", "approved", "rejected"}


def _read_queue_items() -> list[dict]:
    if not APPROVAL_QUEUE_FILE.exists():
        return []

    items = []
    for line in APPROVAL_QUEUE_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        items.append(json.loads(line))
    return items


def _write_queue_items(items: list[dict]) -> None:
    APPROVAL_QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with APPROVAL_QUEUE_FILE.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item) + "\n")


def create_approval_item(
    client_name: str,
    source_type: str,
    mode: str,
    severity: str,
    decision: str,
    average_confidence: float | None,
    user_instruction: str,
    safe_output: str,
    reason: str,
) -> dict:
    item = sanitize_for_log(
        {
            "approval_id": f"apr_{uuid4().hex[:12]}",
            "status": "pending",
            "client_name": client_name,
            "source_type": source_type,
            "mode": mode,
            "severity": severity,
            "decision": decision,
            "average_confidence": average_confidence,
            "user_instruction": user_instruction,
            "safe_output": safe_output,
            "reason": reason,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "resolved_at": None,
            "reviewer": None,
            "resolution_notes": None,
        }
    )
    items = _read_queue_items()
    items.append(item)
    _write_queue_items(items)
    return item


def list_approval_items(status: str | None = None, limit: int = 50) -> list[dict]:
    items = _read_queue_items()
    if status:
        items = [item for item in items if item.get("status") == status]
    return list(reversed(items[-limit:]))


def resolve_approval_item(
    approval_id: str,
    status: str,
    reviewer: str,
    resolution_notes: str = "",
) -> dict:
    if status not in {"approved", "rejected"}:
        raise ValueError("Resolution status must be 'approved' or 'rejected'.")

    items = _read_queue_items()
    for item in items:
        if item.get("approval_id") == approval_id:
            item["status"] = status
            item["reviewer"] = sanitize_for_log(reviewer)
            item["resolution_notes"] = sanitize_for_log(resolution_notes)
            item["resolved_at"] = datetime.now(timezone.utc).isoformat()
            _write_queue_items(items)
            return item

    raise KeyError(f"Approval item not found: {approval_id}")
