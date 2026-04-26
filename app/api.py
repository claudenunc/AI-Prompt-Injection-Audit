import os

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from app.approval_queue import create_approval_item, list_approval_items, resolve_approval_item
from app.audit_logger import read_recent_events, read_recent_log_entries
from app.firewall import run_firewall
from app.report_generator import (
    build_report_content,
    build_session_report_content,
    generate_report,
    generate_session_report,
)
from app.security import rate_limit_middleware, require_api_key


app = FastAPI(title="AI Prompt Injection Firewall")
app.middleware("http")(rate_limit_middleware)


class FirewallRequest(BaseModel):
    user_instruction: str
    untrusted_content: str
    source_type: str = "web_content"
    mode: str = "strict"
    client_name: str = "Demo Client"
    generate_report: bool = False


class SessionExportRequest(BaseModel):
    client_name: str = "Demo Client"
    session_title: str = "Audit Session"
    limit: int = 20


class ApprovalQueueRequest(BaseModel):
    client_name: str = "Demo Client"
    user_instruction: str
    source_type: str
    mode: str
    severity: str
    decision: str
    average_confidence: float | None = None
    safe_output: str
    reason: str = ""


class ApprovalResolutionRequest(BaseModel):
    status: str
    reviewer: str
    resolution_notes: str = ""


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AI Prompt Injection Firewall",
        "version": "0.1.0",
        "auth_enabled": bool(os.getenv("FIREWALL_API_KEY")),
    }


@app.get("/history")
def history_endpoint(limit: int = 10, _: None = Depends(require_api_key)):
    normalized_limit = max(1, min(limit, 100))
    return read_recent_events(normalized_limit)


@app.post("/session/export")
def session_export_endpoint(req: SessionExportRequest, _: None = Depends(require_api_key)):
    normalized_limit = max(1, min(req.limit, 100))
    events = read_recent_log_entries(normalized_limit)
    report_path = str(generate_session_report(events, req.client_name, req.session_title))
    report_content = build_session_report_content(events, req.client_name, req.session_title)
    report_filename = report_path.split("/")[-1].split("\\")[-1]

    return {
        "run_count": len(events),
        "report_path": report_path,
        "report_content": report_content,
        "report_filename": report_filename,
    }


@app.get("/approvals")
def approvals_endpoint(
    status: str = "pending",
    limit: int = 50,
    _: None = Depends(require_api_key),
):
    normalized_limit = max(1, min(limit, 100))
    normalized_status = None if status == "all" else status
    return list_approval_items(normalized_status, normalized_limit)


@app.post("/approvals")
def create_approval_endpoint(req: ApprovalQueueRequest, _: None = Depends(require_api_key)):
    item = create_approval_item(
        client_name=req.client_name,
        source_type=req.source_type,
        mode=req.mode,
        severity=req.severity,
        decision=req.decision,
        average_confidence=req.average_confidence,
        user_instruction=req.user_instruction,
        safe_output=req.safe_output,
        reason=req.reason,
    )
    return item


@app.post("/approvals/{approval_id}/resolve")
def resolve_approval_endpoint(
    approval_id: str,
    req: ApprovalResolutionRequest,
    _: None = Depends(require_api_key),
):
    try:
        return resolve_approval_item(
            approval_id=approval_id,
            status=req.status,
            reviewer=req.reviewer,
            resolution_notes=req.resolution_notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/firewall")
def firewall_endpoint(req: FirewallRequest, _: None = Depends(require_api_key)):
    result = run_firewall(
        user_instruction=req.user_instruction,
        untrusted_content=req.untrusted_content,
        untrusted_source_type=req.source_type,
        mode=req.mode,
    )

    report_path = None
    report_content = None
    report_filename = None
    if req.generate_report:
        report_path = str(generate_report(result, req.client_name))
        report_content = build_report_content(result, req.client_name)
        report_filename = report_path.split("/")[-1].split("\\")[-1]

    return {
        "safe_output": result["safe_output"],
        "mode": result["mode"],
        "security_analysis": result["security_analysis"],
        "council_review": result["council_review"],
        "report_path": report_path,
        "report_content": report_content,
        "report_filename": report_filename,
    }
