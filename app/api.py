from fastapi import FastAPI
from pydantic import BaseModel

from app.audit_logger import read_recent_events
from app.firewall import run_firewall
from app.report_generator import build_report_content, generate_report


app = FastAPI(title="AI Prompt Injection Firewall")


class FirewallRequest(BaseModel):
    user_instruction: str
    untrusted_content: str
    source_type: str = "web_content"
    mode: str = "strict"
    client_name: str = "Demo Client"
    generate_report: bool = False


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AI Prompt Injection Firewall",
        "version": "0.1.0",
    }


@app.get("/history")
def history_endpoint(limit: int = 10):
    normalized_limit = max(1, min(limit, 100))
    events = read_recent_events(normalized_limit)
    return {
        "count": len(events),
        "events": events,
    }


@app.post("/firewall")
def firewall_endpoint(req: FirewallRequest):
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
