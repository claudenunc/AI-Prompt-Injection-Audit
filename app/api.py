import os

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from app.audit_logger import read_recent_events
from app.firewall import run_firewall
from app.report_generator import build_report_content, generate_report
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
