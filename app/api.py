from fastapi import FastAPI
from pydantic import BaseModel

from app.firewall import run_firewall
from app.report_generator import generate_report


app = FastAPI(title="AI Prompt Injection Firewall")


class FirewallRequest(BaseModel):
    user_instruction: str
    untrusted_content: str
    source_type: str = "web_content"
    client_name: str = "Demo Client"
    generate_report: bool = False


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AI Prompt Injection Firewall",
        "version": "0.1.0",
    }


@app.post("/firewall")
def firewall_endpoint(req: FirewallRequest):
    result = run_firewall(
        user_instruction=req.user_instruction,
        untrusted_content=req.untrusted_content,
        untrusted_source_type=req.source_type,
    )

    report_path = None
    if req.generate_report:
        report_path = str(generate_report(result, req.client_name))

    return {
        "safe_output": result["safe_output"],
        "security_analysis": result["security_analysis"],
        "council_review": result["council_review"],
        "report_path": report_path,
    }
