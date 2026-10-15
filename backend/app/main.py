import csv
import io
import json
import ipaddress
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from app.scope import parse_allowlist, validate_target
from app.scanner import scan_ports
from app.risk import build_findings
from app.flow_engine import analyze as analyze_flows, load_flows, load_iocs

app = FastAPI(title="AI RiskSentinel API", version="0.1.0",
              description="Authorized-only private-lab security assessment MVP")

# Local development only. Keep backend bound to 127.0.0.1.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

class ScanRequest(BaseModel):
    target: str = Field(..., description="Literal private/loopback IP address")
    allow_cidr: list[str] = Field(..., min_length=1, max_length=8)
    ports: list[int] = Field(default_factory=lambda: [22, 80, 443, 8000, 8080], min_length=1, max_length=64)
    timeout: float = Field(default=0.5, ge=0.1, le=2.0)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports):
        if any(p < 1 or p > 65535 for p in ports):
            raise ValueError("Ports must be between 1 and 65535.")
        if len(set(ports)) != len(ports):
            raise ValueError("Duplicate ports are not allowed.")
        return ports

class ScanResponse(BaseModel):
    generated_at_utc: str
    target: str
    scan: list[dict]
    findings: list[dict]
    finding_count: int
    open_port_count: int
    limitations: list[str]

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "AI RiskSentinel API", "version": "0.1.0"}

@app.post("/api/scan", response_model=ScanResponse)
def run_scan(req: ScanRequest):
    try:
        networks = parse_allowlist(req.allow_cidr)
        target = validate_target(req.target, networks)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Limit each request to a single approved host and at most 64 explicitly supplied ports.
    scan = scan_ports(str(target), sorted(req.ports), req.timeout)
    findings = build_findings(str(target), scan)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "scan": scan,
        "findings": findings,
        "finding_count": len(findings),
        "open_port_count": sum(1 for row in scan if row["state"] == "open"),
        "limitations": [
            "Open ports are not proof of vulnerabilities.",
            "Risk scores are explainable heuristics, not trained AI predictions.",
            "This MVP does not confirm CVEs or perform exploitation."
        ]
    }

@app.post("/api/export/json")
def export_json(payload: dict):
    # Exports only client-supplied report data; no target scan is triggered here.
    raw = json.dumps(payload, indent=2)
    return StreamingResponse(io.BytesIO(raw.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="risksentinel-report.json"'})

@app.post("/api/export/csv")
def export_csv(payload: dict):
    findings = payload.get("findings", [])
    if not isinstance(findings, list) or any(not isinstance(x, dict) for x in findings):
        raise HTTPException(status_code=400, detail="Expected a findings array.")
    columns = ["target", "title", "category", "port", "service", "risk_score",
               "severity", "confidence", "evidence", "recommendation", "risk_method"]
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(findings)
    return StreamingResponse(iter([stream.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="risksentinel-findings.csv"'})


class FlowAnalysisRequest(BaseModel):
    csv_text: str = Field(..., min_length=20, max_length=1_000_000, description="CSV network-flow records")
    ioc_ips: list[str] = Field(default_factory=list, max_length=500)
    enable_ml: bool = True

    @field_validator("csv_text")
    @classmethod
    def validate_csv_text(cls, value):
        lines = value.splitlines()
        if not lines or "timestamp" not in lines[0] or "src_ip" not in lines[0]:
            raise ValueError("CSV header must include timestamp and src_ip columns.")
        if len(lines) > 5001:
            raise ValueError("Maximum 5,000 flow rows per analysis.")
        return value

@app.post("/api/analyze-flows")
def run_flow_analysis(req: FlowAnalysisRequest):
    # Offline flow analysis; this endpoint does not capture traffic or scan targets.
    try:
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "flows.csv"
            csv_path.write_text(req.csv_text, encoding="utf-8")
            df = load_flows(csv_path)
        ioc_file = Path(__file__).resolve().parent.parent / "data" / "ioc_ips.txt"
        iocs = load_iocs(ioc_file) if not req.ioc_ips else set()
        for raw in req.ioc_ips:
            try:
                iocs.add(str(ipaddress.ip_address(raw.strip())))
            except ValueError:
                raise ValueError(f"Invalid IOC IP address: {raw}")
        alerts, summary = analyze_flows(df, iocs, enable_ml=req.enable_ml)
        return {"summary": summary, "alerts": alerts, "limitations": [
            "Flow analysis depends on the supplied CSV data and does not capture live traffic.",
            "An alert is an investigation lead, not proof of malicious activity.",
            "Isolation Forest is an optional unsupervised anomaly detector, not a trained threat classifier."
        ]}
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
