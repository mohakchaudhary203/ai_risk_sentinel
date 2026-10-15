from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

CSV = """timestamp,src_ip,dst_ip,dst_port,protocol,bytes,packets,duration
2026-10-15T08:00:00Z,192.168.1.10,192.168.1.20,21,TCP,120,2,0.1
2026-10-15T08:00:01Z,192.168.1.10,192.168.1.20,22,TCP,130,2,0.1
2026-10-15T08:00:02Z,192.168.1.10,192.168.1.20,23,TCP,140,2,0.1
2026-10-15T08:00:03Z,192.168.1.10,192.168.1.20,25,TCP,150,2,0.1
2026-10-15T08:00:04Z,192.168.1.10,192.168.1.20,53,UDP,160,2,0.1
2026-10-15T08:00:05Z,192.168.1.10,192.168.1.20,80,TCP,170,2,0.1
"""

def test_flow_analysis_returns_summary_and_alerts():
    response = client.post("/api/analyze-flows", json={"csv_text": CSV, "ioc_ips": [], "enable_ml": False})
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["flows_analyzed"] == 6
    assert data["summary"]["sources_seen"] == 1
    assert any(alert["type"] == "port_sweep_suspected" for alert in data["alerts"])

def test_flow_analysis_rejects_invalid_ioc():
    response = client.post("/api/analyze-flows", json={"csv_text": CSV, "ioc_ips": ["not-an-ip"], "enable_ml": False})
    assert response.status_code == 400
