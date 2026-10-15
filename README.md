# AI RiskSentinel — Integrated Project

AI RiskSentinel combines authorized TCP/IP port scanning, explainable risk scoring, offline network-flow analysis, local indicator-of-compromise (IOC) matching, optional Isolation Forest anomaly detection, and a Next.js dashboard in one connected project.

> **Current status:** This is a student MVP. Port-scan risk scores are rule-based. The optional Isolation Forest feature analyzes supplied flow data for relative anomalies; it is not a trained threat classifier. An open port or generated alert is not proof of a vulnerability or malicious activity.

## Main file structure

```text
AI_RiskSentinel_Integrated/
├── frontend/                 # Next.js + React + TypeScript dashboard
│   └── app/                  # Dashboard and styles
├── backend/                  # FastAPI service
│   ├── app/                  # API, TCP scanner, risk rules, flow engine, scope checks
│   ├── data/                 # Sample network-flow CSV and local IOC list
│   ├── tests/                # Backend tests
│   └── requirements.txt      # Python dependencies
├── README.md
└── .gitignore
```

## Requirements

- Python 3.11 or newer recommended
- Node.js 20 or newer
- npm

## Run on Windows (PowerShell)

### 1. Start the backend

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 2. Start the frontend in a second terminal

```powershell
cd frontend
npm install
Copy-Item .env.example .env.local
npm run dev
```

Open `http://localhost:3000`.

## Feature 1 — TCP/IP port scanning and risk analysis

1. Run a service you own locally, for example `py -m http.server 8000 --bind 127.0.0.1` in another terminal.
2. In the dashboard, set Target IP to `127.0.0.1` and Approved CIDR to `127.0.0.1/32`.
3. Enter ports such as `8000,8080`, then run the assessment.
4. Review open ports, evidence, severity, risk score, and recommendations. Export JSON or CSV.

The API only accepts literal private, loopback, or link-local IP targets included in the explicit CIDR allowlist. Keep the backend bound to `127.0.0.1`; only scan systems you own or have explicit permission to assess.

## Feature 2 — Network-flow risk analysis

The dashboard's **Network flow risk analysis** panel accepts CSV flow records and checks for:

- Possible port sweeps and traffic spikes using explainable rules
- Matches against IP indicators supplied with the API request
- Optional Isolation Forest anomaly scoring when enough distinct sources are present
- Evidence, risk scores, severity, and recommended investigation actions

Required CSV columns:

```csv
timestamp,src_ip,dst_ip,dst_port,protocol,bytes,packets,duration
2026-10-15T08:00:00Z,192.168.1.10,192.168.1.20,443,TCP,1200,12,0.4
```

The dashboard starts with a small editable example. You can paste your own authorized or synthetic flow records. This is offline analysis of supplied CSV, not live packet capture.

## API routes

- `GET /api/health` — backend health check
- `POST /api/scan` — authorized single-host TCP port assessment
- `POST /api/analyze-flows` — analyze supplied CSV flow data
- `POST /api/export/json` — export port assessment report
- `POST /api/export/csv` — export port findings

Interactive API docs: `http://127.0.0.1:8000/docs`.

## Tests

From the `backend` folder, install requirements and run:

```powershell
python -m pytest
```

## Limitations and future scope

- No exploitation, credential attacks, or live traffic capture.
- No CVE validation or guarantee that an exposed service is vulnerable.
- Rule-based port risk scoring is not a trained AI model.
- Optional unsupervised anomaly detection is a relative signal and needs context.
- Future work could add authorized asset inventory, trusted vulnerability-intelligence feeds, richer baselines, and authenticated deployment controls.
