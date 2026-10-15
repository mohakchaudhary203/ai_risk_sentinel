"use client";

import { FormEvent, useMemo, useState } from "react";

type ScanRow = { port: number; service: string; state: string };
type Finding = {
  target: string; title: string; category: string; port: number; service: string;
  risk_score: number; severity: string; confidence: string; evidence: string;
  recommendation: string; risk_method: string;
};
type FlowAlert = { timestamp: string; src_ip: string; type: string; risk_score: number; severity: string; evidence: string; recommended_action: string };
type FlowReport = { summary: { flows_analyzed: number; sources_seen: number; alerts_generated: number; ml_enabled: boolean; ml_note?: string }; alerts: FlowAlert[]; limitations: string[] };
type Report = {
  generated_at_utc: string; target: string; scan: ScanRow[]; findings: Finding[];
  finding_count: number; open_port_count: number; limitations: string[];
};

const API = process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000";

export default function Home() {
  const [target, setTarget] = useState("127.0.0.1");
  const [cidr, setCidr] = useState("127.0.0.1/32");
  const [ports, setPorts] = useState("22,80,443,8000,8080");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [flowBusy, setFlowBusy] = useState(false);
  const [flowError, setFlowError] = useState("");
  const [flowReport, setFlowReport] = useState<FlowReport | null>(null);
  const [flowCsv, setFlowCsv] = useState(`timestamp,src_ip,dst_ip,dst_port,protocol,bytes,packets,duration
2026-10-15T08:00:00Z,192.168.1.10,192.168.1.20,21,TCP,120,2,0.1
2026-10-15T08:00:01Z,192.168.1.10,192.168.1.20,22,TCP,130,2,0.1
2026-10-15T08:00:02Z,192.168.1.10,192.168.1.20,23,TCP,140,2,0.1
2026-10-15T08:00:03Z,192.168.1.10,192.168.1.20,25,TCP,150,2,0.1
2026-10-15T08:00:04Z,192.168.1.10,192.168.1.20,53,UDP,160,2,0.1
2026-10-15T08:00:05Z,192.168.1.10,192.168.1.20,80,TCP,170,2,0.1
2026-10-15T08:00:06Z,192.168.1.10,192.168.1.20,443,TCP,180,2,0.1`);

  const portList = useMemo(() => ports.split(",").map(x => x.trim()).filter(Boolean), [ports]);

  async function runAssessment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setReport(null);
    try {
      const parsedPorts = portList.map(Number);
      if (!parsedPorts.length || parsedPorts.some(p => !Number.isInteger(p) || p < 1 || p > 65535)) {
        throw new Error("Enter valid ports separated by commas, between 1 and 65535.");
      }
      if (parsedPorts.length > 64) throw new Error("MVP limit: 64 ports per assessment.");
      const response = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, allow_cidr: [cidr], ports: parsedPorts, timeout: 0.5 }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Assessment failed.");
      setReport(data as Report);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not connect to the API. Is the backend running?");
    } finally {
      setBusy(false);
    }
  }

  async function runFlowAnalysis() {
    setFlowBusy(true);
    setFlowError("");
    setFlowReport(null);
    try {
      const response = await fetch(`${API}/api/analyze-flows`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ csv_text: flowCsv, ioc_ips: [], enable_ml: true }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Flow analysis failed.");
      setFlowReport(data as FlowReport);
    } catch (err) {
      setFlowError(err instanceof Error ? err.message : "Could not connect to the API. Is the backend running?");
    } finally {
      setFlowBusy(false);
    }
  }

  function exportFlowReport() {
    if (!flowReport) return;
    const blob = new Blob([JSON.stringify(flowReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "risksentinel-flow-analysis.json";
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function exportReport(kind: "json" | "csv") {
    if (!report) return;
    try {
      const response = await fetch(`${API}/api/export/${kind}`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report),
      });
      if (!response.ok) throw new Error("Export failed.");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = kind === "json" ? "risksentinel-report.json" : "risksentinel-findings.csv";
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed.");
    }
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brandMark">RS</div>
        <div className="brandText"><strong>RISK<span>SENTINEL</span></strong><small>AUTHORIZED SECURITY ASSESSMENT</small></div>
        <div className="status"><i /> LOCAL LAB MODE</div>
      </header>

      <section className="hero">
        <p className="eyebrow">HYBRID OFFENSIVE SECURITY PLATFORM / MVP 0.1</p>
        <h1>Scan TCP ports.<br /><span>Analyze risk.</span></h1>
        <p className="subhead">TCP/IP port scanning plus explainable risk analysis for systems you own or are explicitly authorized to assess.</p>
      </section>

      <section className="grid">
        <div className="panel scanPanel">
          <div className="panelTitle"><div><span className="kicker">01 / ASSESSMENT</span><h2>Configure target</h2></div><span className="lock">SCOPE LOCKED</span></div>
          <form onSubmit={runAssessment}>
            <label>Target IP <span>Required</span><input value={target} onChange={e => setTarget(e.target.value)} placeholder="127.0.0.1" required /></label>
            <label>Approved CIDR <span>Must include target</span><input value={cidr} onChange={e => setCidr(e.target.value)} placeholder="127.0.0.1/32" required /></label>
            <label>TCP ports <span>Max 64</span><input value={ports} onChange={e => setPorts(e.target.value)} placeholder="22,80,443,8000,8080" required /></label>
            <div className="scopeNote"><b>Safety controls enabled</b><br />Private, loopback, and link-local targets only. Public targets and out-of-scope IPs are rejected by the API.</div>
            <button className="primary" disabled={busy}>{busy ? "ASSESSMENT RUNNING…" : "RUN AUTHORIZED ASSESSMENT"} <span>↗</span></button>
          </form>
          {error && <div className="error" role="alert">{error}</div>}
        </div>

        <div className="panel overviewPanel">
          <div className="panelTitle"><div><span className="kicker">02 / LIVE OVERVIEW</span><h2>Assessment summary</h2></div><span className="liveDot">● READY</span></div>
          <div className="metrics">
            <div className="metric"><small>OPEN PORTS</small><strong>{report?.open_port_count ?? "—"}</strong><span>Reachable TCP services</span></div>
            <div className="metric"><small>FINDINGS</small><strong>{report?.finding_count ?? "—"}</strong><span>Evidence-backed exposure</span></div>
            <div className="metric"><small>TARGET</small><strong className="targetMetric">{report?.target ?? "Not scanned"}</strong><span>Approved single host</span></div>
          </div>
          <div className="method"><span className="methodIcon">✳</span><div><b>Risk analysis</b><p>Each exposed TCP service receives an explainable risk score, severity, evidence, and remediation guidance. An open port alone is not proof of a vulnerability.</p></div></div>
          <div className="method"><span className="methodIcon">◎</span><div><b>TCP/IP port scanning</b><p>Checks selected TCP ports and labels common services · low concurrency · no exploitation or credential testing.</p></div></div>
        </div>
      </section>

      {report && <section className="panel results">
        <div className="panelTitle"><div><span className="kicker">03 / RESULTS</span><h2>Findings & evidence</h2></div><div className="exports"><button onClick={() => exportReport("json")}>EXPORT JSON ↓</button><button onClick={() => exportReport("csv")}>EXPORT CSV ↓</button></div></div>
        <p className="resultMeta">Target {report.target} · Generated {new Date(report.generated_at_utc).toLocaleString()}</p>
        {report.findings.length === 0 ? <div className="empty">No open TCP services were identified in the selected ports. This does not prove the host is secure.</div> :
          <div className="tableWrap"><table><thead><tr><th>PORT / SERVICE</th><th>FINDING</th><th>RISK</th><th>CONFIDENCE</th><th>RECOMMENDATION</th></tr></thead><tbody>
            {report.findings.map((f, i) => <tr key={`${f.port}-${i}`}><td><b>{f.port}</b><small>{f.service}</small></td><td><b>{f.title}</b><small>{f.evidence}</small></td><td><span className={`severity ${f.severity}`}>{f.severity.toUpperCase()}</span><small>{f.risk_score}/100</small></td><td>{f.confidence}</td><td>{f.recommendation}</td></tr>)}
          </tbody></table></div>}
        <div className="limitations"><b>Interpret results carefully</b>{report.limitations.map(x => <p key={x}>• {x}</p>)}</div>
      </section>}


      <section className="panel results flowPanel">
        <div className="panelTitle"><div><span className="kicker">04 / NETWORK TELEMETRY</span><h2>Network flow risk analysis</h2></div><span className="lock">OFFLINE CSV</span></div>
        <p className="subhead">Analyze supplied network-flow records for possible port sweeps, traffic spikes, local IOC matches, and optional anomaly detection. This does not capture live traffic.</p>
        <label>Network flow CSV <span>Max 5,000 rows · required headers shown below</span>
          <textarea className="flowInput" value={flowCsv} onChange={e => setFlowCsv(e.target.value)} rows={8} spellCheck={false} />
        </label>
        <div className="flowActions"><button className="primary" disabled={flowBusy} onClick={runFlowAnalysis}>{flowBusy ? "ANALYZING FLOWS…" : "ANALYZE NETWORK FLOWS ↗"}</button>{flowReport && <button onClick={exportFlowReport}>EXPORT FLOW REPORT ↓</button>}</div>
        {flowError && <div className="error" role="alert">{flowError}</div>}
        {flowReport && <>
          <div className="metrics flowMetrics">
            <div className="metric"><small>FLOWS ANALYZED</small><strong>{flowReport.summary.flows_analyzed}</strong><span>Rows in submitted CSV</span></div>
            <div className="metric"><small>SOURCES SEEN</small><strong>{flowReport.summary.sources_seen}</strong><span>Distinct source IPs</span></div>
            <div className="metric"><small>ALERTS</small><strong>{flowReport.summary.alerts_generated}</strong><span>{flowReport.summary.ml_enabled ? "Optional ML ran" : "Rule-based analysis"}</span></div>
          </div>
          {flowReport.summary.ml_note && <p className="resultMeta">{flowReport.summary.ml_note}</p>}
          {flowReport.alerts.length === 0 ? <div className="empty">No alert was produced by the current rules. This does not prove the traffic is safe.</div> :
            <div className="tableWrap"><table><thead><tr><th>SOURCE IP</th><th>ALERT</th><th>RISK</th><th>EVIDENCE</th><th>RECOMMENDED ACTION</th></tr></thead><tbody>
              {flowReport.alerts.map((a, i) => <tr key={`${a.src_ip}-${a.type}-${i}`}><td>{a.src_ip}</td><td><b>{a.type.replaceAll("_", " ")}</b><small>{new Date(a.timestamp).toLocaleString()}</small></td><td><span className={`severity ${a.severity}`}>{a.severity.toUpperCase()}</span><small>{a.risk_score}/100</small></td><td>{a.evidence}</td><td>{a.recommended_action}</td></tr>)}
            </tbody></table></div>}
          <div className="limitations"><b>Flow-analysis limitations</b>{flowReport.limitations.map(x => <p key={x}>• {x}</p>)}</div>
        </>}
      </section>

      <footer><span>RISK SENTINEL / STUDENT MVP</span><span>DEFENSIVE VALIDATION · AUTHORIZED SCOPE ONLY</span></footer>
    </main>
  );
}
