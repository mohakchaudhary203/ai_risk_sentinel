from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

REQUIRED = {"timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "packets", "duration"}
FEATURES = ["connections", "unique_dst_ports", "unique_dst_ips", "total_bytes", "total_packets", "mean_duration", "failed_like_ratio"]


def load_flows(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = REQUIRED - set(df.columns)
    if missing:
        raise ValueError(f"Missing required CSV columns: {', '.join(sorted(missing))}")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    if df["timestamp"].isna().any():
        raise ValueError("Every timestamp must be parseable; use ISO-8601 timestamps.")
    for col in ["dst_port", "bytes", "packets", "duration"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
        if df[col].isna().any() or (df[col] < 0).any():
            raise ValueError(f"Column {col} must contain non-negative numeric values.")
    for col in ["src_ip", "dst_ip"]:
        df[col] = df[col].astype(str).str.strip()
        for ip in df[col]:
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address in {col}: {ip}") from exc
    df["protocol"] = df["protocol"].astype(str).str.upper()
    df["dst_port"] = df["dst_port"].astype(int)
    return df.sort_values("timestamp").reset_index(drop=True)


def load_iocs(path: str | Path | None) -> set[str]:
    if not path or not Path(path).exists():
        return set()
    result = set()
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            result.add(str(ipaddress.ip_address(value)))
        except ValueError:
            # Fail closed for malformed intelligence entries: ignore and continue.
            continue
    return result


def _alert(src_ip: str, kind: str, points: int, evidence: str, timestamp: str) -> dict[str, Any]:
    score = max(0, min(100, int(points)))
    severity = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"
    return {"timestamp": timestamp, "src_ip": src_ip, "type": kind, "risk_score": score,
            "severity": severity, "evidence": evidence, "recommended_action": _recommend(score, kind)}


def _recommend(score: int, kind: str) -> str:
    if "threat_intel" in kind:
        return "Validate the indicator against trusted sources; review related events and consider containment under local policy."
    if "port_scan" in kind:
        return "Inspect source context and destination logs; rate-limit or block only if confirmed and authorized."
    if "traffic_spike" in kind:
        return "Compare with the normal baseline and check service health before taking action."
    if "ml_anomaly" in kind:
        return "Review the contributing flow records; anomaly scores are leads, not proof of malicious activity."
    return "Investigate associated flows and correlate with firewall, endpoint, and authentication logs."


def analyze(df: pd.DataFrame, iocs: set[str] | None = None, enable_ml: bool = True) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    iocs = iocs or set()
    alerts: list[dict[str, Any]] = []
    if df.empty:
        return alerts, {"flows_analyzed": 0, "sources_seen": 0, "ml_enabled": False}

    # Source-level summary; the fixed time window is suitable for a small offline MVP.
    src = df.groupby("src_ip").agg(
        connections=("src_ip", "size"), unique_dst_ports=("dst_port", "nunique"),
        unique_dst_ips=("dst_ip", "nunique"), total_bytes=("bytes", "sum"),
        total_packets=("packets", "sum"), mean_duration=("duration", "mean"),
        first_seen=("timestamp", "min"), last_seen=("timestamp", "max")
    ).reset_index()
    src["failed_like_ratio"] = 0.0  # Flow CSV has no connection outcome; auth failures need separate logs.

    # Explainable rules.
    for _, row in src.iterrows():
        ip = row["src_ip"]
        stamp = row["last_seen"].isoformat()
        if row["unique_dst_ports"] >= 12:
            alerts.append(_alert(ip, "possible_port_scan", 75 + min(20, int(row["unique_dst_ports"] - 12)),
                                 f"Source contacted {int(row['unique_dst_ports'])} distinct destination ports.", stamp))
        elif row["unique_dst_ports"] >= 6:
            alerts.append(_alert(ip, "port_sweep_suspected", 48,
                                 f"Source contacted {int(row['unique_dst_ports'])} distinct destination ports.", stamp))
        if row["connections"] >= 100:
            alerts.append(_alert(ip, "traffic_spike", 60 + min(30, int(row["connections"] / 20)),
                                 f"Source generated {int(row['connections'])} flows in the input period.", stamp))
        if ip in iocs:
            alerts.append(_alert(ip, "threat_intel_match", 95,
                                 "Source IP matched the configured local indicator list; verify indicator freshness and provenance.", stamp))

    ml_used = False
    ml_note = ""
    if enable_ml and len(src) >= 8:
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            import numpy as np
            X = src[FEATURES].astype(float).replace([np.inf, -np.inf], 0).fillna(0)
            Xs = StandardScaler().fit_transform(X)
            model = IsolationForest(n_estimators=150, contamination="auto", random_state=42)
            labels = model.fit_predict(Xs)
            scores = -model.decision_function(Xs)
            # Only flag the strongest relative outliers, avoiding arbitrary absolute score claims.
            threshold = float(np.quantile(scores, 0.90))
            for idx, label in enumerate(labels):
                if label == -1 and scores[idx] >= threshold:
                    row = src.iloc[idx]
                    alerts.append(_alert(row["src_ip"], "ml_anomaly", 45 + min(35, int(scores[idx] * 100)),
                                         f"Isolation Forest marked source behavior anomalous (relative anomaly score {scores[idx]:.3f}); review feature profile.",
                                         row["last_seen"].isoformat()))
            ml_used = True
        except ImportError:
            ml_note = "scikit-learn is not installed; rules and local IOC matching still ran. Install requirements.txt to enable ML."
    elif enable_ml:
        ml_note = "ML skipped: need at least 8 distinct source IPs for a minimally useful baseline."

    # Deduplicate same source/type while retaining the highest score.
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for item in alerts:
        key = (item["src_ip"], item["type"])
        if key not in unique or item["risk_score"] > unique[key]["risk_score"]:
            unique[key] = item
    output = sorted(unique.values(), key=lambda x: (x["risk_score"], x["timestamp"]), reverse=True)
    summary = {"flows_analyzed": int(len(df)), "sources_seen": int(df["src_ip"].nunique()),
               "alerts_generated": len(output), "ml_enabled": ml_used, "ml_note": ml_note,
               "time_range_start": df["timestamp"].min().isoformat(), "time_range_end": df["timestamp"].max().isoformat()}
    return output, summary


def save_results(alerts: list[dict[str, Any]], summary: dict[str, Any], output_dir: str | Path) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "alerts.json").write_text(json.dumps({"summary": summary, "alerts": alerts}, indent=2), encoding="utf-8")
    pd.DataFrame(alerts, columns=["timestamp", "src_ip", "type", "risk_score", "severity", "evidence", "recommended_action"]).to_csv(out / "alerts.csv", index=False)
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
