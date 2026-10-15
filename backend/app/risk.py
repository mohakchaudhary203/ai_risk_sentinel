def build_findings(target: str, scan: list[dict]):
    findings = []
    higher_review_ports = {21, 23, 445, 6379}
    for item in scan:
        if item["state"] != "open":
            continue
        port = item["port"]
        service = item["service"]
        if port in higher_review_ports:
            score, severity, confidence = 45, "medium", "medium"
            title = f"Review exposed service: {service} (TCP/{port})"
            recommendation = "Confirm business need, restrict access, and verify secure authentication/configuration."
            category = "exposure_review"
        else:
            score, severity, confidence = 25, "low", "high"
            title = f"Exposed service: {service} (TCP/{port})"
            recommendation = "Confirm the service is required, limit access, and keep it patched."
            category = "exposed_service"
        findings.append({
            "target": target, "title": title, "category": category,
            "port": port, "service": service, "risk_score": score,
            "severity": severity, "confidence": confidence,
            "evidence": f"TCP connection succeeded to {target}:{port}",
            "recommendation": recommendation,
            "risk_method": "explainable_rules_v1"
        })
    return sorted(findings, key=lambda f: f["risk_score"], reverse=True)
