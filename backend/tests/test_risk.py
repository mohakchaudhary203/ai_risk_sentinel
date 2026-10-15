import unittest
from app.risk import build_findings

class RiskTests(unittest.TestCase):
    def test_only_open_ports_create_findings(self):
        rows = [
            {"port": 80, "service": "HTTP", "state": "open"},
            {"port": 22, "service": "SSH", "state": "closed_or_filtered"}
        ]
        findings = build_findings("127.0.0.1", rows)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["port"], 80)
    def test_higher_review_service(self):
        findings = build_findings("127.0.0.1", [
            {"port": 6379, "service": "Redis", "state": "open"}
        ])
        self.assertEqual(findings[0]["severity"], "medium")

if __name__ == "__main__":
    unittest.main()
