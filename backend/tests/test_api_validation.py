import unittest
from pydantic import ValidationError
from app.main import ScanRequest

class RequestValidationTests(unittest.TestCase):
    def test_rejects_invalid_port(self):
        with self.assertRaises(ValidationError):
            ScanRequest(target="127.0.0.1", allow_cidr=["127.0.0.1/32"], ports=[0])
    def test_rejects_too_many_ports(self):
        with self.assertRaises(ValidationError):
            ScanRequest(target="127.0.0.1", allow_cidr=["127.0.0.1/32"], ports=list(range(1, 66)))

if __name__ == "__main__":
    unittest.main()
