import unittest
from app.scope import parse_allowlist, validate_target

class ScopeTests(unittest.TestCase):
    def test_loopback_target_allowed(self):
        nets = parse_allowlist(["127.0.0.1/32"])
        self.assertEqual(str(validate_target("127.0.0.1", nets)), "127.0.0.1")
    def test_out_of_scope_rejected(self):
        nets = parse_allowlist(["127.0.0.1/32"])
        with self.assertRaises(ValueError):
            validate_target("127.0.0.2", nets)
    def test_public_cidr_rejected(self):
        with self.assertRaises(ValueError):
            parse_allowlist(["8.8.8.0/24"])

if __name__ == "__main__":
    unittest.main()
