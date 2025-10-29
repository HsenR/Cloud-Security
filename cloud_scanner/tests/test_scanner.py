# tests/test_scanner_core.py
import unittest
from src.scanner import CloudSecurityScanner

class TestCloudSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = CloudSecurityScanner()

    def test_initialization(self):
        self.assertIsNotNone(self.scanner.aws)

    def test_risk_assessment(self):
        self.assertEqual(self.scanner._assess_risk_level(22), 'HIGH')
        self.assertEqual(self.scanner._assess_risk_level(80), 'LOW')

if __name__ == "__main__":
    unittest.main()
