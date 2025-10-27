import unittest
from src.scanner import CloudSecurityScanner

class TestPhase1(unittest.TestCase):
    def setUp(self):
        self.scanner = CloudSecurityScanner()
    
    def test_initialization(self):
        self.assertIsNotNone(self.scanner.aws)
        self.assertEqual(len(self.scanner.inventory), 0)
        self.assertEqual(len(self.scanner.findings), 0)
    
    def test_risk_assessment(self):
        self.assertEqual(self.scanner._assess_risk_level(22), 'HIGH')
        self.assertEqual(self.scanner._assess_risk_level(80), 'LOW')

if __name__ == '__main__':
    unittest.main()