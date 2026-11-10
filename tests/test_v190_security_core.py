import unittest
import v190_modules as v

class V190Tests(unittest.TestCase):
    def test_capabilities_are_honest(self):
        c=v.capabilities()
        self.assertFalse(c["sandbox"]["executes_samples"])
        self.assertFalse(c["privacy"]["guarantees_anonymity"])
        self.assertFalse(c["traffic_lab"]["network_io"])

    def test_ai_detects_secret_and_shell(self):
        r=v.ai_security_advice("API_KEY = 'abcdef123456'\nos.system(user_input)")
        ids={x["rule"] for x in r["findings"]}
        self.assertIn("possible-hardcoded-secret",ids)
        self.assertIn("shell-injection-risk",ids)

    def test_capacity_simulation_no_network(self):
        r=v.simulate_capacity(1000,100,10,20)
        self.assertFalse(r["network_io"])
        self.assertEqual(r["offered_rps"],100)

    def test_capacity_bounds(self):
        with self.assertRaises(ValueError): v.simulate_capacity(999999,100,10,20)

    def test_virtual_fleet_is_bounded(self):
        r=v.simulate_virtual_fleet(20,10)
        self.assertEqual(r["synthetic_total_events"],200)
        with self.assertRaises(ValueError): v.simulate_virtual_fleet(201,10)

    def test_web_headers_review(self):
        r=v.web_hardening_review({"content-security-policy":"default-src 'self'"})
        self.assertEqual(r["checks"],6)
        self.assertEqual(len(r["missing"]),5)

    def test_privacy_audit(self):
        r=v.privacy_exposure_audit("Mozilla/5.0 (Windows NT 10.0) Chrome/120",{"via":"proxy"})
        self.assertGreaterEqual(r["signal_count"],2)
        self.assertIn("Không có chế độ",r["guarantee"])

    def test_static_sandbox_never_executes(self):
        r=v.sandbox_static_inspect("import os\nos.system('whoami')\neval('1+1')")
        self.assertFalse(r["executed"])
        self.assertGreaterEqual(len(r["findings"]),2)

    def test_input_type_and_size(self):
        with self.assertRaises(ValueError): v.ai_security_advice(123)
        with self.assertRaises(ValueError): v.sandbox_static_inspect("x"*50001)

if __name__ == "__main__":
    unittest.main()
