from __future__ import annotations

import unittest

from detectionforge.api import healthz, home


class DashboardTests(unittest.TestCase):
    def test_dashboard_contains_core_sections_and_rules(self):
        page = home()
        self.assertIn("Ship detections with evidence, not intuition.", page)
        self.assertIn("Release scorecard", page)
        self.assertIn("MITRE ATT&amp;CK map", page)
        self.assertIn("Analyst feedback", page)
        self.assertIn("df-entra-001", page)
        self.assertIn("df-endpoint-001", page)

    def test_health_endpoint_reports_loaded_fixture(self):
        payload = healthz()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["rules"], 3)
        self.assertGreater(payload["events"], 0)


if __name__ == "__main__":
    unittest.main()
