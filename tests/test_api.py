"""
NetGuard Unit Tests - Flask REST API Endpoints
Verifies web API responses for devices, alerts, simulation steps, and settings.
"""

import unittest
import json
import sys
from pathlib import Path

# Add NetGuard root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app
from database.seed_data import seed_database


class TestNetGuardAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        seed_database(clean=True)
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_get_devices(self):
        """GET /api/devices returns all canonical seeded devices."""
        response = self.client.get("/api/devices")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(len(data["devices"]), 5)

    def test_stats_overview(self):
        """GET /api/stats/overview returns correct aggregation stats."""
        response = self.client.get("/api/stats/overview")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")
        self.assertIn("total_devices", data)
        self.assertIn("max_risk_score", data)

    def test_viva_simulation_steps(self):
        """Tests live simulation endpoints for Steps 1 through 4."""
        # Step 1
        res1 = self.client.post("/api/simulation/step/1")
        self.assertEqual(res1.status_code, 200)

        # Step 2: Port Scan
        res2 = self.client.post("/api/simulation/step/2")
        self.assertEqual(res2.status_code, 200)
        data2 = json.loads(res2.data)
        self.assertEqual(data2["result"]["status"], "Suspicious")

        # Step 3: Escalation and Quarantine
        res3 = self.client.post("/api/simulation/step/3")
        self.assertEqual(res3.status_code, 200)
        data3 = json.loads(res3.data)
        self.assertTrue(data3["result"]["is_quarantined"])

        # Step 4: Admin Release
        res4 = self.client.post("/api/simulation/step/4")
        self.assertEqual(res4.status_code, 200)
        data4 = json.loads(res4.data)
        self.assertEqual(data4["result"]["status"], "Normal")

    def test_settings_reject_invalid_weight_total(self):
        """The configurable 100-point risk model must reject totals above 100."""
        response = self.client.post("/api/settings", json={
            "weight_port_scan": 50,
            "weight_unknown_device": 50,
            "weight_dns_anomaly": 50,
            "weight_traffic_spike": 15,
            "weight_unfamiliar_dest": 15,
            "quarantine_threshold": 70,
            "quarantine_backend": "SIMULATED",
            "capture_mode": "SIMULATED",
            "auto_quarantine": "true"
        })
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "error")

    def test_active_scan_requires_explicit_authorisation(self):
        """The scan route must fail closed before any network sweep begins."""
        response = self.client.post("/api/network/scan", json={})
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "error")


if __name__ == "__main__":
    unittest.main()
