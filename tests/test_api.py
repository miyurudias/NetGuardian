"""
NetGuard Unit Tests - Flask REST API Endpoints
Verifies web API responses for devices, alerts, simulation steps, and settings.
"""

import unittest
import json
import sys
import os
from unittest.mock import patch
from pathlib import Path

# Add NetGuard root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app
from database.seed_data import seed_database
from database.models import ConfigModel, DeviceModel


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

    def test_report_shows_recorded_simulation_source(self):
        response = self.client.get("/reports")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"synthetic", response.data.lower())

    def test_favicon_is_served(self):
        response = self.client.get("/favicon.ico", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<svg", response.data)
        response.close()

    def test_scanner_explains_live_capture_requirement(self):
        dashboard = self.client.get("/")
        academic = self.client.get("/academic")
        self.assertIn(b"scan-capture-notice", dashboard.data)
        self.assertIn(b"live-mode-help", academic.data)

    def test_import_refuses_without_live_capture_and_preserves_demo_inventory(self):
        ConfigModel.set("capture_mode", "SIMULATED")
        before = len(DeviceModel.get_all())
        response = self.client.post("/api/network/import", json={
            "authorization_confirmed": True,
            "devices": [{"ip": "192.168.1.99", "mac": "AA:BB:CC:DD:EE:99", "name": "Host", "device_type": "Laptop"}]
        })
        self.assertEqual(response.status_code, 409)
        self.assertIn("Live capture", response.json["message"])
        self.assertEqual(len(DeviceModel.get_all()), before)

    def test_mode_status_reports_capture_state(self):
        response = self.client.get("/api/mode/status")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["operating_mode"], "LAB_SIMULATION")
        self.assertIn("ready", response.json["capture"])
        self.assertIn("boot_id", response.json)
        self.assertIn("restart_available", response.json)

    def test_restart_requires_supervised_launcher_and_confirmation(self):
        with patch.dict(os.environ, {"NETGUARD_SUPERVISED": ""}):
            response = self.client.post("/api/system/restart", json={"authorization_confirmed": True})
            self.assertEqual(response.status_code, 409)
        with patch.dict(os.environ, {"NETGUARD_SUPERVISED": "1"}):
            response = self.client.post("/api/system/restart", json={})
            self.assertEqual(response.status_code, 403)

    def test_restart_requests_child_exit_after_response(self):
        with patch.dict(os.environ, {"NETGUARD_SUPERVISED": "1"}), \
             patch("app.threading.Thread") as worker:
            response = self.client.post("/api/system/restart", json={"authorization_confirmed": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "success")
        worker.return_value.start.assert_called_once()

    def test_saving_live_capture_reports_restart_required(self):
        ConfigModel.set("capture_mode", "SIMULATED")

    def test_switching_live_to_demo_saves_simulated_capture_and_requires_restart(self):
        ConfigModel.set("operating_mode", "LIVE_LAN")
        ConfigModel.set("capture_mode", "LIVE")
        try:
            with patch("app.live_capture_status", return_value={"runtime_mode": "LIVE", "ready": True, "error": None}):
                response = self.client.post("/api/mode/switch", json={
                    "mode": "LAB_SIMULATION", "authorization_confirmed": True
                })
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.json["restart_required"])
                status = self.client.get("/api/mode/status").json
            self.assertEqual(status["operating_mode"], "LAB_SIMULATION")
            self.assertEqual(status["capture_mode"], "SIMULATED")
            self.assertTrue(status["restart_required"])
            self.assertEqual(len(DeviceModel.get_all()), 5)
        finally:
            seed_database(clean=True)
        response = self.client.post("/api/settings", json={
            "capture_mode": "LIVE", "quarantine_backend": "SIMULATED",
            "authorization_confirmed": True
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["restart_required"])
        self.assertEqual(ConfigModel.get("capture_mode"), "LIVE")
        ConfigModel.set("capture_mode", "SIMULATED")

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

    def test_live_switch_refuses_simulated_capture_without_erasing_inventory(self):
        before = len(DeviceModel.get_all())
        response = self.client.post("/api/mode/switch", json={
            "mode": "LIVE_LAN", "authorization_confirmed": True
        })
        self.assertEqual(response.status_code, 409)
        self.assertEqual(len(DeviceModel.get_all()), before)
        self.assertEqual(ConfigModel.get("operating_mode"), "LAB_SIMULATION")

    def test_scenarios_refuse_live_mode(self):
        ConfigModel.set("operating_mode", "LIVE_LAN")
        for endpoint in ("/api/simulation/step/1", "/api/simulation/attack", "/api/simulation/reset"):
            response = self.client.post(endpoint, json={"type": "port_scan"})
            self.assertEqual(response.status_code, 409)
        self.assertEqual(len(DeviceModel.get_all()), 5)
        ConfigModel.set("operating_mode", "LAB_SIMULATION")

    def test_live_firewall_cannot_be_enabled_in_lab(self):
        response = self.client.post("/api/settings", json={
            "quarantine_backend": "WINDOWS", "authorization_confirmed": True
        })
        self.assertEqual(response.status_code, 409)
        self.assertEqual(ConfigModel.get("quarantine_backend"), "SIMULATED")

    def test_mode_switch_updates_capture_setting_and_separates_inventory(self):
        seed_database(clean=True)
        ConfigModel.set("capture_mode", "LIVE")
        scan_result = {
            "status": "success",
            "network_info": {"subnet": "10.20.30.0/24", "interface": "Wi-Fi"},
            "devices": [{
                "ip": "10.20.30.45", "mac": "AA:BB:CC:DD:EE:FF", "name": "Lab Host",
                "device_type": "Laptop", "is_gateway": False, "is_localhost": True
            }]
        }
        with patch("app.live_capture_status", return_value={"ready": True, "error": None, "runtime_mode": "LIVE"}), \
             patch("app.scan_local_lan", return_value=scan_result):
            live = self.client.post("/api/mode/switch", json={
                "mode": "LIVE_LAN", "authorization_confirmed": True
            })
            self.assertEqual(live.status_code, 200)
            self.assertEqual(len(DeviceModel.get_all()), 1)
            self.assertEqual(ConfigModel.get("operating_mode"), "LIVE_LAN")

            lab = self.client.post("/api/mode/switch", json={
                "mode": "LAB_SIMULATION", "authorization_confirmed": True
            })
        self.assertEqual(lab.status_code, 200)
        self.assertEqual(len(DeviceModel.get_all()), 5)
        self.assertEqual(ConfigModel.get("capture_mode"), "SIMULATED")
        self.assertTrue(lab.json["restart_required"])


if __name__ == "__main__":
    unittest.main()
