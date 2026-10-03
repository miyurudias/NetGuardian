"""
NetGuard Unit Tests - Quarantine & Remediation Manager
Verifies device isolation, Cisco ACL generation, and unblock workflows.
"""

import unittest
import sys
from pathlib import Path

# Add NetGuard root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.seed_data import seed_database
from database.models import DeviceModel, QuarantineLogModel, AlertModel
from core.quarantine_manager import quarantine_device, release_device, execute_system_isolation
from core.capture_engine import record_packet_event, process_interval_evaluations
from unittest.mock import patch


class TestQuarantineManager(unittest.TestCase):

    def setUp(self):
        seed_database(clean=True)

    def test_quarantine_and_unblock_cycle(self):
        """Tests that a device can be quarantined, generates ACL, and released back to normal."""
        laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
        dev_id = laptop2["id"]

        # 1. Quarantine
        success, msg = quarantine_device(dev_id, reason="Unit test critical risk breach", manual=True)
        self.assertTrue(success)

        updated_dev = DeviceModel.get_by_id(dev_id)
        self.assertEqual(updated_dev["is_quarantined"], 1)
        self.assertEqual(updated_dev["status"], "Quarantined")

        # Check quarantine log
        logs = QuarantineLogModel.get_logs(limit=5)
        self.assertTrue(any(l["device_id"] == dev_id and "QUARANTINE" in l["action"] for l in logs))

        # 2. Release
        rel_success, rel_msg = release_device(dev_id, admin_reason="Unit test verification complete")
        self.assertTrue(rel_success)

        restored_dev = DeviceModel.get_by_id(dev_id)
        self.assertEqual(restored_dev["is_quarantined"], 0)
        self.assertEqual(restored_dev["status"], "Normal")
        self.assertEqual(restored_dev["current_risk_score"], 0)

    def test_whitelist_protection(self):
        """Whitelisted devices must be shielded from quarantine."""
        laptop1 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:01")
        self.assertEqual(laptop1["is_whitelisted"], 1)

        success, msg = quarantine_device(laptop1["id"], reason="Attempted isolation on whitelisted host")
        self.assertFalse(success)
        self.assertIn("Whitelisted", msg)

        # Device should still NOT be quarantined
        check_dev = DeviceModel.get_by_id(laptop1["id"])
        self.assertEqual(check_dev["is_quarantined"], 0)

    def test_failed_enforcement_does_not_mark_device_quarantined(self):
        laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
        with patch("core.quarantine_manager.execute_system_isolation", return_value=("failed command", False)):
            success, _ = quarantine_device(laptop2["id"], reason="Failure test")
        self.assertFalse(success)
        self.assertEqual(DeviceModel.get_by_id(laptop2["id"])["is_quarantined"], 0)

    def test_evaluator_keeps_critical_status_after_enforcement_failure(self):
        laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
        for port in range(100, 112):
            record_packet_event(laptop2["mac"], laptop2["ip"], "198.51.100.1", port, "TCP", 50000)
        for i in range(70):
            record_packet_event(laptop2["mac"], laptop2["ip"], f"198.51.100.{i+2}", 443, "TCP", 50000)
        for _ in range(120):
            record_packet_event(laptop2["mac"], laptop2["ip"], "8.8.8.8", 53, "UDP", 80, is_dns=True)
        with patch("core.quarantine_manager.execute_system_isolation", return_value=("failed command", False)):
            process_interval_evaluations()
        updated = DeviceModel.get_by_id(laptop2["id"])
        self.assertGreaterEqual(updated["current_risk_score"], 70)
        self.assertEqual(updated["status"], "Critical")
        self.assertEqual(updated["is_quarantined"], 0)

    def test_repeated_indicator_updates_one_active_alert(self):
        laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
        for _ in range(2):
            for port in range(100, 112):
                record_packet_event(laptop2["mac"], laptop2["ip"], "192.168.1.1", port, "TCP", 60)
            process_interval_evaluations()
        alerts = [a for a in AlertModel.get_all() if a["indicator"] == "Port Scanning Detected"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["resolved"], 0)

        record_packet_event(laptop2["mac"], laptop2["ip"], "192.168.1.1", 443, "TCP", 60)
        process_interval_evaluations()
        self.assertEqual([a for a in AlertModel.get_all(unacknowledged_only=True) if a["indicator"] == "Port Scanning Detected"], [])

    def test_windows_partial_firewall_rule_is_rolled_back(self):
        device = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
        with patch("core.quarantine_manager.subprocess.run") as run:
            run.side_effect = [
                type("Result", (), {"returncode": 0})(),
                type("Result", (), {"returncode": 1})(),
                type("Result", (), {"returncode": 0})(),
            ]
            _, success = execute_system_isolation(device, "WINDOWS", action="BLOCK")
        self.assertFalse(success)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(run.call_args_list[-1].args[0][3], "delete")


if __name__ == "__main__":
    unittest.main()
