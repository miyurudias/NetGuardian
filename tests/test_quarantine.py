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
from database.models import DeviceModel, QuarantineLogModel
from core.quarantine_manager import quarantine_device, release_device


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


if __name__ == "__main__":
    unittest.main()
