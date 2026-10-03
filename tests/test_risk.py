"""
NetGuard Unit Tests - Risk Scoring Engine
Verifies weighted anomaly indicators and band transitions from Section 8.3 of proposal.
"""

import unittest
import sys
from pathlib import Path

# Add NetGuard root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.seed_data import seed_database
from database.models import DeviceModel, BaselineModel
from core.risk_engine import evaluate_device_risk


class TestRiskEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        seed_database(clean=True)

    def test_benign_traffic_low_risk(self):
        """Normal traffic within baseline should remain in Low risk (0 - 39)."""
        laptop1 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:01")
        baseline = BaselineModel.get_by_device(laptop1["id"])

        benign_sample = {
            "dns_count": 30,
            "distinct_ips_count": 8,
            "port_count": 3,
            "bytes_transferred_kb": 220.0
        }

        total_risk, band, status, rules, sub_scores = evaluate_device_risk(
            device=laptop1,
            current_sample=benign_sample,
            baseline=baseline
        )

        self.assertEqual(band, "Low")
        self.assertEqual(status, "Normal")
        self.assertLess(total_risk, 40)
        self.assertEqual(len(rules), 0)

    def test_port_scan_medium_risk(self):
        """Probing multiple ports triggers +30 indicator and elevates status to Suspicious."""
        laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
        baseline = BaselineModel.get_by_device(laptop2["id"])

        port_scan_sample = {
            "dns_count": 35,
            "distinct_ips_count": 6,
            "port_count": 28,  # Probing 28 ports (threshold >= 8)
            "bytes_transferred_kb": 250.0
        }

        total_risk, band, status, rules, sub_scores = evaluate_device_risk(
            device=laptop2,
            current_sample=port_scan_sample,
            baseline=baseline
        )

        self.assertEqual(sub_scores["port_scan"], 30)
        self.assertEqual(band, "Medium")
        self.assertEqual(status, "Suspicious")
        self.assertGreaterEqual(total_risk, 30)
        self.assertTrue(any("Port Scanning" in r["indicator"] for r in rules))

    def test_unprofiled_device_is_marked_for_review(self):
        """A device without a learned profile must not appear as normal."""
        device = {"device_type": "Unknown", "is_quarantined": False}
        baseline = {
            "dns_queries_avg": 15.0,
            "distinct_ips_avg": 4.0,
            "ports_contacted_avg": 3.0,
            "bytes_transferred_kb_avg": 100.0,
            "sample_count": 0
        }
        sample = {"dns_count": 10, "distinct_ips_count": 2, "port_count": 2, "bytes_transferred_kb": 50.0}

        total_risk, band, status, rules, _ = evaluate_device_risk(device, sample, baseline)

        self.assertEqual(total_risk, 20)
        self.assertEqual(band, "Medium")
        self.assertEqual(status, "Suspicious")
        self.assertTrue(any("Rogue" in rule["indicator"] for rule in rules))

    def test_multi_vector_escalation_critical(self):
        """Combined threats cross 70 point threshold and enter High / Critical band."""
        laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
        baseline = BaselineModel.get_by_device(laptop2["id"])

        critical_sample = {
            "dns_count": 180,           # DNS anomaly (+20)
            "distinct_ips_count": 16,   # Unfamiliar dest (+15)
            "port_count": 25,           # Port scan (+30)
            "bytes_transferred_kb": 2500.0  # Traffic spike (+15)
        }

        total_risk, band, status, rules, sub_scores = evaluate_device_risk(
            device=laptop2,
            current_sample=critical_sample,
            baseline=baseline
        )

        self.assertEqual(band, "High")
        self.assertEqual(status, "Critical")
        self.assertGreaterEqual(total_risk, 70)
        self.assertGreaterEqual(len(rules), 3)

    def test_unfamiliar_destinations_compare_addresses_not_just_count(self):
        laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
        baseline = BaselineModel.get_by_device(laptop2["id"])
        sample = {
            "dns_count": 0, "port_count": 1, "bytes_transferred_kb": 20,
            "distinct_ips_count": 3,
            "dest_ips": ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
        }
        score, _, _, rules, sub_scores = evaluate_device_risk(laptop2, sample, baseline)
        self.assertEqual(sub_scores["unfamiliar_dest"], 15)
        self.assertTrue(any(r["indicator"] == "Unfamiliar External Destinations" for r in rules))

        sample["dest_ips"] = baseline["known_dest_ips"][:3]
        _, _, _, _, known_scores = evaluate_device_risk(laptop2, sample, baseline)
        self.assertEqual(known_scores["unfamiliar_dest"], 0)


if __name__ == "__main__":
    unittest.main()
