"""Tests for safe behavioural-baseline learning."""

import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from core.capture_engine import record_packet_event, process_interval_evaluations
from database.models import BaselineModel, DeviceModel
from database.seed_data import seed_database


class TestBaselineLearning(unittest.TestCase):
    def setUp(self):
        seed_database(clean=True)

    def test_clean_samples_lock_a_new_device_profile(self):
        """New endpoints learn only from clean samples and lock at the defined limit."""
        mac = "02:50:56:C0:00:09"
        ip = "192.168.1.99"

        for _ in range(config.BASELINE_LEARNING_SAMPLES):
            record_packet_event(mac, ip, "192.168.1.1", 443, "TCP", 1000)
            process_interval_evaluations()

        device = DeviceModel.get_by_mac(mac)
        baseline = BaselineModel.get_by_device(device["id"])

        self.assertEqual(baseline["sample_count"], config.BASELINE_LEARNING_SAMPLES)
        self.assertEqual(baseline["is_locked"], 1)


if __name__ == "__main__":
    unittest.main()
