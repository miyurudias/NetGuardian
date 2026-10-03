"""
NetGuard Unit Tests - Behaviour Drift Calculation
Verifies the mathematical drift model against Section 8.2 of the proposal.
"""

import unittest
import sys
from pathlib import Path

# Add NetGuard root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.drift_engine import calculate_metric_drift, compute_behavior_drift_score


class TestDriftEngine(unittest.TestCase):

    def test_benign_zero_drift(self):
        """Observed values below or equal to baseline produce 0% drift."""
        drift_pct, norm_score = calculate_metric_drift(observed=20, baseline=25)
        self.assertEqual(drift_pct, 0.0)
        self.assertEqual(norm_score, 0.0)

    def test_moderate_deviation(self):
        """Observed values moderately above baseline produce proportional drift."""
        drift_pct, norm_score = calculate_metric_drift(observed=50, baseline=25)
        self.assertEqual(drift_pct, 100.0)
        self.assertGreater(norm_score, 0.0)

    def test_proposal_worked_example_laptop_04(self):
        """
        Tests the exact worked example from Section 8.2 of proposal:
        Laptop-04:
        - DNS requests: Normal 40, Observed 300 (Drift ~650%)
        - Distinct remote IPs: Normal 12, Observed 85 (Drift ~608%)
        - Ports contacted: Normal 5, Observed 42 (Drift ~740%)
        - Data uploaded: Normal 50MB, Observed 900MB (Drift ~1700%)
        Proposal expected combined Behaviour Drift score: ~87%.
        """
        baseline = {
            "dns_queries_avg": 40.0,
            "distinct_ips_avg": 12.0,
            "ports_contacted_avg": 5.0,
            "bytes_transferred_kb_avg": 50.0 * 1024.0
        }

        current_sample = {
            "dns_count": 300,
            "distinct_ips_count": 85,
            "port_count": 42,
            "bytes_transferred_kb": 900.0 * 1024.0
        }

        drift_score, breakdown = compute_behavior_drift_score(current_sample, baseline)

        # Expected to be ~85-90% as described in Section 8.2 of the proposal
        self.assertGreaterEqual(drift_score, 80.0)
        self.assertLessEqual(drift_score, 95.0)
        self.assertIn("metrics", breakdown)
        self.assertGreater(breakdown["metrics"]["dns"]["drift_pct"], 600.0)
        self.assertGreater(breakdown["metrics"]["distinct_ips"]["drift_pct"], 550.0)
        self.assertGreater(breakdown["metrics"]["ports"]["drift_pct"], 700.0)


if __name__ == "__main__":
    unittest.main()
