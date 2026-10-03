"""Run reproducible synthetic scenarios and write per-run evidence.

This evaluates the simulator and detection pipeline, not live-network accuracy or
firewall isolation. A temporary SQLite database is used for every invocation.
"""

import argparse
import csv
import json
import os
import random
import tempfile
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="Run-level CSV path")
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be at least 1")

    with tempfile.TemporaryDirectory(prefix="netguardian-evaluation-") as workdir:
        os.environ["NETGUARD_DB"] = str(Path(workdir) / "lab.db")
        os.environ["NETGUARD_MODE"] = "SIMULATED"

        from database.seed_data import seed_database
        from database.models import AlertModel, DeviceModel
        from core.capture_engine import process_interval_evaluations
        from simulator.normal_traffic import generate_single_benign_cycle
        from simulator.attack_scenarios import (
            run_port_scan_attack, run_dns_tunneling_attack, run_traffic_spike_attack,
            run_unfamiliar_destinations_attack, run_combined_escalation_attack,
            run_rogue_device_injection, run_benign_spike
        )

        cases = (
            ("normal", None, None, False, "00:1A:2B:3C:4D:04"),
            ("port_scan", run_port_scan_attack, "Port Scanning Detected", False, "00:1A:2B:3C:4D:04"),
            ("dns_volume", run_dns_tunneling_attack, "DNS Anomaly / Tunneling", False, "00:1A:2B:3C:4D:04"),
            ("traffic_spike", run_traffic_spike_attack, "Traffic Volume Spike", False, "00:1A:2B:3C:4D:04"),
            ("destinations", run_unfamiliar_destinations_attack, "Unfamiliar External Destinations", False, "00:1A:2B:3C:4D:04"),
            ("combined", run_combined_escalation_attack, "Port Scanning Detected", True, "00:1A:2B:3C:4D:04"),
            ("rogue", run_rogue_device_injection, "Unknown / Rogue Device", False, "00:50:56:C0:00:08"),
            ("benign_update", run_benign_spike, None, False, "00:1A:2B:3C:4D:01"),
        )
        rows = []
        for repetition in range(1, args.repetitions + 1):
            for name, scenario, expected_indicator, expected_quarantine, mac in cases:
                random.seed(1000 * repetition + len(rows))
                seed_database(clean=True)
                started = time.perf_counter()
                if scenario:
                    scenario()
                else:
                    generate_single_benign_cycle()
                process_interval_evaluations()
                elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

                device = DeviceModel.get_by_mac(mac)
                indicators = {alert["indicator"] for alert in AlertModel.get_all(limit=100)}
                detected = expected_indicator in indicators if expected_indicator else not indicators
                quarantined = bool(device["is_quarantined"]) if device else False
                rows.append({
                    "source": "synthetic_simulation",
                    "scenario": name,
                    "repetition": repetition,
                    "expected_indicator": expected_indicator or "none",
                    "indicator_matched": detected,
                    "expected_simulated_quarantine": expected_quarantine,
                    "simulated_quarantine": quarantined,
                    "risk_score": device["current_risk_score"] if device else "missing_device",
                    "processing_elapsed_ms": elapsed_ms,
                    "passed": detected and quarantined == expected_quarantine,
                })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "source": "synthetic_simulation",
        "runs": len(rows),
        "passed": sum(row["passed"] for row in rows),
        "failed": sum(not row["passed"] for row in rows),
        "note": "Processing duration is local software time, not live capture or network isolation latency.",
    }
    summary_path = args.output.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
