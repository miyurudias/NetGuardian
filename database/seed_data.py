"""
NetGuard - Seed Data Generator
Pre-populates the 5 canonical devices and baseline profiles from the project proposal.
(Laptop 01, Phone 01, Printer, Laptop 02, CCTV)
"""

import sys
import json
from pathlib import Path

# Ensure NetGuard root is in python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import get_db, init_db, reset_db
from database.models import DeviceModel, BaselineModel, ConfigModel
import config

BENIGN_EXTERNAL_IPS = [
    "142.250.190.46", "172.217.16.206", "104.16.132.229",
    "20.112.52.29", "52.95.120.67"
]

CANONICAL_DEVICES = [
    {
        "name": "Laptop 01 (Staff Workstation)",
        "ip": "192.168.1.10",
        "mac": "00:1A:2B:3C:4D:01",
        "device_type": "Laptop",
        "is_whitelisted": True,
        "baseline": {
            "dns_queries_avg": 35.0,
            "distinct_ips_avg": 10.0,
            "ports_contacted_avg": 4.0,
            "bytes_transferred_kb_avg": 250.0
        },
        "known_dest_ips": BENIGN_EXTERNAL_IPS + ["8.8.8.8"]
    },
    {
        "name": "Phone 01 (Staff Mobile)",
        "ip": "192.168.1.15",
        "mac": "00:1A:2B:3C:4D:02",
        "device_type": "Phone",
        "is_whitelisted": False,
        "baseline": {
            "dns_queries_avg": 25.0,
            "distinct_ips_avg": 8.0,
            "ports_contacted_avg": 3.0,
            "bytes_transferred_kb_avg": 120.0
        },
        "known_dest_ips": BENIGN_EXTERNAL_IPS[:3] + ["1.1.1.1"]
    },
    {
        "name": "Printer (Office Network Printer)",
        "ip": "192.168.1.20",
        "mac": "00:1A:2B:3C:4D:03",
        "device_type": "Printer",
        "is_whitelisted": False,
        "baseline": {
            "dns_queries_avg": 2.0,
            "distinct_ips_avg": 1.0,
            "ports_contacted_avg": 2.0,
            "bytes_transferred_kb_avg": 45.0
        },
        "known_dest_ips": []
    },
    {
        "name": "Laptop 02 (Student Lab Laptop)",
        "ip": "192.168.1.45",
        "mac": "00:1A:2B:3C:4D:04",
        "device_type": "Laptop",
        "is_whitelisted": False,
        "baseline": {
            "dns_queries_avg": 25.0,
            "distinct_ips_avg": 4.0,
            "ports_contacted_avg": 4.0,
            "bytes_transferred_kb_avg": 200.0
        },
        "known_dest_ips": BENIGN_EXTERNAL_IPS + ["8.8.8.8"]
    },
    {
        "name": "CCTV (Security Camera Unit)",
        "ip": "192.168.1.50",
        "mac": "00:1A:2B:3C:4D:05",
        "device_type": "CCTV",
        "is_whitelisted": False,
        "baseline": {
            "dns_queries_avg": 1.0,
            "distinct_ips_avg": 1.0,
            "ports_contacted_avg": 1.0,
            "bytes_transferred_kb_avg": 850.0
        },
        "known_dest_ips": []
    }
]


def seed_database(clean=False, capture_mode_override=None):
    """Populates database with canonical baseline devices and default configuration."""
    if clean:
        reset_db()
    else:
        init_db()

    # Seed Default Configurations
    for key, weight in config.DEFAULT_WEIGHTS.items():
        if clean or ConfigModel.get(f"weight_{key}") is None:
            ConfigModel.set(f"weight_{key}", weight, f"Risk weight for {key}")

    defaults = {
        "auto_quarantine": "true",
        "quarantine_threshold": str(config.THRESHOLDS["high_risk_quarantine_threshold"]),
        "capture_mode": capture_mode_override or config.CAPTURE_MODE,
        "quarantine_backend": "SIMULATED",
        "operating_mode": "LAB_SIMULATION",
    }
    for key, value in defaults.items():
        if clean or ConfigModel.get(key) is None:
            ConfigModel.set(key, value)
    from core.capture_engine import set_operating_mode
    set_operating_mode("LAB_SIMULATION")

    # Seed Devices & Baselines
    created_ids = []
    for dev in CANONICAL_DEVICES:
        existing = DeviceModel.get_by_mac(dev["mac"])
        if not existing:
            dev_id = DeviceModel.create(
                mac=dev["mac"],
                ip=dev["ip"],
                name=dev["name"],
                device_type=dev["device_type"],
                is_whitelisted=dev["is_whitelisted"]
            )
            b = dev["baseline"]
            BaselineModel.update_baseline(
                device_id=dev_id,
                dns_avg=b["dns_queries_avg"],
                ips_avg=b["distinct_ips_avg"],
                ports_avg=b["ports_contacted_avg"],
                bytes_kb_avg=b["bytes_transferred_kb_avg"],
                increment_sample=False
            )
            BaselineModel.add_known_destinations(dev_id, dev["known_dest_ips"])
            # Set sample_count to 50 to signify established profile
            with get_db() as conn:
                conn.execute("UPDATE baselines SET sample_count = 50, is_locked = 1 WHERE device_id = ?", (dev_id,))
            created_ids.append(dev_id)
        else:
            baseline = BaselineModel.get_by_device(existing["id"])
            if baseline and baseline["is_locked"] and not baseline["known_dest_ips"] and dev["known_dest_ips"]:
                with get_db() as conn:
                    conn.execute("UPDATE baselines SET known_dest_ips = ? WHERE device_id = ?", (
                        json.dumps(dev["known_dest_ips"]), existing["id"]
                    ))
            created_ids.append(existing["id"])

    print(f"[+] Database seeded successfully with {len(created_ids)} canonical devices.")
    return created_ids


if __name__ == "__main__":
    seed_database(clean=True)
