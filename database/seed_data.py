"""
NetGuard - Seed Data Generator
Pre-populates the 5 canonical devices and baseline profiles from the project proposal.
(Laptop 01, Phone 01, Printer, Laptop 02, CCTV)
"""

import sys
from pathlib import Path

# Ensure NetGuard root is in python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db import get_db, init_db, reset_db
from database.models import DeviceModel, BaselineModel, ConfigModel
import config

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
        }
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
        }
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
        }
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
        }
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
        }
    }
]


def seed_database(clean=False):
    """Populates database with canonical baseline devices and default configuration."""
    if clean:
        reset_db()
    else:
        init_db()

    # Seed Default Configurations
    for key, weight in config.DEFAULT_WEIGHTS.items():
        ConfigModel.set(f"weight_{key}", weight, f"Risk weight for {key}")

    ConfigModel.set("auto_quarantine", "true", "Automatic Quarantine on High Risk")
    ConfigModel.set("quarantine_threshold", str(config.THRESHOLDS["high_risk_quarantine_threshold"]))
    ConfigModel.set("capture_mode", config.CAPTURE_MODE)
    ConfigModel.set("quarantine_backend", config.QUARANTINE_BACKEND)

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
            # Set sample_count to 50 to signify established profile
            with get_db() as conn:
                conn.execute("UPDATE baselines SET sample_count = 50, is_locked = 1 WHERE device_id = ?", (dev_id,))
            created_ids.append(dev_id)
        else:
            created_ids.append(existing["id"])

    print(f"[+] Database seeded successfully with {len(created_ids)} canonical devices.")
    return created_ids


if __name__ == "__main__":
    seed_database(clean=True)
