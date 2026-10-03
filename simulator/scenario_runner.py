"""
NetGuard - Automated Live Demonstration Scenario Runner
Directly executes the 4-phase demonstration workflow from Section 15 of proposal.
"""

from database.seed_data import seed_database
from core.capture_engine import process_interval_evaluations, live_capture_status
from core.quarantine_manager import release_device
from simulator.normal_traffic import generate_single_benign_cycle
from simulator.attack_scenarios import (
    run_port_scan_attack,
    run_combined_escalation_attack,
    run_rogue_device_injection,
    run_benign_spike
)
from database.models import DeviceModel


def demo_step_1_baseline():
    """
    Step 1: Normal Network.
    5 devices connected and profiled, all in LOW risk on dashboard.
    """
    seed_database(clean=True, capture_mode_override=live_capture_status()["runtime_mode"])
    generate_single_benign_cycle()
    process_interval_evaluations()

    devices = DeviceModel.get_all()
    return {
        "step": 1,
        "title": "Normal Network Baseline",
        "description": "5 devices profiled. All devices in LOW risk (Green - Normal).",
        "devices_count": len(devices),
        "status": "success"
    }


def demo_step_2_port_scan():
    """
    Step 2: Controlled Attack Introduced.
    Port scan initiated against the network from Laptop 02.
    Dashboard shows Laptop 02 change status to SUSPICIOUS (Amber).
    """
    run_port_scan_attack()
    process_interval_evaluations()

    laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
    return {
        "step": 2,
        "title": "Controlled Port Scan Attack",
        "description": "Port scan detected from Laptop 02. Risk score increased by +30.",
        "target": laptop2["name"],
        "new_risk_score": laptop2["current_risk_score"],
        "status": laptop2["status"]
    }


def demo_step_3_escalation_quarantine():
    """
    Step 3: Escalation and Automatic Response.
    Threat escalated (DNS anomaly + unfamiliar destinations).
    Risk score crosses 70 (Critical) -> NetGuard triggers AUTOMATIC QUARANTINE!
    """
    run_combined_escalation_attack()
    process_interval_evaluations()

    laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
    return {
        "step": 3,
        "title": "Threat Escalation & Automatic Quarantine",
        "description": "Laptop 02 crossed the critical threshold. A simulated quarantine policy was recorded.",
        "target": laptop2["name"],
        "new_risk_score": laptop2["current_risk_score"],
        "is_quarantined": bool(laptop2["is_quarantined"]),
        "status": laptop2["status"],
        "quarantine_reason": laptop2["quarantine_reason"]
    }


def demo_step_4_admin_release():
    """
    Step 4: Administrator Remediation.
    Admin reviews alert, investigates device drift, and releases device from quarantine.
    """
    laptop2 = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
    if laptop2 and laptop2["is_quarantined"]:
        release_device(laptop2["id"], admin_reason="Admin verified device cleansed in lab demo")

    laptop2_updated = DeviceModel.get_by_mac("00:1A:2B:3C:4D:04")
    return {
        "step": 4,
        "title": "Administrator Remediation & Unblock",
        "description": "Device unblocked and restored to Normal monitoring state.",
        "target": laptop2_updated["name"],
        "new_risk_score": laptop2_updated["current_risk_score"],
        "status": laptop2_updated["status"]
    }
