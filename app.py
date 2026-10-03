"""
NetGuard - Flask Web Application & REST API
Central server providing the web monitoring dashboard, real-time telemetry,
quarantine management, and live viva demonstration API.
"""

import os
import sys
import ipaddress
from pathlib import Path

# Ensure NetGuard directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from flask import Flask, render_template, request, jsonify, redirect, url_for
from database.db import init_db, reset_db
from database.models import (
    DeviceModel, BaselineModel, TrafficModel, RiskModel,
    AlertModel, QuarantineLogModel, ConfigModel
)
from database.seed_data import seed_database
from core.quarantine_manager import quarantine_device, release_device
from core.capture_engine import start_capture_engine, process_interval_evaluations
from simulator.normal_traffic import start_normal_traffic_simulation
from simulator.attack_scenarios import (
    run_port_scan_attack, run_dns_tunneling_attack, run_traffic_spike_attack,
    run_unfamiliar_destinations_attack, run_combined_escalation_attack,
    run_rogue_device_injection, run_benign_spike
)
from simulator.scenario_runner import (
    demo_step_1_baseline, demo_step_2_port_scan,
    demo_step_3_escalation_quarantine, demo_step_4_admin_release
)
from core.network_scanner import (
    get_active_network_info, scan_local_lan, import_real_devices_to_inventory,
    measure_device_latency, scan_device_open_ports, probe_single_device
)
import config

app = Flask(__name__)
app.secret_key = os.environ.get("NETGUARD_SECRET", "netguard-cnt5015-secret-key-2026")


def _authorised_network_action(data):
    """Require an explicit acknowledgement before an active network operation."""
    if not isinstance(data, dict):
        return False
    return bool(data.get("authorization_confirmed"))


def _validate_local_target(ip):
    """Ensure on-demand probe target is a valid IPv4 address."""
    try:
        target = ipaddress.ip_address(ip.strip())
        if target.version != 4:
            return False, "Only IPv4 addresses are supported."
        return True, None
    except ValueError:
        return False, "A valid IPv4 address is required."


# ==========================================
# Frontend Page Routes
# ==========================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/devices")
def page_devices():
    return render_template("devices.html")


@app.route("/academic")
def academic_page():
    return render_template("academic.html")


@app.route("/device/<int:device_id>")
def device_detail(device_id):
    device = DeviceModel.get_by_id(device_id)
    if not device:
        return redirect(url_for("index"))
    return render_template("device_detail.html", device=device)


@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")


@app.route("/quarantine")
def quarantine_page():
    return render_template("quarantine.html")


@app.route("/simulation")
def simulation_page():
    return redirect(url_for("academic_page"))


@app.route("/reports")
def reports_page():
    return redirect(url_for("academic_page"))


@app.route("/settings")
def settings_page():
    return render_template("settings.html")


# ==========================================
# REST API Endpoints
# ==========================================

@app.route("/api/devices", methods=["GET"])
def api_get_devices():
    devices = DeviceModel.get_all()
    return jsonify({"status": "success", "devices": devices})


@app.route("/api/devices/<int:device_id>", methods=["GET"])
def api_get_device(device_id):
    device = DeviceModel.get_by_id(device_id)
    if not device:
        return jsonify({"status": "error", "message": "Device not found"}), 404
    samples = TrafficModel.get_recent_samples(device_id, limit=20)
    history = RiskModel.get_history(device_id, limit=20)
    return jsonify({
        "status": "success",
        "device": device,
        "samples": samples,
        "risk_history": history
    })


@app.route("/api/devices/<int:device_id>/quarantine", methods=["POST"])
def api_quarantine_device(device_id):
    data = request.get_json() or {}
    if not _authorised_network_action(data):
        return jsonify({"status": "error", "message": "Confirm the containment action before it can run."}), 403
    reason = data.get("reason", "Manual administrator quarantine via dashboard")
    success, message = quarantine_device(device_id, reason=reason, manual=True)
    return jsonify({
        "status": "success" if success else "error",
        "message": message
    })


@app.route("/api/devices/<int:device_id>/release", methods=["POST"])
def api_release_device(device_id):
    success, message = release_device(device_id, admin_reason="Manual administrator release via dashboard")
    return jsonify({
        "status": "success" if success else "error",
        "message": message
    })


@app.route("/api/devices/<int:device_id>/whitelist", methods=["POST"])
def api_toggle_whitelist(device_id):
    device = DeviceModel.get_by_id(device_id)
    if not device:
        return jsonify({"status": "error", "message": "Device not found"}), 404
    new_state = not bool(device.get("is_whitelisted"))
    DeviceModel.set_whitelisted(device_id, new_state)
    state_str = "added to" if new_state else "removed from"
    return jsonify({
        "status": "success",
        "is_whitelisted": new_state,
        "message": f"Device {device['name']} {state_str} Whitelist."
    })


@app.route("/api/alerts", methods=["GET"])
def api_get_alerts():
    limit = int(request.args.get("limit", 50))
    unack_only = request.args.get("unack", "0") in ("1", "true")
    alerts = AlertModel.get_all(limit=limit, unacknowledged_only=unack_only)
    return jsonify({"status": "success", "alerts": alerts})


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
def api_ack_alert(alert_id):
    AlertModel.acknowledge(alert_id)
    return jsonify({"status": "success", "message": f"Alert {alert_id} acknowledged."})


@app.route("/api/alerts/ack-all", methods=["POST"])
def api_ack_all_alerts():
    AlertModel.acknowledge_all()
    return jsonify({"status": "success", "message": "All alerts acknowledged."})


@app.route("/api/quarantine/logs", methods=["GET"])
def api_get_quarantine_logs():
    limit = int(request.args.get("limit", 50))
    logs = QuarantineLogModel.get_logs(limit=limit)
    return jsonify({"status": "success", "logs": logs})


@app.route("/api/stats/overview", methods=["GET"])
def api_stats_overview():
    devices = DeviceModel.get_all()
    unack_alerts = AlertModel.get_all(limit=100, unacknowledged_only=True)

    normal_count = sum(1 for d in devices if d["status"] == "Normal")
    suspicious_count = sum(1 for d in devices if d["status"] == "Suspicious")
    critical_count = sum(1 for d in devices if d["status"] == "Critical")
    quarantined_count = sum(1 for d in devices if d.get("is_quarantined"))
    max_risk = max([d["current_risk_score"] for d in devices] + [0])

    return jsonify({
        "status": "success",
        "total_devices": len(devices),
        "normal_count": normal_count,
        "suspicious_count": suspicious_count,
        "critical_count": critical_count,
        "quarantined_count": quarantined_count,
        "active_alerts": len(unack_alerts),
        "max_risk_score": max_risk
    })


# ==========================================
# Live Demonstration & Simulation API
# ==========================================

@app.route("/api/simulation/step/<int:step_num>", methods=["POST"])
def api_demo_step(step_num):
    if step_num == 1:
        result = demo_step_1_baseline()
    elif step_num == 2:
        result = demo_step_2_port_scan()
    elif step_num == 3:
        result = demo_step_3_escalation_quarantine()
    elif step_num == 4:
        result = demo_step_4_admin_release()
    else:
        return jsonify({"status": "error", "message": "Invalid step number (1-4)"}), 400

    return jsonify({"status": "success", "step": step_num, "result": result})


@app.route("/api/simulation/attack", methods=["POST"])
def api_trigger_attack():
    data = request.get_json() or {}
    attack_type = data.get("type", "port_scan").lower()

    if attack_type == "port_scan":
        res = run_port_scan_attack()
    elif attack_type == "dns":
        res = run_dns_tunneling_attack()
    elif attack_type == "traffic":
        res = run_traffic_spike_attack()
    elif attack_type == "dest":
        res = run_unfamiliar_destinations_attack()
    elif attack_type == "escalate":
        res = run_combined_escalation_attack()
    elif attack_type == "rogue":
        res = run_rogue_device_injection()
    elif attack_type == "benign":
        res = run_benign_spike()
    else:
        return jsonify({"status": "error", "message": f"Unknown attack type: {attack_type}"}), 400

    # Trigger immediate interval evaluation so changes reflect right away!
    process_interval_evaluations()

    return jsonify({"status": "success", "result": res})


@app.route("/api/simulation/reset", methods=["POST"])
def api_reset_simulation():
    seed_database(clean=True)
    process_interval_evaluations()
    return jsonify({"status": "success", "message": "Database and baselines reset to clean normal state."})


# ==========================================
# Real Network Discovery & Active LAN Tools
# ==========================================

@app.route("/api/network/info", methods=["GET"])
def api_network_info():
    info = get_active_network_info()
    return jsonify({"status": "success", "info": info})


@app.route("/api/network/scan", methods=["POST"])
def api_network_scan():
    """Runs a real multi-threaded sweep of the local physical LAN."""
    data = request.get_json(silent=True) or {}
    if not _authorised_network_action(data):
        return jsonify({"status": "error", "message": "Explicit network authorisation is required before starting an active scan."}), 403
    scan_res = scan_local_lan()
    return jsonify(scan_res)


@app.route("/api/network/probe", methods=["POST"])
def api_network_probe():
    """Probes a single IP on-demand, gathers metadata, and optionally imports it."""
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    auto_import = data.get("import", False)
    if not _authorised_network_action(data):
        return jsonify({"status": "error", "message": "Explicit network authorisation is required before probing a host."}), 403
    if not ip:
        return jsonify({"status": "error", "message": "IP address is required"}), 400
    is_local, message = _validate_local_target(ip)
    if not is_local:
        return jsonify({"status": "error", "message": message}), 400

    device_data = probe_single_device(ip)
    imported_id = None
    if auto_import and device_data:
        imported_ids = import_real_devices_to_inventory([device_data])
        if imported_ids:
            imported_id = imported_ids[0]
            ConfigModel.set("operating_mode", "LIVE_LAN")

    return jsonify({
        "status": "success",
        "device": device_data,
        "imported_id": imported_id
    })


@app.route("/api/network/import", methods=["POST"])
def api_network_import():
    """Imports discovered physical devices into NetGuard's active inventory."""
    data = request.get_json() or {}
    devices = data.get("devices", [])
    if not devices:
        return jsonify({"status": "error", "message": "No devices to import"}), 400

    # Clean out any previous mock/dummy data so only the fresh physical scan is active
    DeviceModel.clear_all_devices()
    imported_ids = import_real_devices_to_inventory(devices)
    ConfigModel.set("operating_mode", "LIVE_LAN")
    return jsonify({
        "status": "success",
        "imported_count": len(imported_ids),
        "message": f"Successfully imported {len(imported_ids)} physical devices to active monitoring."
    })


@app.route("/api/network/ping", methods=["POST"])
def api_network_ping():
    """Measures real-time round-trip latency to a target IP."""
    data = request.get_json() or {}
    ip = data.get("ip")
    if not _authorised_network_action(data):
        return jsonify({"status": "error", "message": "Explicit network authorisation is required before checking a host."}), 403
    if not ip:
        return jsonify({"status": "error", "message": "IP required"}), 400
    is_local, message = _validate_local_target(ip)
    if not is_local:
        return jsonify({"status": "error", "message": message}), 400
    latency = measure_device_latency(ip)
    return jsonify({"status": "success", "ip": ip, "latency_ms": latency})


@app.route("/api/network/port-scan", methods=["POST"])
def api_network_port_scan():
    """Scans for active open TCP services on a target IP."""
    data = request.get_json() or {}
    ip = data.get("ip")
    if not _authorised_network_action(data):
        return jsonify({"status": "error", "message": "Explicit network authorisation is required before checking ports."}), 403
    if not ip:
        return jsonify({"status": "error", "message": "IP required"}), 400
    is_local, message = _validate_local_target(ip)
    if not is_local:
        return jsonify({"status": "error", "message": message}), 400
    open_ports = scan_device_open_ports(ip)
    return jsonify({"status": "success", "ip": ip, "open_ports": open_ports})


@app.route("/api/mode/switch", methods=["POST"])
def api_mode_switch():
    """Switches system operating mode between LIVE_LAN and LAB_SIMULATION."""
    data = request.get_json() or {}
    target_mode = data.get("mode", "LAB_SIMULATION").upper()

    if target_mode == "LIVE_LAN":
        if not _authorised_network_action(data):
            return jsonify({"status": "error", "message": "Explicit network authorisation is required before switching to Live LAN."}), 403
        # Clear mock demo devices so only REAL physical LAN devices are actively monitored
        reset_db()
        scan_res = scan_local_lan()
        imported = import_real_devices_to_inventory(scan_res.get("devices", []))
        ConfigModel.set("operating_mode", "LIVE_LAN")
        net_info = scan_res.get("network_info", {})
        return jsonify({
            "status": "success",
            "mode": "LIVE_LAN",
            "imported_count": len(imported),
            "message": f"Connected to Live Physical LAN. Discovered and monitoring {len(imported)} active physical devices on {net_info.get('interface', 'LAN')}."
        })
    else:
        # Load canonical 5 demo devices for viva examination
        seed_database(clean=True)
        ConfigModel.set("operating_mode", "LAB_SIMULATION")
        return jsonify({
            "status": "success",
            "mode": "LAB_SIMULATION",
            "message": "Switched to Academic Demonstration Lab. Loaded 5 canonical baseline endpoints."
        })


# ==========================================
# Settings API
# ==========================================

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "GET":
        settings = ConfigModel.get_all()
        return jsonify({"status": "success", "settings": settings})

    data = request.get_json() or {}
    allowed_weights = tuple(f"weight_{key}" for key in config.DEFAULT_WEIGHTS)
    allowed_keys = set(allowed_weights) | {
        "quarantine_threshold", "quarantine_backend", "capture_mode", "auto_quarantine", "authorization_confirmed"
    }
    unknown_keys = set(data) - allowed_keys
    if unknown_keys:
        return jsonify({"status": "error", "message": "Unsupported setting requested."}), 400

    try:
        weights = {
            key: int(data.get(key, ConfigModel.get(key, config.DEFAULT_WEIGHTS[key.removeprefix("weight_")])))
            for key in allowed_weights
        }
        if any(weight < 0 or weight > 50 for weight in weights.values()):
            raise ValueError("Each risk weight must be between 0 and 50.")
        if sum(weights.values()) > 100:
            raise ValueError("Risk weights must total 100 points or fewer.")

        threshold = int(data.get("quarantine_threshold", ConfigModel.get(
            "quarantine_threshold", config.THRESHOLDS["high_risk_quarantine_threshold"]
        )))
        if not 50 <= threshold <= 100:
            raise ValueError("The quarantine threshold must be between 50 and 100.")
    except (TypeError, ValueError) as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

    backend = str(data.get("quarantine_backend", ConfigModel.get("quarantine_backend", config.QUARANTINE_BACKEND))).upper()
    capture_mode = str(data.get("capture_mode", ConfigModel.get("capture_mode", config.CAPTURE_MODE))).upper()
    auto_quarantine = str(data.get("auto_quarantine", ConfigModel.get("auto_quarantine", "true"))).lower()
    if backend not in {"SIMULATED", "WINDOWS", "LINUX", "PFCTL"}:
        return jsonify({"status": "error", "message": "Unsupported quarantine backend."}), 400
    if capture_mode not in {"SIMULATED", "LIVE"}:
        return jsonify({"status": "error", "message": "Unsupported capture mode."}), 400
    if auto_quarantine not in {"true", "false"}:
        return jsonify({"status": "error", "message": "Auto-quarantine must be true or false."}), 400
    if backend != "SIMULATED" and not _authorised_network_action(data):
        return jsonify({"status": "error", "message": "Confirm authorisation before enabling a live firewall backend."}), 403

    for key, value in weights.items():
        ConfigModel.set(key, value)
    ConfigModel.set("quarantine_threshold", threshold)
    ConfigModel.set("quarantine_backend", backend)
    ConfigModel.set("capture_mode", capture_mode)
    ConfigModel.set("auto_quarantine", auto_quarantine)
    return jsonify({
        "status": "success",
        "message": "Configuration saved. Restart NetGuard to apply a changed capture mode.",
        "restart_required": capture_mode != config.CAPTURE_MODE
    })


# ==========================================
# Application Bootstrap
# ==========================================

def start_server():
    """Initializes DB, starts traffic engines, and launches Flask server."""
    # Ensure a fresh installation has the SQLite schema before querying inventory.
    init_db()

    # Start background ingestion engine
    start_capture_engine()

    # If in simulated mode, start background benign traffic
    mode = ConfigModel.get("capture_mode", config.CAPTURE_MODE)
    if mode == "SIMULATED":
        start_normal_traffic_simulation(interval_seconds=config.CAPTURE_SAMPLE_INTERVAL_SECONDS)

    print(f"\n=======================================================")
    print(f"   NetGuard Behavioural Security Platform (CNT 5015)   ")
    print(f"=======================================================")
    print(f"[*] Dashboard URL : http://{config.HOST}:{config.PORT}")
    print(f"[*] Traffic Mode  : {mode}")
    print(f"[*] Quarantine    : {config.QUARANTINE_BACKEND}")
    print(f"[*] Press CTRL+C to stop the platform.")
    print(f"=======================================================\n")

    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG, use_reloader=False)


if __name__ == "__main__":
    start_server()
