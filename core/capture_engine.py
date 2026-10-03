"""
NetGuard - Dual-Mode Traffic Ingestion Engine
Handles live packet capture via Scapy or synthetic lab traffic generation.
Aggregates per-device metrics and drives the Drift and Risk evaluation loop.
"""

import time
import threading
import ipaddress
from collections import defaultdict
from database.models import DeviceModel, BaselineModel, TrafficModel, RiskModel, AlertModel, ConfigModel
from core.device_profiler import process_device_observation
from core.drift_engine import compute_behavior_drift_score
from core.risk_engine import evaluate_device_risk
from core.quarantine_manager import quarantine_device
import config

# In-memory accumulator for current interval
_interval_lock = threading.Lock()
_device_accumulators = defaultdict(lambda: {
    "dns_count": 0,
    "distinct_ips": set(),
    "ports_contacted": set(),
    "bytes_sent": 0,
    "bytes_recv": 0,
    "is_new_device": False
})

_engine_running = False
_engine_thread = None
_live_capture_ready = threading.Event()
_live_capture_error = None
_local_network = ipaddress.ip_network(config.LOCAL_SUBNET, strict=False)
_operating_mode = "LAB_SIMULATION"
_capture_mode_runtime = "SIMULATED"


def set_local_network(subnet):
    """Use the discovered lab subnet for external-destination classification."""
    global _local_network
    _local_network = ipaddress.ip_network(subnet, strict=False)


def set_operating_mode(mode):
    global _operating_mode
    with _interval_lock:
        _device_accumulators.clear()
        _operating_mode = mode


def live_capture_status():
    return {"ready": _live_capture_ready.is_set(), "error": _live_capture_error, "runtime_mode": _capture_mode_runtime}


def _source_enabled(source):
    return (source == "LIVE" and _operating_mode == "LIVE_LAN") or (source == "SIMULATED" and _operating_mode == "LAB_SIMULATION")


def record_packet_event(src_mac, src_ip, dst_ip, dst_port, protocol, length, is_dns=False, dns_query=None, source="SIMULATED"):
    """
    Called by live sniffer or traffic simulator for every observed packet.
    """
    if not src_mac or not src_ip or not _source_enabled(source):
        return

    # Check device discovery
    device, is_new = process_device_observation(src_mac, src_ip)
    if not device:
        return

    dev_id = device["id"]

    with _interval_lock:
        acc = _device_accumulators[dev_id]
        acc["is_new_device"] = acc["is_new_device"] or is_new
        if is_dns:
            acc["dns_count"] += 1
        if dst_ip:
            try:
                destination = ipaddress.ip_address(dst_ip)
                if destination not in _local_network and not destination.is_loopback and not destination.is_multicast and not destination.is_link_local:
                    acc["distinct_ips"].add(dst_ip)
            except ValueError:
                pass
        if dst_port:
            acc["ports_contacted"].add(dst_port)
        acc["bytes_sent"] += length


def record_received_packet_event(dst_ip, length):
    """Credit inbound bytes to a known local destination during live capture."""
    if not _source_enabled("LIVE"):
        return
    device = DeviceModel.get_by_ip(dst_ip)
    if device:
        with _interval_lock:
            _device_accumulators[device["id"]]["bytes_recv"] += length


def process_interval_evaluations():
    """
    Executes periodically (every CAPTURE_SAMPLE_INTERVAL_SECONDS):
    1. Extracts aggregated samples for each active device.
    2. Calculates Behaviour Drift Score.
    3. Calculates Weighted Risk Score.
    4. Triggers alerts & automated quarantine if threshold exceeded.
    """
    with _interval_lock:
        active_items = list(_device_accumulators.items())
        _device_accumulators.clear()

    # If no activity in accumulator, still process canonical devices to maintain fresh live data
    devices = DeviceModel.get_all()
    devices_by_id = {d["id"]: d for d in devices}

    for dev_id, acc in active_items:
        device = devices_by_id.get(dev_id)
        if not device:
            continue

        baseline = BaselineModel.get_by_device(dev_id)
        dns_count = acc["dns_count"]
        distinct_ips_count = len(acc["distinct_ips"])
        port_count = len(acc["ports_contacted"])
        bytes_sent = acc["bytes_sent"]
        bytes_recv = acc["bytes_recv"]
        bytes_kb = (bytes_sent + bytes_recv) / 1024.0

        current_sample = {
            "dns_count": dns_count,
            "distinct_ips_count": distinct_ips_count,
            "dest_ips": list(acc["distinct_ips"]),
            "port_count": port_count,
            "bytes_transferred_kb": bytes_kb
        }

        # 1. Compute Behaviour Drift Score
        drift_score, drift_breakdown = compute_behavior_drift_score(current_sample, baseline)

        # 2. Evaluate Anomaly Indicators & Risk Score
        total_risk, risk_band, status, triggered_rules, sub_scores = evaluate_device_risk(
            device=device,
            current_sample=current_sample,
            baseline=baseline,
            is_new_device=acc["is_new_device"]
        )

        # 3. Persist traffic sample and risk assessment
        TrafficModel.record_sample(
            device_id=dev_id,
            dns_count=dns_count,
            distinct_ips_count=distinct_ips_count,
            port_count=port_count,
            bytes_sent=bytes_sent,
            bytes_recv=bytes_recv,
            ports_list=list(acc["ports_contacted"]),
            dest_ips=list(acc["distinct_ips"])
        )

        RiskModel.record_assessment(
            device_id=dev_id,
            drift_score=drift_score,
            port_scan=sub_scores["port_scan"],
            unknown_dev=sub_scores["unknown_device"],
            dns_anom=sub_scores["dns_anomaly"],
            traffic_spk=sub_scores["traffic_spike"],
            unfam_dest=sub_scores["unfamiliar_dest"],
            total=total_risk,
            band=risk_band,
            notes=", ".join([r["indicator"] for r in triggered_rules])
        )

        # 4. Check for Alert Generation
        AlertModel.resolve_inactive_indicators(dev_id, [r["indicator"] for r in triggered_rules])
        if triggered_rules and not device.get("is_quarantined"):
            for rule in triggered_rules:
                severity = "Critical" if total_risk >= 70 else ("Medium" if total_risk >= 40 else "Low")
                AlertModel.create_or_update_active(
                    device_id=dev_id,
                    severity=severity,
                    indicator=rule["indicator"],
                    message=f"{rule['indicator']} on {device['name']}: {rule['detail']}",
                    drift_pct=drift_score,
                    risk_score=total_risk
                )

        # 5. Check Automatic Quarantine Trigger
        auto_quarantine_setting = ConfigModel.get("auto_quarantine", "true").lower() == "true"
        quarantine_threshold = int(ConfigModel.get("quarantine_threshold", config.THRESHOLDS["high_risk_quarantine_threshold"]))

        if total_risk >= quarantine_threshold and auto_quarantine_setting and not device.get("is_quarantined"):
            reason = f"Combined Risk Score ({total_risk}/100) crossed critical threshold ({quarantine_threshold}). Rules: {', '.join([r['indicator'] for r in triggered_rules])}"
            quarantined, _ = quarantine_device(dev_id, reason=reason, manual=False)
            if quarantined:
                status = "Quarantined"

        # Learn a baseline only from clean intervals. This prevents an attack
        # from being absorbed into the normal profile of a newly seen device.
        has_behavioural_anomaly = any(
            rule["indicator"] != "Unknown / Rogue Device" for rule in triggered_rules
        )
        if baseline and not baseline.get("is_locked") and not has_behavioural_anomaly:
            alpha = config.BASELINE_EWMA_ALPHA
            first_sample = baseline.get("sample_count", 0) == 0
            learned = {
                "dns": dns_count if first_sample else (1 - alpha) * baseline["dns_queries_avg"] + alpha * dns_count,
                "ips": distinct_ips_count if first_sample else (1 - alpha) * baseline["distinct_ips_avg"] + alpha * distinct_ips_count,
                "ports": port_count if first_sample else (1 - alpha) * baseline["ports_contacted_avg"] + alpha * port_count,
                "bytes": bytes_kb if first_sample else (1 - alpha) * baseline["bytes_transferred_kb_avg"] + alpha * bytes_kb,
            }
            BaselineModel.update_baseline(
                dev_id, learned["dns"], learned["ips"], learned["ports"], learned["bytes"]
            )
            BaselineModel.add_known_destinations(dev_id, acc["distinct_ips"])
            if baseline.get("sample_count", 0) + 1 >= config.BASELINE_LEARNING_SAMPLES:
                BaselineModel.set_lock(dev_id, True)

        # Update current live metrics on device row
        DeviceModel.update_scores(dev_id, total_risk, drift_score, status)


def _live_sniff_worker(interface):
    """Worker thread using Scapy to sniff raw network packets."""
    global _live_capture_error
    try:
        from scapy.all import sniff, conf, IP, TCP, UDP, DNS, DNSQR
        socket = conf.L2listen(iface=interface)
        _live_capture_error = None
        _live_capture_ready.set()
        print(f"[*] Starting live Scapy capture on interface {interface}...")

        def _packet_callback(pkt):
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                length = len(pkt)
                src_mac = pkt.src if hasattr(pkt, "src") else None
                protocol = "OTHER"
                dst_port = 0
                is_dns = False

                if TCP in pkt:
                    protocol = "TCP"
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    protocol = "UDP"
                    dst_port = pkt[UDP].dport
                    if dst_port == 53 and DNS in pkt and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                        is_dns = True

                if ipaddress.ip_address(src_ip) in _local_network:
                    record_packet_event(src_mac, src_ip, dst_ip, dst_port, protocol, length, is_dns, source="LIVE")
                if ipaddress.ip_address(dst_ip) in _local_network:
                    record_received_packet_event(dst_ip, length)

        try:
            while _engine_running:
                sniff(opened_socket=socket, prn=_packet_callback, store=False, timeout=1)
        finally:
            socket.close()
    except Exception as e:
        _live_capture_error = str(e)
        print(f"[!] Live capture error: {e}.")
    finally:
        _live_capture_ready.clear()


def _engine_loop():
    """Main background loop driving periodic evaluations."""
    global _engine_running
    while _engine_running:
        time.sleep(config.CAPTURE_SAMPLE_INTERVAL_SECONDS)
        try:
            process_interval_evaluations()
        except Exception as e:
            print(f"[!] Error in interval evaluation: {e}")


def start_capture_engine():
    """Starts the capture and evaluation background threads."""
    global _engine_running, _engine_thread, _capture_mode_runtime
    if _engine_running:
        return

    set_operating_mode(ConfigModel.get("operating_mode", "LAB_SIMULATION"))
    _engine_running = True
    _engine_thread = threading.Thread(target=_engine_loop, daemon=True)
    _engine_thread.start()

    mode = ConfigModel.get("capture_mode", config.CAPTURE_MODE)
    _capture_mode_runtime = mode
    if mode == "LIVE":
        from core.network_scanner import get_active_network_info
        network_info = get_active_network_info()
        interface = config.CAPTURE_INTERFACE or network_info["interface"]
        if network_info["host_ip"] != "127.0.0.1":
            set_local_network(network_info["subnet"])
        sniff_thread = threading.Thread(
            target=_live_sniff_worker,
            args=(interface,),
            daemon=True
        )
        sniff_thread.start()
    print(f"[+] NetGuard Traffic Engine initialized in {mode} mode.")


def stop_capture_engine():
    """Stops the engine background thread."""
    global _engine_running
    _engine_running = False
