"""
NetGuard - Dual-Mode Traffic Ingestion Engine
Handles live packet capture via Scapy or synthetic lab traffic generation.
Aggregates per-device metrics and drives the Drift and Risk evaluation loop.
"""

import time
import threading
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


def record_packet_event(src_mac, src_ip, dst_ip, dst_port, protocol, length, is_dns=False, dns_query=None):
    """
    Called by live sniffer or traffic simulator for every observed packet.
    """
    if not src_mac or not src_ip:
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
        if dst_ip and dst_ip != config.GATEWAY_IP and not dst_ip.startswith("192.168.1."):
            acc["distinct_ips"].add(dst_ip)
        if dst_port:
            acc["ports_contacted"].add(dst_port)
        acc["bytes_sent"] += length


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
        if triggered_rules and not device.get("is_quarantined"):
            for rule in triggered_rules:
                severity = "Critical" if total_risk >= 70 else ("Medium" if total_risk >= 40 else "Low")
                AlertModel.create(
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
            quarantine_device(dev_id, reason=reason, manual=False)
            status = "Quarantined"

        # Learn a baseline only from clean intervals. This prevents an attack
        # from being absorbed into the normal profile of a newly seen device.
        has_behavioural_anomaly = any(
            rule["indicator"] != "Unknown / Rogue Device" for rule in triggered_rules
        )
        if baseline and not baseline.get("is_locked") and not has_behavioural_anomaly:
            alpha = config.BASELINE_EWMA_ALPHA
            learned = {
                "dns": (1 - alpha) * baseline["dns_queries_avg"] + alpha * dns_count,
                "ips": (1 - alpha) * baseline["distinct_ips_avg"] + alpha * distinct_ips_count,
                "ports": (1 - alpha) * baseline["ports_contacted_avg"] + alpha * port_count,
                "bytes": (1 - alpha) * baseline["bytes_transferred_kb_avg"] + alpha * bytes_kb,
            }
            BaselineModel.update_baseline(
                dev_id, learned["dns"], learned["ips"], learned["ports"], learned["bytes"]
            )
            if baseline.get("sample_count", 0) + 1 >= config.BASELINE_LEARNING_SAMPLES:
                BaselineModel.set_lock(dev_id, True)

        # Update current live metrics on device row
        DeviceModel.update_scores(dev_id, total_risk, drift_score, status)


def _live_sniff_worker(interface):
    """Worker thread using Scapy to sniff raw network packets."""
    try:
        from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
        print(f"[*] Starting live Scapy capture on interface {interface}...")

        def _packet_callback(pkt):
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                length = len(pkt)
                src_mac = pkt.src if hasattr(pkt, "src") else "00:00:00:00:00:00"
                protocol = "OTHER"
                dst_port = 0
                is_dns = False

                if TCP in pkt:
                    protocol = "TCP"
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    protocol = "UDP"
                    dst_port = pkt[UDP].dport
                    if DNS in pkt and pkt.haslayer(DNSQR):
                        is_dns = True

                record_packet_event(src_mac, src_ip, dst_ip, dst_port, protocol, length, is_dns)

        sniff(iface=interface, prn=_packet_callback, store=0)
    except Exception as e:
        print(f"[!] Live capture error: {e}. Switching to Simulated Mode.")


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
    global _engine_running, _engine_thread
    if _engine_running:
        return

    _engine_running = True
    _engine_thread = threading.Thread(target=_engine_loop, daemon=True)
    _engine_thread.start()

    mode = ConfigModel.get("capture_mode", config.CAPTURE_MODE)
    if mode == "LIVE":
        sniff_thread = threading.Thread(
            target=_live_sniff_worker,
            args=(config.CAPTURE_INTERFACE,),
            daemon=True
        )
        sniff_thread.start()
    print(f"[+] NetGuard Traffic Engine initialized in {mode} mode.")


def stop_capture_engine():
    """Stops the engine background thread."""
    global _engine_running
    _engine_running = False
