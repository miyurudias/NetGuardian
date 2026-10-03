"""
NetGuard - Risk Scoring Engine
Calculates device risk score based on behavioral anomaly indicators.
(Section 8.3 of Computing Project Proposal)
"""

from database.models import ConfigModel, AlertModel, RiskModel, DeviceModel
import config


def get_configured_weights():
    """Fetches risk weights from DB or defaults to proposal values."""
    return {
        "port_scan": int(ConfigModel.get("weight_port_scan", config.DEFAULT_WEIGHTS["port_scan"])),
        "unknown_device": int(ConfigModel.get("weight_unknown_device", config.DEFAULT_WEIGHTS["unknown_device"])),
        "dns_anomaly": int(ConfigModel.get("weight_dns_anomaly", config.DEFAULT_WEIGHTS["dns_anomaly"])),
        "traffic_spike": int(ConfigModel.get("weight_traffic_spike", config.DEFAULT_WEIGHTS["traffic_spike"])),
        "unfamiliar_dest": int(ConfigModel.get("weight_unfamiliar_dest", config.DEFAULT_WEIGHTS["unfamiliar_dest"]))
    }


def evaluate_device_risk(device, current_sample, baseline, is_new_device=False):
    """
    Evaluates current device behavior against baseline, scoring anomalies based on weights.
    
    Returns:
        total_risk_score (int): 0 - 100
        risk_band (str): 'Low', 'Medium', 'High'
        triggered_indicators (list): Details of each active indicator
        sub_scores (dict): Breakdown of points added
    """
    weights = get_configured_weights()
    sub_scores = {
        "port_scan": 0,
        "unknown_device": 0,
        "dns_anomaly": 0,
        "traffic_spike": 0,
        "unfamiliar_dest": 0
    }
    triggered_indicators = []

    # 1. Port Scanning Indicator (+30)
    ports_probed = current_sample.get("port_count", 0)
    ports_baseline = baseline.get("ports_contacted_avg", 3.0) if baseline else 3.0
    if ports_probed >= config.THRESHOLDS["port_scan_unique_ports"] or ports_probed >= (ports_baseline * 3.5):
        sub_scores["port_scan"] = weights["port_scan"]
        triggered_indicators.append({
            "indicator": "Port Scanning Detected",
            "weight": weights["port_scan"],
            "detail": f"Observed {ports_probed} unique ports probed (baseline is {ports_baseline:.1f})"
        })

    # 2. Unknown / Unrecognized Device Indicator (+20)
    if is_new_device or device.get("device_type") == "Unknown" or (baseline is None) or (baseline.get("sample_count", 0) == 0):
        sub_scores["unknown_device"] = weights["unknown_device"]
        triggered_indicators.append({
            "indicator": "Unknown / Rogue Device",
            "weight": weights["unknown_device"],
            "detail": "New device connecting to network without verified baseline"
        })

    # 3. DNS Anomaly Indicator (+20)
    dns_count = current_sample.get("dns_count", 0)
    dns_baseline = baseline.get("dns_queries_avg", 20.0) if baseline else 20.0
    if dns_count >= (dns_baseline * config.THRESHOLDS["dns_volume_multiplier"]) and dns_count > 30:
        sub_scores["dns_anomaly"] = weights["dns_anomaly"]
        triggered_indicators.append({
            "indicator": "DNS Anomaly / Tunneling",
            "weight": weights["dns_anomaly"],
            "detail": f"DNS query surge of {dns_count} queries (baseline is {dns_baseline:.1f})"
        })

    # 4. Traffic-Volume Spike Indicator (+15)
    bytes_kb = current_sample.get("bytes_transferred_kb", 0)
    bytes_baseline = baseline.get("bytes_transferred_kb_avg", 150.0) if baseline else 150.0
    if bytes_kb >= (bytes_baseline * config.THRESHOLDS["traffic_spike_multiplier"]) and bytes_kb > 200:
        sub_scores["traffic_spike"] = weights["traffic_spike"]
        triggered_indicators.append({
            "indicator": "Traffic Volume Spike",
            "weight": weights["traffic_spike"],
            "detail": f"Observed {bytes_kb:.1f} KB transferred (baseline is {bytes_baseline:.1f} KB)"
        })

    # 5. Connection to New / Unfamiliar Destination (+15)
    ips_count = current_sample.get("distinct_ips_count", 0)
    ips_baseline = baseline.get("distinct_ips_avg", 5.0) if baseline else 5.0
    if ips_count >= (ips_baseline + config.THRESHOLDS["unfamiliar_dest_threshold"]) and ips_count > 6:
        sub_scores["unfamiliar_dest"] = weights["unfamiliar_dest"]
        triggered_indicators.append({
            "indicator": "Unfamiliar External Destinations",
            "weight": weights["unfamiliar_dest"],
            "detail": f"Contacted {ips_count} distinct external IPs (baseline is {ips_baseline:.1f})"
        })

    # Total Risk Score (clamped to 100)
    total_risk_score = min(100, sum(sub_scores.values()))

    # Determine Risk Band (Section 8.3 & Section 15 of Proposal)
    if total_risk_score >= config.RISK_BANDS["HIGH"]["min"]:
        risk_band = "High"
        dashboard_status = "Critical"
    elif (total_risk_score >= config.RISK_BANDS["MEDIUM"]["min"] or
          sub_scores["port_scan"] > 0 or sub_scores["unknown_device"] > 0):
        risk_band = "Medium"
        dashboard_status = "Suspicious"
    else:
        risk_band = "Low"
        dashboard_status = "Normal"

    # If device is already quarantined, maintain Quarantined status
    if device.get("is_quarantined"):
        dashboard_status = "Quarantined"

    return total_risk_score, risk_band, dashboard_status, triggered_indicators, sub_scores
