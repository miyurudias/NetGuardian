"""
NetGuard - Controlled Attack Simulation Engine
Implements controlled security testing scenarios matching Section 14 and 15 of proposal.
"""

import random
from core.capture_engine import record_packet_event
from database.models import DeviceModel

TARGET_MAC = "00:1A:2B:3C:4D:04"  # Laptop 02
TARGET_IP = "192.168.1.45"

COMMON_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017
]

SUSPICIOUS_C2_IPS = [
    "185.220.101.5",   # Known suspicious host
    "194.26.29.112",   # Suspicious IP
    "91.240.118.172",  # Foreign node
    "45.154.255.88",   # Untrusted VPS
    "103.145.13.2",    # External IP
    "193.106.191.24",  # Foreign C2
    "195.123.246.11",  # Remote node
    "198.51.100.23",   # Suspicious IP
    "203.0.113.88",    # Remote node
    "192.0.2.145",     # Foreign host
    "198.51.100.99",   # Untrusted endpoint
    "203.0.113.211"    # C2 server
]


def run_port_scan_attack(target_mac=TARGET_MAC, target_ip=TARGET_IP):
    """
    Scenario: Laptop 02 initiates a SYN/Connect reconnaissance scan.
    Probes multiple ports and external perimeter nodes.
    Expected: Risk score jumps by +30 (scan) and +15 (unfamiliar dest) = 45; flagged as SUSPICIOUS.
    """
    for port in COMMON_SCAN_PORTS:
        record_packet_event(
            src_mac=target_mac,
            src_ip=target_ip,
            dst_ip="192.168.1.1",
            dst_port=port,
            protocol="TCP",
            length=60
        )
    # Contact untrusted external hosts during scan reconnaissance
    for dst in ["185.220.101.5", "194.26.29.112", "91.240.118.172", "45.154.255.88"]:
        record_packet_event(
            src_mac=target_mac,
            src_ip=target_ip,
            dst_ip=dst,
            dst_port=443,
            protocol="TCP",
            length=80
        )
    return {
        "status": "success",
        "scenario": "Port Scan Simulation",
        "target": f"{target_ip} ({target_mac})",
        "ports_scanned": len(COMMON_SCAN_PORTS),
        "expected_points": "+30 (Scan) + 15 (Dest) = 45 (Suspicious)"
    }


def run_dns_tunneling_attack(target_mac=TARGET_MAC, target_ip=TARGET_IP):
    """
    Scenario: Laptop 02 exhibits high-volume anomalous DNS requests / DNS tunneling.
    Expected: Risk score jumps by +20; flagged as DNS Anomaly.
    """
    for i in range(120):
        subdomain = f"x{random.randint(1000, 9999)}.data-exfil.attacker-dns.org"
        record_packet_event(
            src_mac=target_mac,
            src_ip=target_ip,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="UDP",
            length=128,
            is_dns=True,
            dns_query=subdomain
        )
    return {
        "status": "success",
        "scenario": "DNS Tunneling / Anomaly",
        "target": target_ip,
        "queries_sent": 120,
        "expected_points": "+20"
    }


def run_traffic_spike_attack(target_mac=TARGET_MAC, target_ip=TARGET_IP, size_mb=3.5):
    """
    Scenario: Massive outbound data exfiltration surge.
    Expected: Risk score jumps by +15; flagged as Traffic Spike.
    """
    total_bytes = int(size_mb * 1024 * 1024)
    # Stream in 100KB chunks
    chunk_size = 102400
    for _ in range(total_bytes // chunk_size):
        record_packet_event(
            src_mac=target_mac,
            src_ip=target_ip,
            dst_ip="185.220.101.5",
            dst_port=443,
            protocol="TCP",
            length=chunk_size
        )
    return {
        "status": "success",
        "scenario": "Traffic Volume Spike / Exfiltration",
        "target": target_ip,
        "transferred_mb": size_mb,
        "expected_points": "+15"
    }


def run_unfamiliar_destinations_attack(target_mac=TARGET_MAC, target_ip=TARGET_IP):
    """
    Scenario: Device connects to multiple newly seen foreign/suspicious external IPs.
    Expected: Risk score jumps by +15; flagged as Unfamiliar Destination.
    """
    for dst in SUSPICIOUS_C2_IPS:
        record_packet_event(
            src_mac=target_mac,
            src_ip=target_ip,
            dst_ip=dst,
            dst_port=random.choice([443, 8443, 9001]),
            protocol="TCP",
            length=random.randint(5000, 15000)
        )
    return {
        "status": "success",
        "scenario": "Unfamiliar Destinations Connection",
        "target": target_ip,
        "destinations_contacted": len(SUSPICIOUS_C2_IPS),
        "expected_points": "+15"
    }


def run_combined_escalation_attack(target_mac=TARGET_MAC, target_ip=TARGET_IP):
    """
    Scenario: Full multi-vector attack combining Port Scan (+30), DNS Tunneling (+20),
    and Unfamiliar Destinations (+15).
    Combined Score = 65 to 80 (CRITICAL) -> Triggers AUTOMATIC QUARANTINE!
    """
    run_port_scan_attack(target_mac, target_ip)
    run_dns_tunneling_attack(target_mac, target_ip)
    run_unfamiliar_destinations_attack(target_mac, target_ip)
    run_traffic_spike_attack(target_mac, target_ip, size_mb=2.0)

    return {
        "status": "success",
        "scenario": "Multi-Vector Attack Escalation",
        "target": target_ip,
        "expected_score": "75 - 85 (Critical)",
        "expected_action": "AUTOMATIC QUARANTINE TRIGGERED"
    }


def run_rogue_device_injection():
    """
    Scenario: An unauthorized hardware unit connects to the LAN switch.
    Expected: Device discovered, tagged as 'Unknown', +20 risk score.
    """
    rogue_mac = "00:50:56:C0:00:08"
    rogue_ip = "192.168.1.99"

    # Send packets from the rogue device
    for _ in range(5):
        record_packet_event(
            src_mac=rogue_mac,
            src_ip=rogue_ip,
            dst_ip="192.168.1.1",
            dst_port=80,
            protocol="TCP",
            length=120
        )
    return {
        "status": "success",
        "scenario": "Rogue Device Injection",
        "rogue_mac": rogue_mac,
        "rogue_ip": rogue_ip,
        "expected_points": "+20 (Unknown Device)"
    }


def run_benign_spike(target_mac="00:1A:2B:3C:4D:01", target_ip="192.168.1.10"):
    """
    Scenario: Legitimate OS update download on Laptop 01.
    Expected: Verifies false-positive resistance: volume increases moderately,
    but with zero port scans or DNS anomalies, score remains LOW/MEDIUM and DOES NOT quarantine.
    """
    # Download 800 KB from legitimate CDN over single HTTPS connection
    chunk_size = 50000
    for _ in range(16):
        record_packet_event(
            src_mac=target_mac,
            src_ip=target_ip,
            dst_ip="20.112.52.29",  # Legitimate Microsoft CDN
            dst_port=443,
            protocol="TCP",
            length=chunk_size
        )
    return {
        "status": "success",
        "scenario": "Benign Software Update Spike (False Positive Test)",
        "target": target_ip,
        "expected_result": "Moderate volume drift only; NO quarantine triggered."
    }
