"""
NetGuard - System Configuration
Configurable parameters for Behavioral Fingerprinting and Risk Scoring
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.environ.get("NETGUARD_DB", str(BASE_DIR / "netguard.db"))

# Server Settings
HOST = os.environ.get("NETGUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("NETGUARD_PORT", 5050))
DEBUG = os.environ.get("NETGUARD_DEBUG", "False").lower() in ("true", "1", "yes")
RESTART_EXIT_CODE = 75  # Launcher replaces the server child after this exit status.

# Traffic Capture Settings
# Dual-Mode: "LIVE" (Scapy sniff) or "SIMULATED" (synthetic lab traffic)
CAPTURE_MODE = os.environ.get("NETGUARD_MODE", "SIMULATED").upper()
CAPTURE_INTERFACE = os.environ.get("NETGUARD_IFACE")  # e.g., 'eth0', 'en0', 'Wi-Fi'; auto-detect if unset
CAPTURE_SAMPLE_INTERVAL_SECONDS = 5  # aggregation window for metric calculations

# Baseline learning for newly discovered devices. Profiles are built only from
# intervals without behavioural anomalies and lock after enough clean samples.
BASELINE_LEARNING_SAMPLES = 20
BASELINE_EWMA_ALPHA = 0.20

# Risk Scoring Indicators & Default Weights (Section 8.3 of Proposal)
# Maximum combined score = 100
DEFAULT_WEIGHTS = {
    "port_scan": 30,           # Port scanning detected (+30)
    "unknown_device": 20,      # Unknown / unrecognized device (+20)
    "dns_anomaly": 20,         # DNS anomaly (volume spike or tunneling) (+20)
    "traffic_spike": 15,       # Traffic-volume spike (+15)
    "unfamiliar_dest": 15      # Connection to new/unfamiliar destination (+15)
}

# Risk Bands (Section 8.3 of Proposal)
RISK_BANDS = {
    "LOW": {"min": 0, "max": 39, "label": "Normal", "color": "green"},
    "MEDIUM": {"min": 40, "max": 69, "label": "Suspicious", "color": "amber"},
    "HIGH": {"min": 70, "max": 100, "label": "Critical", "color": "red"}
}

# Thresholds for Anomaly Triggers
THRESHOLDS = {
    "port_scan_unique_ports": 8,       # >= 8 distinct ports probed in interval -> port scan
    "dns_volume_multiplier": 3.0,      # >= 3.0x baseline DNS queries -> DNS anomaly
    "traffic_spike_multiplier": 4.0,   # >= 4.0x baseline byte volume -> traffic spike
    "unfamiliar_dest_threshold": 3,    # >= 3 new external IPs in single interval -> unfamiliar dest
    "high_risk_quarantine_threshold": 70 # Score >= 70 triggers auto-quarantine if enabled
}

# Automated Response Settings
AUTO_QUARANTINE_ENABLED = True
# Quarantine Backend: "SIMULATED" (Cisco ACL output & virtual drop - works cross-platform),
# "IPTABLES" (Linux), "PFCTL" (macOS), "WINDOWS" (netsh)
QUARANTINE_BACKEND = os.environ.get("NETGUARD_QUARANTINE_BACKEND", "SIMULATED").upper()

# Known Network Subnet
LOCAL_SUBNET = "192.168.1.0/24"
GATEWAY_IP = "192.168.1.1"
