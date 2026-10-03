"""
NetGuard - Background Benign Traffic Generator
Generates realistic normal network traffic metadata matching the profiles in Section 8.1:
- Laptop 01 (Staff): Web browsing, DNS lookups, HTTPS to known domains
- Phone 01: Messaging APIs, DNS, mobile web
- Printer: LAN print jobs, minimal DNS, only internal communication
- Laptop 02: Normal student browsing (until targeted by attack test)
- CCTV: Video feed streaming to local recording server
"""

import time
import random
import threading
from core.capture_engine import record_packet_event
from database.seed_data import CANONICAL_DEVICES

_simulator_running = False
_simulator_thread = None

# Known harmless external destination IPs (Google, Cloudflare, Microsoft, AWS)
BENIGN_DEST_IPS = [
    "142.250.190.46",  # Google
    "172.217.16.206",  # Google
    "104.16.132.229",  # Cloudflare
    "20.112.52.29",    # Microsoft
    "52.95.120.67"     # AWS CDN
]

BENIGN_DNS_DOMAINS = [
    "google.com", "github.com", "cloudflare.com", "wikipedia.org", "icbt.lk",
    "cardiffmet.ac.uk", "youtube.com", "microsoft.com", "amazon.com"
]


from database.models import ConfigModel, DeviceModel


def generate_single_benign_cycle():
    """Generates one interval's worth of normal traffic for all 5 devices."""
    # Strictly run only when in LAB_SIMULATION mode
    current_mode = ConfigModel.get("operating_mode", "LIVE_LAN")
    if current_mode != "LAB_SIMULATION":
        return

    # Never auto-generate or inject dummy devices if database has no mock devices
    existing_mock = [d for d in DeviceModel.get_all() if d.get("mac", "").startswith("00:1A:2B")]
    if not existing_mock:
        return

    for dev in CANONICAL_DEVICES:
        mac = dev["mac"]
        ip = dev["ip"]
        dev_type = dev["device_type"]

        if dev_type == "Printer":
            # Printer only communicates locally
            record_packet_event(
                src_mac=mac, src_ip=ip, dst_ip="192.168.1.10",
                dst_port=9100, protocol="TCP", length=random.randint(1024, 4096)
            )
            # Rare DNS check
            if random.random() < 0.2:
                record_packet_event(
                    src_mac=mac, src_ip=ip, dst_ip="192.168.1.1",
                    dst_port=53, protocol="UDP", length=64, is_dns=True
                )

        elif dev_type == "CCTV":
            # CCTV streams continuously to NVR server (192.168.1.5) on port 554
            record_packet_event(
                src_mac=mac, src_ip=ip, dst_ip="192.168.1.5",
                dst_port=554, protocol="TCP", length=random.randint(450000, 750000)
            )

        elif dev_type == "Phone":
            # Phone: 2-4 distinct IPs, 443/5228, ~80-150KB, 15-25 DNS queries
            for _ in range(random.randint(15, 25)):
                record_packet_event(
                    src_mac=mac, src_ip=ip, dst_ip="1.1.1.1",
                    dst_port=53, protocol="UDP", length=72, is_dns=True
                )
            for _ in range(random.randint(4, 8)):
                dst = random.choice(BENIGN_DEST_IPS[:3])
                record_packet_event(
                    src_mac=mac, src_ip=ip, dst_ip=dst,
                    dst_port=random.choice([443, 5228]), protocol="TCP",
                    length=random.randint(15000, 35000)
                )

        elif dev_type == "Laptop":
            # Laptop 1 & Laptop 2 normal baseline: 25-35 DNS, 4-7 IPs, 443/80, ~200-300KB
            for _ in range(random.randint(20, 35)):
                record_packet_event(
                    src_mac=mac, src_ip=ip, dst_ip="8.8.8.8",
                    dst_port=53, protocol="UDP", length=72, is_dns=True
                )
            for _ in range(random.randint(6, 12)):
                dst = random.choice(BENIGN_DEST_IPS)
                record_packet_event(
                    src_mac=mac, src_ip=ip, dst_ip=dst,
                    dst_port=random.choice([443, 80]), protocol="TCP",
                    length=random.randint(20000, 45000)
                )


def _traffic_generator_loop(interval_seconds=5):
    """Loop generating background traffic."""
    global _simulator_running
    while _simulator_running:
        try:
            generate_single_benign_cycle()
        except Exception as e:
            print(f"[!] Normal traffic simulator error: {e}")
        time.sleep(interval_seconds)


def start_normal_traffic_simulation(interval_seconds=5):
    """Starts continuous background normal traffic generation."""
    global _simulator_running, _simulator_thread
    if _simulator_running:
        return
    _simulator_running = True
    _simulator_thread = threading.Thread(
        target=_traffic_generator_loop,
        args=(interval_seconds,),
        daemon=True
    )
    _simulator_thread.start()
    print("[+] Normal background network traffic simulation started.")


def stop_normal_traffic_simulation():
    """Stops the normal traffic generator."""
    global _simulator_running
    _simulator_running = False
