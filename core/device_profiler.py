"""
NetGuard - Device Profiler & Inventory Manager
Discovers devices, categorizes hardware types, and tracks per-device identities.
"""

from database.models import DeviceModel, BaselineModel

# Common OUI Vendor Signatures for Lab & Real Physical Networks
KNOWN_VENDORS = {
    # Networking & Routers
    "00:1A:2B": "Cisco Systems",
    "00:26:0B": "Cisco Systems",
    "00:14:D1": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies",
    "E4:C3:2A": "TP-Link Technologies",
    "9C:74:1A": "Huawei Technologies",
    "F8:3D:FF": "Huawei Technologies",
    "70:7B:E8": "Huawei Technologies",
    "00:26:5A": "D-Link Corporation",
    "70:62:B8": "D-Link Corporation",
    "F0:9F:C2": "Ubiquiti Networks",
    "B4:FB:E4": "Ubiquiti Networks",
    "2C:39:96": "Netgear Inc.",
    "00:14:6C": "Netgear Inc.",
    "00:0C:43": "Ralink / MediaTek",
    "E8:65:D4": "ZTE Corporation",
    "20:2B:C1": "Ericsson / SLT",
    "00:1F:33": "Netgear Inc.",
    "D8:07:B6": "Mikrotik",
    # Apple
    "D2:1B:03": "Apple Inc.",
    "AC:DE:48": "Apple Inc.",
    "3C:06:30": "Apple Inc.",
    "F0:18:98": "Apple Inc.",
    "A4:83:E7": "Apple Inc.",
    "7C:04:D0": "Apple Inc.",
    "BC:D0:74": "Apple Inc.",
    "DC:A9:04": "Apple Inc.",
    "28:CF:E9": "Apple Inc.",
    "88:66:5A": "Apple Inc.",
    "F4:D4:88": "Apple Inc.",
    "60:F8:1D": "Apple Inc.",
    "18:65:90": "Apple Inc.",
    "38:F9:D3": "Apple Inc.",
    "A8:66:7F": "Apple Inc.",
    # PCs & Laptops
    "00:14:22": "Dell Inc.",
    "B8:85:84": "Dell Inc.",
    "44:A8:42": "Dell Inc.",
    "00:25:B3": "Hewlett Packard",
    "3C:D9:2B": "Hewlett Packard",
    "9C:8E:99": "HP Inc.",
    "00:21:5C": "Intel Corporation",
    "80:86:F2": "Intel Corporation",
    "34:13:E8": "Intel Corporation",
    "00:15:5D": "Microsoft Corporation",
    "58:11:22": "Lenovo Group",
    "6C:02:E0": "ASUSTeK Computer",
    "04:D9:F5": "ASUSTeK Computer",
    # Mobile Phones & Tablets
    "54:E1:AD": "Samsung Electronics",
    "40:4E:36": "Samsung Electronics",
    "78:4F:43": "Samsung Electronics",
    "94:65:2D": "Samsung Electronics",
    "64:A2:F9": "Xiaomi Communications",
    "74:23:44": "Xiaomi Communications",
    "98:09:CF": "OnePlus / Oppo",
    "AC:36:13": "Google Inc. (Pixel)",
    # Printers & Imaging
    "00:1E:8F": "Canon Inc.",
    "00:21:B7": "Epson Corporation",
    "00:80:77": "Brother Industries",
    # Surveillance & IoT
    "00:40:8C": "Axis Communications (CCTV)",
    "BC:BA:C7": "Hangzhou Hikvision (CCTV)",
    "3C:EF:8C": "Hangzhou Hikvision (CCTV)",
    "3C:1B:F8": "Hangzhou Hikvision (CCTV)",
    "34:C6:DD": "Hangzhou Ezviz (Smart IoT)",
    "E0:50:8B": "Dahua Technology (CCTV)",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi 4",
    "E4:5F:01": "Raspberry Pi 4",
    "28:CD:C1": "Raspberry Pi 5",
    "00:11:32": "Synology Inc. (NAS)",
    "00:08:9B": "QNAP Systems (NAS)",
    "68:37:E9": "Amazon Technologies (Echo/FireTV)",
    "FC:65:DE": "Amazon Technologies",
    "54:60:09": "Google Nest / Home",
    "F4:F5:DB": "Google Chromecast",
    "00:04:20": "Slim Devices / Logitech",
    "70:2C:1F": "Sony Interactive (PlayStation)",
    # Smart TVs & Streaming
    "00:24:E4": "Samsung Smart TV",
    "14:49:E0": "Samsung Smart TV",
    "30:CD:A7": "Samsung Smart TV",
    "00:1C:62": "LG Electronics (webOS TV)",
    "A8:23:FE": "LG Electronics (webOS TV)",
    "B8:5D:43": "Roku Inc. (Streaming TV)",
    "CC:6D:A0": "Roku Inc. (Streaming TV)",
    "50:1E:2D": "TCL King Electrical (Smart TV)",
    "08:C5:E1": "Sony Bravia (Smart TV)",
    # Virtualization
    "00:50:56": "VMware Virtual Device",
    "00:0C:29": "VMware Virtual Device",
    "08:00:27": "Oracle VirtualBox"
}


def is_locally_administered_mac(mac):
    """
    Checks if MAC address is an IEEE 802.11 Locally Administered Address
    (i.e. Private Wi-Fi MAC randomization used by iOS, Android, and Windows 11).
    """
    if not mac:
        return False
    try:
        clean = mac.replace("-", ":").strip()
        first_byte = int(clean.split(":")[0], 16)
        return (first_byte & 0x02) != 0
    except Exception:
        return False


def lookup_vendor(mac):
    """Resolves vendor name from MAC address prefix or identifies Private Wi-Fi MACs."""
    if not mac:
        return "Unknown Manufacturer"
    
    clean_mac = mac.upper().replace("-", ":").strip()
    
    # Check if modern randomized MAC
    if is_locally_administered_mac(clean_mac):
        return "Private Wi-Fi MAC (Apple / Android)"
        
    prefix = clean_mac[:8]
    return KNOWN_VENDORS.get(prefix, "Generic Network Device")


def classify_device_type(vendor, hostname="", ports_probed=None):
    """Infers device type based on vendor string, hostname, and open/observed ports."""
    vendor_lower = (vendor or "").lower()
    host_lower = (hostname or "").lower()
    ports = set(ports_probed or [])

    # Router & Gateway clues
    if any(k in host_lower for k in ["gateway", "router", "modem", "ont", "ap-"]) or \
       any(k in vendor_lower for k in ["cisco", "tp-link", "d-link", "ubiquiti", "netgear", "mikrotik", "zte", "huawei"]):
        if any(p in ports for p in [80, 443, 53, 8080]):
            return "Router"

    # Printer clues
    if any(k in host_lower for k in ["printer", "print", "laserjet", "deskjet", "mfp", "epson", "brother", "canon"]) or \
       any(k in vendor_lower for k in ["canon", "epson", "brother", "hewlett packard"]):
        if 9100 in ports or 631 in ports or 515 in ports or "printer" in host_lower:
            return "Printer"

    # Surveillance / CCTV clues
    if any(k in host_lower for k in ["cctv", "cam", "camera", "dvr", "nvr", "axis", "hikvision", "dahua", "ezviz"]) or \
       any(k in vendor_lower for k in ["axis", "hikvision", "dahua", "ezviz"]):
        return "CCTV"
    if 554 in ports or 8000 in ports or 37777 in ports:
        return "CCTV"

    # Smart TV / Media clues
    if any(k in host_lower for k in ["tv", "bravia", "chromecast", "firetv", "roku", "appletv", "smarttv", "webos", "tizen"]) or \
       any(k in vendor_lower for k in ["smart tv", "roku", "webos", "bravia", "tcl", "amazon technologies"]):
        return "Smart TV"
    if any(p in ports for p in [8001, 8002, 3000, 3001, 8008, 8009, 6466, 6467]):
        return "Smart TV"

    # Phone / Tablet clues
    if 62078 in ports:  # Apple mobile sync port
        return "Phone"
    if "private wi-fi" in vendor_lower or "mobile" in host_lower or "phone" in host_lower or "iphone" in host_lower or "android" in host_lower:
        return "Phone"
    if any(k in vendor_lower for k in ["samsung", "xiaomi", "oneplus", "oppo", "vivo", "pixel"]) and not any(p in ports for p in [8001, 8002, 3000, 3001]):
        return "Phone"

    # Server / Infrastructure
    if 3306 in ports or 5432 in ports or 27017 in ports or "server" in host_lower or "nas" in host_lower or "synology" in vendor_lower:
        return "Server"

    # Default to Laptop / Workstation
    return "Laptop"


def process_device_observation(mac, ip, hostname="", ports=None):
    """
    Checks if device exists in inventory. If new, registers device as 'Unknown'
    and triggers elevated risk flagging (Section 8.3 of Proposal).
    """
    if not mac:
        return None, False

    clean_mac = mac.upper().replace("-", ":").strip()
    device = DeviceModel.get_by_mac(clean_mac)

    if device:
        # Existing device: update last seen and IP
        DeviceModel.update_last_seen(device["id"], ip)
        return device, False
    else:
        # New / Rogue Device detected!
        vendor = lookup_vendor(clean_mac)
        dev_type = classify_device_type(vendor, hostname, ports)
        
        if hostname:
            name = hostname
        elif is_locally_administered_mac(clean_mac):
            name = f"Mobile Client ({ip.split('.')[-1]})"
        else:
            name = f"{vendor.split()[0]} Device ({ip.split('.')[-1]})"

        # Newly discovered devices start with elevated risk (+20 unknown)
        new_id = DeviceModel.create(
            mac=clean_mac,
            ip=ip,
            name=name,
            device_type=dev_type,
            is_whitelisted=False
        )
        new_device = DeviceModel.get_by_id(new_id)
        return new_device, True
