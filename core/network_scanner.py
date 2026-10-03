"""
NetGuard - Real Network Scanner & Device Discovery Engine
Actively scans the local physical LAN (Wi-Fi / Ethernet), detects real active hosts,
resolves hostnames, MAC OUI manufacturers, open ports, and live latency.
Works cross-platform on macOS, Windows, and Linux.
"""

import os
import re
import sys
import time
import socket
import platform
import subprocess
import concurrent.futures
from pathlib import Path

# Add project root to sys.path for direct invocation
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from database.models import DeviceModel, BaselineModel, ConfigModel
from core.device_profiler import lookup_vendor, classify_device_type, is_locally_administered_mac, KNOWN_VENDORS

# Use extended vendor dictionary synchronized with device_profiler
EXTENDED_VENDORS = KNOWN_VENDORS


def get_real_vendor(mac):
    """Resolves manufacturer from MAC address prefix or detects private Wi-Fi MACs."""
    if not mac:
        return "Unknown Manufacturer"
    clean_mac = mac.upper().replace("-", ":").strip()
    if is_locally_administered_mac(clean_mac):
        return "Private Wi-Fi MAC (Apple / Android)"
    prefix = clean_mac[:8]
    if prefix in EXTENDED_VENDORS:
        return EXTENDED_VENDORS[prefix]
    return lookup_vendor(clean_mac)


def probe_http_banner_and_title(ip, timeout=0.15):
    """
    Attempts to read HTTP Server header and HTML title from port 80 or 8080.
    Useful for naming routers (e.g. 'Huawei EchoLife', 'TP-Link Wireless Router')
    printers ('HP LaserJet', 'Epson') and embedded web servers.
    """
    for port in [80, 8080, 443]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetGuard-Scanner/2.0\r\n\r\n"
            s.sendall(req.encode("latin-1"))
            resp = b""
            try:
                resp = s.recv(1024)
            except Exception:
                pass
            s.close()

            if resp:
                text = resp.decode("latin-1", errors="ignore")
                m_title = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
                if m_title:
                    clean_title = m_title.group(1).strip()
                    if clean_title and len(clean_title) < 50:
                        return clean_title
                m_server = re.search(r"Server:\s*([^\r\n]+)", text, re.IGNORECASE)
                if m_server:
                    clean_srv = m_server.group(1).strip()
                    if clean_srv and len(clean_srv) < 40:
                        return clean_srv
        except Exception:
            pass
    return ""


def probe_netbios_name(ip, timeout=0.15):
    """
    Sends NetBIOS Name Service Status Request (UDP 137) to discover
    Windows computer names and workgroups.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        query = b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        s.sendto(query, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()
        if len(data) > 57:
            raw_name = data[57:72].decode("latin-1", errors="ignore").strip()
            if raw_name and raw_name.isprintable():
                return raw_name
    except Exception:
        pass
    return ""


def get_active_network_info():
    """
    Detects the machine's active network interface, host IP, gateway IP,
    and subnet configuration on macOS, Linux, or Windows.
    """
    os_name = platform.system().lower()
    default_info = {
        "interface": "en0" if "darwin" in os_name else ("eth0" if "linux" in os_name else "Ethernet"),
        "host_ip": "127.0.0.1",
        "host_mac": "00:00:00:00:00:00",
        "gateway_ip": "192.168.1.1",
        "subnet": "192.168.1.0/24",
        "netmask": "255.255.255.0",
        "status": "active"
    }

    try:
        # Determine host IP via UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        s.close()
        default_info["host_ip"] = host_ip
    except Exception:
        host_ip = "127.0.0.1"

    # macOS route & ifconfig detection
    if "darwin" in os_name:
        try:
            route_proc = subprocess.Popen(["netstat", "-rn", "-f", "inet"], stdout=subprocess.PIPE, text=True)
            out, _ = route_proc.communicate()
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    default_info["gateway_ip"] = parts[1]
                    if len(parts) > 3:
                        default_info["interface"] = parts[3]
                    break

            if_proc = subprocess.Popen(["ifconfig", default_info["interface"]], stdout=subprocess.PIPE, text=True)
            if_out, _ = if_proc.communicate()
            ip_m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", if_out)
            ether_m = re.search(r"ether ([0-9a-fA-F:]+)", if_out)
            if ip_m:
                default_info["host_ip"] = ip_m.group(1)
            if ether_m:
                default_info["host_mac"] = ether_m.group(1)

            # Derive /24 subnet from host IP
            octets = default_info["host_ip"].split(".")
            if len(octets) == 4:
                default_info["subnet"] = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        except Exception as e:
            print(f"[!] Error detecting macOS network info: {e}")

    # Linux route detection
    elif "linux" in os_name:
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if parts[1] == "00000000":
                        default_info["interface"] = parts[0]
                        gw_hex = parts[2]
                        gw_ip = socket.inet_ntoa(bytes.fromhex(gw_hex)[::-1])
                        default_info["gateway_ip"] = gw_ip
                        break
            octets = default_info["host_ip"].split(".")
            default_info["subnet"] = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        except Exception as e:
            print(f"[!] Error detecting Linux network info: {e}")

    # Windows route detection
    elif "windows" in os_name:
        try:
            ipconfig_out = subprocess.check_output(["ipconfig"], text=True)
            gw_m = re.search(r"Default Gateway[ .]*: (\d+\.\d+\.\d+\.\d+)", ipconfig_out)
            if gw_m:
                default_info["gateway_ip"] = gw_m.group(1)
            octets = default_info["host_ip"].split(".")
            default_info["subnet"] = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        except Exception as e:
            print(f"[!] Error detecting Windows network info: {e}")

    return default_info


def resolve_hostname(ip, timeout=0.25):
    """Attempts reverse DNS / mDNS lookup with strict timeout to prevent thread stalling."""
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            host, _, _ = fut.result(timeout=timeout)
            return host
    except Exception:
        pass
    return ""


def measure_device_latency(ip, port=80, timeout=0.12):
    """
    Measures round-trip TCP connection latency in milliseconds.
    If port connection fails, falls back to ICMP/UDP latency.
    """
    start = time.time()
    for p in [port, 53, 443, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, p))
            s.close()
            elapsed_ms = (time.time() - start) * 1000.0
            return round(elapsed_ms, 1)
        except Exception:
            pass
    return round((time.time() - start) * 1000.0, 1)


def scan_device_open_ports(ip, ports_to_check=[21, 22, 53, 80, 443, 445, 554, 1900, 3000, 6466, 7000, 8001, 8002, 8008, 8009, 8080, 9100, 62078]):
    """Checks for active open TCP ports concurrently with tight non-blocking timeouts."""
    open_ports = []
    def _check(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.06)
            res = s.connect_ex((ip, p))
            s.close()
            if res == 0:
                return p
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports_to_check), 18)) as ex:
        results = ex.map(_check, ports_to_check)
        for r in results:
            if r is not None:
                open_ports.append(r)
    return sorted(open_ports)


def scan_local_lan(custom_subnet=None):
    """
    Performs a high-performance, multi-vector active sweep of the local LAN subnet:
    1. Sends UDP broadcast bursts (SSDP, NetBIOS, mDNS) to wake up Wi-Fi power-save devices.
    2. Concurrently probes all 254 IPs across key device listener ports (Web, Smart TV, Cast, AirPlay, Apple sync, SMB).
    3. Performs multi-pass harvesting of the system ARP cache to catch late-waking endpoints.
    4. Resolves hardware vendors, hostnames, open ports, and live round-trip latency.
    5. Intelligently classifies hardware (Routers, Smart TVs, iPhones, Android phones, Laptops, CCTV).
    """
    net_info = get_active_network_info()
    host_ip = net_info["host_ip"]
    gateway_ip = net_info["gateway_ip"]
    active_iface = net_info["interface"]

    # Determine subnet prefix e.g. "192.168.1"
    octets = host_ip.split(".")
    if len(octets) != 4 or host_ip == "127.0.0.1":
        octets = gateway_ip.split(".")
    prefix = f"{octets[0]}.{octets[1]}.{octets[2]}"
    bcast_ip = f"{prefix}.255"

    # Step 1: Broadcast wakeup bursts to trigger ARP resolution across Wi-Fi stations
    for b_target in [bcast_ip, "255.255.255.255"]:
        for port in [137, 1900, 5353]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.settimeout(0.06)
                if port == 1900:
                    payload = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
                elif port == 137:
                    payload = b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
                else:
                    payload = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                s.sendto(payload, (b_target, port))
                s.close()
            except Exception:
                pass

    # Step 2: Multi-port active probing across all 254 IPs
    # Ports that wake up and fingerprint Smart TVs, Phones, Laptops, IoT, and Routers
    SWEEP_PORTS = [80, 443, 8008, 8009, 8001, 3000, 7000, 62078, 445, 137, 5353, 554, 9100]

    def _probe_ip(ip):
        # Quick non-blocking TCP connect attempts
        for p in [80, 443, 8008, 7000, 62078, 445, 137]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.04)
                s.connect_ex((ip, p))
                s.close()
            except Exception:
                pass
        # UDP probe
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.settimeout(0.04)
            u.sendto(b"\x00", (ip, 5353))
            u.sendto(b"\x00", (ip, 137))
            u.close()
        except Exception:
            pass

    targets = [f"{prefix}.{i}" for i in range(1, 255)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
        list(ex.map(_probe_ip, targets))

    # Step 3: Multi-pass harvesting of the ARP table
    time.sleep(0.35)
    arp_entries = {}

    def _read_arp():
        try:
            arp_proc = subprocess.Popen(["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            arp_out, _ = arp_proc.communicate()
            for line in arp_out.splitlines():
                if "incomplete" in line.lower() or "ff:ff:ff:ff:ff:ff" in line.lower() or "1:0:5e" in line.lower():
                    continue
                m = re.search(r"\(([\d\.]+)\) at ([0-9a-fA-F:]+) on (\w+)", line)
                if m:
                    ip, mac, iface = m.group(1), m.group(2).upper(), m.group(3)
                    # Normalize MAC format
                    mac_parts = [p.zfill(2) for p in mac.split(":")]
                    mac_norm = ":".join(mac_parts).upper()
                    arp_entries[ip] = {"mac": mac_norm, "iface": iface}
                else:
                    m_win = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})", line)
                    if m_win:
                        ip = m_win.group(1)
                        mac = m_win.group(2).replace("-", ":").upper()
                        mac_parts = [p.zfill(2) for p in mac.split(":")]
                        mac_norm = ":".join(mac_parts).upper()
                        arp_entries[ip] = {"mac": mac_norm, "iface": active_iface}
        except Exception as e:
            print(f"[!] Error reading ARP cache: {e}")

    _read_arp()
    time.sleep(0.4)
    _read_arp()

    # Always ensure the local host machine is represented
    if host_ip != "127.0.0.1" and host_ip not in arp_entries:
        host_mac = net_info["host_mac"].upper()
        mac_norm = ":".join([p.zfill(2) for p in host_mac.split(":")])
        arp_entries[host_ip] = {"mac": mac_norm, "iface": active_iface}

    # Step 4: Parallel device deep-inspection and fingerprinting
    discovered_devices = []

    def _inspect_device(ip, data):
        mac = data["mac"]
        is_private = is_locally_administered_mac(mac)
        vendor = get_real_vendor(mac)
        hostname = resolve_hostname(ip)
        netbios_name = probe_netbios_name(ip)
        http_title = probe_http_banner_and_title(ip)

        # Extended port probe for fingerprinting
        open_ports = scan_device_open_ports(ip, [21, 22, 53, 80, 443, 445, 554, 1900, 3000, 6466, 7000, 8001, 8002, 8008, 8009, 8080, 9100, 62078])
        latency = measure_device_latency(ip)

        # Classify hardware type
        combined_identity = " ".join(filter(None, [hostname, netbios_name, http_title]))
        dev_type = classify_device_type(vendor, combined_identity, open_ports)

        # Intelligent Name Assignment
        last_octet = ip.split(".")[-1]

        if ip == gateway_ip:
            dev_type = "Router"
            name = f"Default Gateway ({http_title if http_title else vendor})"
        elif ip == host_ip:
            dev_type = "Laptop"
            name = f"NetGuard Host ({hostname or 'Admin Laptop'})"
        elif 62078 in open_ports:
            dev_type = "Phone"
            name = f"Apple iPhone / iPad (.{last_octet})"
        elif any(p in open_ports for p in [8001, 8002]):
            dev_type = "Smart TV"
            name = f"Samsung Smart TV (.{last_octet})"
        elif any(p in open_ports for p in [3000, 3001]):
            dev_type = "Smart TV"
            name = f"LG webOS Smart TV (.{last_octet})"
        elif any(p in open_ports for p in [8008, 8009]):
            dev_type = "Smart TV"
            name = f"Google Cast / Android TV (.{last_octet})"
        elif any(p in open_ports for p in [445, 139]):
            dev_type = "Laptop"
            name = f"Windows Workstation ({netbios_name or 'PC .' + last_octet})"
        elif "hikvision" in vendor.lower() or mac.startswith("3C:1B:F8") or 554 in open_ports:
            dev_type = "CCTV"
            name = f"Hikvision Security Camera (.{last_octet})"
        elif "ezviz" in vendor.lower() or mac.startswith("34:C6:DD"):
            dev_type = "CCTV"
            name = f"Ezviz Smart Camera / IoT (.{last_octet})"
        elif http_title:
            name = http_title
        elif netbios_name:
            name = f"Windows PC ({netbios_name})"
            dev_type = "Laptop"
        elif hostname:
            name = hostname.split(".")[0].replace("-", " ").title()
        elif is_private:
            name = f"Mobile Client (Private Wi-Fi .{last_octet})"
            dev_type = "Phone"
        else:
            name = f"{vendor.split()[0]} Endpoint (.{last_octet})"

        return {
            "ip": ip,
            "mac": mac,
            "name": name,
            "hostname": hostname or netbios_name or http_title,
            "vendor": vendor,
            "device_type": dev_type,
            "open_ports": open_ports,
            "latency_ms": latency,
            "is_gateway": (ip == gateway_ip),
            "is_localhost": (ip == host_ip)
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        futures = [ex.submit(_inspect_device, ip, data) for ip, data in arp_entries.items()]
        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                discovered_devices.append(res)
            except Exception as e:
                print(f"[!] Error inspecting device: {e}")

    # Sort so Gateway is first, then localhost, then by IP
    discovered_devices.sort(key=lambda d: (
        not d["is_gateway"],
        not d["is_localhost"],
        [int(x) for x in d["ip"].split(".") if x.isdigit()]
    ))

    return {
        "status": "success",
        "network_info": net_info,
        "devices_count": len(discovered_devices),
        "devices": discovered_devices
    }


def probe_single_device(ip):
    """
    On-demand single target probe:
    Probes a specific IP address directly, forces ARP resolution,
    detects ports, vendor, and classification, and returns device metadata.
    """
    ip = ip.strip()
    net_info = get_active_network_info()
    gateway_ip = net_info["gateway_ip"]
    host_ip = net_info["host_ip"]

    # Active probe to populate kernel ARP
    for p in [80, 443, 8008, 8009, 8001, 3000, 7000, 62078, 445, 137, 5353]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect_ex((ip, p))
            s.close()
        except Exception:
            pass

    time.sleep(0.3)

    # Lookup in ARP
    mac = ""
    try:
        arp_proc = subprocess.Popen(["arp", "-a"], stdout=subprocess.PIPE, text=True)
        arp_out, _ = arp_proc.communicate()
        for line in arp_out.splitlines():
            if f"({ip})" in line or f"{ip} " in line:
                m = re.search(r"([0-9a-fA-F:]{11,17}|[0-9a-fA-F\-]{17})", line)
                if m:
                    raw_mac = m.group(1).replace("-", ":").upper()
                    mac = ":".join([p.zfill(2) for p in raw_mac.split(":")])
                    break
    except Exception:
        pass

    if not mac:
        if ip == host_ip:
            mac = net_info["host_mac"].upper()
        else:
            # Generate deterministic synthetic MAC if firewall blocked ARP but host is valid
            mac = f"02:AA:BB:CC:{int(ip.split('.')[-2]):02X}:{int(ip.split('.')[-1]):02X}"

    vendor = get_real_vendor(mac)
    hostname = resolve_hostname(ip)
    netbios = probe_netbios_name(ip)
    http_title = probe_http_banner_and_title(ip)
    open_ports = scan_device_open_ports(ip, [21, 22, 53, 80, 443, 445, 554, 1900, 3000, 6466, 7000, 8001, 8002, 8008, 8009, 8080, 9100, 62078])
    latency = measure_device_latency(ip)

    combined_id = " ".join(filter(None, [hostname, netbios, http_title]))
    dev_type = classify_device_type(vendor, combined_id, open_ports)
    last_octet = ip.split(".")[-1]

    if 62078 in open_ports:
        dev_type = "Phone"
        name = f"Apple iPhone / iPad (.{last_octet})"
    elif any(p in open_ports for p in [8001, 8002]):
        dev_type = "Smart TV"
        name = f"Samsung Smart TV (.{last_octet})"
    elif any(p in open_ports for p in [3000, 3001]):
        dev_type = "Smart TV"
        name = f"LG webOS Smart TV (.{last_octet})"
    elif any(p in open_ports for p in [8008, 8009]):
        dev_type = "Smart TV"
        name = f"Google Cast / Android TV (.{last_octet})"
    elif any(p in open_ports for p in [445, 139]):
        dev_type = "Laptop"
        name = f"Windows Workstation ({netbios or 'PC .' + last_octet})"
    elif http_title:
        name = http_title
    elif netbios:
        name = f"Windows PC ({netbios})"
    elif hostname:
        name = hostname.split(".")[0].replace("-", " ").title()
    else:
        name = f"{dev_type} Endpoint (.{last_octet})"

    return {
        "ip": ip,
        "mac": mac,
        "name": name,
        "vendor": vendor,
        "device_type": dev_type,
        "open_ports": open_ports,
        "latency_ms": latency,
        "is_gateway": (ip == gateway_ip),
        "is_localhost": (ip == host_ip)
    }


def import_real_devices_to_inventory(discovered_devices):
    """
    Imports scanned physical devices into NetGuard's active database inventory.
    Generates tailored baseline profiles so real devices can be immediately monitored.
    """
    imported_ids = []
    for d in discovered_devices:
        mac = d["mac"]
        ip = d["ip"]
        name = d["name"]
        dev_type = d["device_type"]
        is_gw = d["is_gateway"]

        existing = DeviceModel.get_by_mac(mac)
        if not existing:
            # Create new device record
            dev_id = DeviceModel.create(
                mac=mac,
                ip=ip,
                name=name,
                device_type=dev_type,
                is_whitelisted=is_gw  # Automatically whitelist gateway to prevent accidental self-isolation!
            )
            # Assign baseline based on device type
            if dev_type == "Router":
                BaselineModel.update_baseline(dev_id, dns_avg=150.0, ips_avg=25.0, ports_avg=8.0, bytes_kb_avg=1200.0, increment_sample=False)
            elif dev_type == "Printer":
                BaselineModel.update_baseline(dev_id, dns_avg=3.0, ips_avg=1.0, ports_avg=2.0, bytes_kb_avg=60.0, increment_sample=False)
            elif dev_type == "Phone":
                BaselineModel.update_baseline(dev_id, dns_avg=30.0, ips_avg=8.0, ports_avg=4.0, bytes_kb_avg=180.0, increment_sample=False)
            else:
                BaselineModel.update_baseline(dev_id, dns_avg=45.0, ips_avg=12.0, ports_avg=5.0, bytes_kb_avg=350.0, increment_sample=False)

            BaselineModel.set_lock(dev_id, True)
            imported_ids.append(dev_id)
        else:
            # Update IP, name, and device type if refined by multi-protocol scanner
            DeviceModel.update_metadata(existing["id"], name=name, device_type=dev_type, ip=ip)
            imported_ids.append(existing["id"])

    return imported_ids


if __name__ == "__main__":
    print("[*] Testing NetGuard Physical LAN Discovery...")
    info = get_active_network_info()
    print(f"[*] Network Info: {info}")
    results = scan_local_lan()
    print(f"[+] Scan Complete: Found {results['devices_count']} devices on {results['network_info']['subnet']}")
    for d in results["devices"]:
        print(f"   -> IP: {d['ip']:<15} | MAC: {d['mac']:<18} | Vendor: {d['vendor']:<20} | Name: {d['name']} | Latency: {d['latency_ms']}ms | Ports: {d['open_ports']}")
