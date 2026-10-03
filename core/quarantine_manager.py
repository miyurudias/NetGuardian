"""
NetGuard - Multi-Backend Quarantine Manager
Executes automated and manual network isolation across Windows, Linux, macOS,
and Simulated Enterprise Router (Cisco / Mikrotik ACL) environments.
(Section 8.4 of Computing Project Proposal)
"""

import sys
import platform
import subprocess
from database.models import DeviceModel, QuarantineLogModel, AlertModel, ConfigModel
import config


def generate_cisco_acl_script(device_ip, device_mac, action="DENY"):
    """Generates standard Cisco IOS / Mikrotik ACL configuration snippet."""
    if action == "DENY":
        return (
            f"! NetGuard Automated Defense: Isolate {device_ip} ({device_mac})\n"
            f"ip access-list extended NETGUARD-QUARANTINE\n"
            f"  10 deny ip host {device_ip} any log\n"
            f"  20 permit ip any any\n"
            f"interface GigabitEthernet0/1\n"
            f"  ip access-group NETGUARD-QUARANTINE in\n"
            f"! Device isolated from LAN and WAN segments."
        )
    else:
        return (
            f"! NetGuard Automated Defense: Restore {device_ip} ({device_mac})\n"
            f"ip access-list extended NETGUARD-QUARANTINE\n"
            f"  no 10\n"
            f"! Normal access restored."
        )


def execute_system_isolation(device, backend, action="BLOCK"):
    """
    Executes quarantine command on the appropriate OS firewall backend
    or formats simulated router ACLs.
    """
    ip = device["ip"]
    mac = device["mac"]
    dev_name = device["name"]
    command_executed = ""
    command_succeeded = True
    os_name = platform.system().lower()

    if backend == "SIMULATED":
        command_executed = generate_cisco_acl_script(ip, mac, "DENY" if action == "BLOCK" else "PERMIT")

    elif backend == "WINDOWS" or (backend == "AUTO" and "windows" in os_name):
        rule_in = f"NetGuard_Block_In_{ip}"
        rule_out = f"NetGuard_Block_Out_{ip}"
        if action == "BLOCK":
            command_executed = (
                f'netsh advfirewall firewall add rule name="{rule_in}" dir=in action=block remoteip={ip} && '
                f'netsh advfirewall firewall add rule name="{rule_out}" dir=out action=block remoteip={ip}'
            )
            try:
                result_in = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_in}", "dir=in", "action=block", f"remoteip={ip}"],
                    capture_output=True, text=True, check=False
                )
                result_out = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_out}", "dir=out", "action=block", f"remoteip={ip}"],
                    capture_output=True, text=True, check=False
                )
                command_succeeded = result_in.returncode == 0 and result_out.returncode == 0
            except Exception as e:
                command_succeeded = False
                command_executed += f" (OS call error: {e})"
        else:
            command_executed = f'netsh advfirewall firewall delete rule name="{rule_in}"'
            try:
                result_in = subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"], capture_output=True, check=False)
                result_out = subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"], capture_output=True, check=False)
                command_succeeded = result_in.returncode == 0 and result_out.returncode == 0
            except Exception as e:
                command_succeeded = False
                command_executed += f" (OS call error: {e})"

    elif backend == "LINUX" or (backend == "AUTO" and "linux" in os_name):
        if action == "BLOCK":
            command_executed = f"iptables -I FORWARD -s {ip} -j DROP"
            try:
                result = subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True, check=False)
                command_succeeded = result.returncode == 0
            except Exception as e:
                command_succeeded = False
                command_executed += f" (OS call error: {e})"
        else:
            command_executed = f"iptables -D FORWARD -s {ip} -j DROP"
            try:
                result = subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True, check=False)
                command_succeeded = result.returncode == 0
            except Exception as e:
                command_succeeded = False
                command_executed += f" (OS call error: {e})"

    elif backend == "PFCTL" or (backend == "AUTO" and "darwin" in os_name):
        cmd = "add" if action == "BLOCK" else "delete"
        command_executed = f"pfctl -t netguard_quarantine -T {cmd} {ip}"
        try:
            result = subprocess.run(["pfctl", "-t", "netguard_quarantine", "-T", cmd, ip], capture_output=True, check=False)
            command_succeeded = result.returncode == 0
        except Exception as e:
            command_succeeded = False
            command_executed += f" (OS call error: {e})"

    else:
        command_executed = generate_cisco_acl_script(ip, mac, "DENY" if action == "BLOCK" else "PERMIT")

    return command_executed, command_succeeded


def quarantine_device(device_id, reason, manual=False):
    """
    Isolates a device from the network.
    Checks whitelist protection before proceeding.
    """
    device = DeviceModel.get_by_id(device_id)
    if not device:
        return False, "Device not found."

    # Whitelist protection check
    if device.get("is_whitelisted"):
        AlertModel.create(
            device_id=device_id,
            severity="Medium",
            indicator="Whitelist Exemption",
            message=f"Device {device['name']} exceeded risk threshold but was spared due to Whitelist protection.",
            drift_pct=device.get("current_drift_score", 0),
            risk_score=device.get("current_risk_score", 0)
        )
        return False, f"Device {device['name']} is Whitelisted. Quarantine aborted."

    backend = ConfigModel.get("quarantine_backend", config.QUARANTINE_BACKEND)
    cmd, command_succeeded = execute_system_isolation(device, backend, action="BLOCK")

    if not command_succeeded:
        QuarantineLogModel.log(
            device_id=device_id,
            action="QUARANTINE_FAILED",
            mechanism=backend,
            command=cmd,
            reason=reason
        )
        AlertModel.create(
            device_id=device_id,
            severity="Critical",
            indicator="Quarantine Enforcement Failed",
            message=f"[CONTAINMENT FAILED] NetGuard could not isolate {device['name']} ({device['ip']}).",
            drift_pct=device.get("current_drift_score", 0),
            risk_score=device.get("current_risk_score", 0)
        )
        return False, f"Isolation command failed via {backend}; host was not marked quarantined."

    # Update state in Database
    DeviceModel.set_quarantined(device_id, is_quarantined=True, reason=reason)
    action_label = "MANUAL_QUARANTINE" if manual else "AUTO_QUARANTINE"
    QuarantineLogModel.log(
        device_id=device_id,
        action=action_label,
        mechanism=backend,
        command=cmd,
        reason=reason
    )

    # Create Critical Incident Alert
    AlertModel.create(
        device_id=device_id,
        severity="Critical",
        indicator="Device Quarantined",
        message=f"[QUARANTINE ACTIVE] Device {device['name']} ({device['ip']}) has been isolated: {reason}",
        drift_pct=device.get("current_drift_score", 0),
        risk_score=device.get("current_risk_score", 0)
    )

    return True, f"Device {device['name']} ({device['ip']}) successfully quarantined via {backend}."


def release_device(device_id, admin_reason="Administrator manual unblock"):
    """
    Releases a quarantined device, restoring normal network connectivity.
    Resets threat scores to baseline.
    """
    device = DeviceModel.get_by_id(device_id)
    if not device:
        return False, "Device not found."

    backend = ConfigModel.get("quarantine_backend", config.QUARANTINE_BACKEND)
    cmd, command_succeeded = execute_system_isolation(device, backend, action="RELEASE")

    if not command_succeeded:
        QuarantineLogModel.log(
            device_id=device_id,
            action="RELEASE_FAILED",
            mechanism=backend,
            command=cmd,
            reason=admin_reason
        )
        return False, f"Release command failed via {backend}; quarantine state was not changed."

    # Update database state
    DeviceModel.set_quarantined(device_id, is_quarantined=False, reason=None)
    DeviceModel.update_scores(device_id, risk_score=0, drift_score=0.0, status="Normal")

    QuarantineLogModel.log(
        device_id=device_id,
        action="UNBLOCK_RELEASE",
        mechanism=backend,
        command=cmd,
        reason=admin_reason
    )

    AlertModel.create(
        device_id=device_id,
        severity="Low",
        indicator="Quarantine Released",
        message=f"Device {device['name']} ({device['ip']}) unblocked and returned to Normal monitoring.",
        drift_pct=0.0,
        risk_score=0
    )

    return True, f"Device {device['name']} released from quarantine."
