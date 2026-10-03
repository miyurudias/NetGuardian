"""Checks the Windows adapter metadata used for live capture and local scope."""

import unittest
from unittest.mock import patch, MagicMock

from core.network_scanner import get_active_network_info


class TestNetworkInfo(unittest.TestCase):
    def test_windows_uses_active_adapter_mask_mac_and_gateway(self):
        ipconfig = """Windows IP Configuration

Wireless LAN adapter Wi-Fi:
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF
   IPv4 Address. . . . . . . . . . . : 10.20.30.45(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . : 10.20.30.1
"""
        sock = MagicMock()
        sock.getsockname.return_value = ("10.20.30.45", 12345)
        with patch("core.network_scanner.platform.system", return_value="Windows"), \
             patch("core.network_scanner.socket.socket", return_value=sock), \
             patch("core.network_scanner.subprocess.check_output", return_value=ipconfig):
            info = get_active_network_info()

        self.assertEqual(info["interface"], "Wi-Fi")
        self.assertEqual(info["host_mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(info["gateway_ip"], "10.20.30.1")
        self.assertEqual(info["subnet"], "10.20.30.0/24")

    def test_windows_lab_without_default_route_uses_adapter_ipv4(self):
        ipconfig = """Windows IP Configuration

Wireless LAN adapter Wi-Fi:
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF
   IPv4 Address. . . . . . . . . . . : 10.20.30.45(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
"""
        sock = MagicMock()
        sock.connect.side_effect = OSError("No default route")
        with patch("core.network_scanner.platform.system", return_value="Windows"), \
             patch("core.network_scanner.socket.socket", return_value=sock), \
             patch("core.network_scanner.subprocess.check_output", return_value=ipconfig):
            info = get_active_network_info()
        self.assertEqual(info["host_ip"], "10.20.30.45")
        self.assertEqual(info["subnet"], "10.20.30.0/24")
        self.assertEqual(info["gateway_ip"], "")


if __name__ == "__main__":
    unittest.main()
