#!/usr/bin/env python3
"""
NetGuard - One-Click Application Launcher
Cross-platform start script for Windows, macOS, and Linux.
Usage:
    python run.py
    python run.py --port 8080
    python run.py --live (to enable live packet capture)
"""

import sys
import os
from pathlib import Path

# Ensure NetGuard is in PYTHONPATH
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Parse CLI arguments
for i, arg in enumerate(sys.argv):
    if arg == "--port" and i + 1 < len(sys.argv):
        os.environ["NETGUARD_PORT"] = sys.argv[i + 1]
    elif arg == "--live":
        os.environ["NETGUARD_MODE"] = "LIVE"
    elif arg == "--debug":
        os.environ["NETGUARD_DEBUG"] = "True"

try:
    import flask
    import scapy
except ImportError as e:
    print(f"\n[!] Missing dependency: {e}")
    print("[*] Please install required dependencies by running:")
    print("    pip install -r requirements.txt\n")
    sys.exit(1)

from app import start_server

if __name__ == "__main__":
    start_server()
