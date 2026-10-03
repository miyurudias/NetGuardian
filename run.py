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
import subprocess
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

import config


def run_supervised():
    """Keep one server child on the port and relaunch it after a UI restart."""
    child_env = os.environ.copy()
    child_env["NETGUARD_SUPERVISED"] = "1"
    command = [sys.executable, str(BASE_DIR / "run.py"), "--_serve"]

    while True:
        child = subprocess.Popen(command, cwd=BASE_DIR, env=child_env.copy())
        try:
            exit_code = child.wait()
        except KeyboardInterrupt:
            child.terminate()
            child.wait()
            return 0
        if exit_code != config.RESTART_EXIT_CODE:
            return exit_code
        # --live applies at initial launch; later restarts use the saved setting.
        child_env.pop("NETGUARD_MODE", None)


if __name__ == "__main__":
    if "--_serve" in sys.argv:
        from app import start_server
        start_server()
    else:
        sys.exit(run_supervised())
