# NetGuard: Behavioural Fingerprinting and Risk-Based Quarantine

> **Final Year Computing Project (CNT 5015)**  
> **Cardiff Metropolitan University / ICBT Campus**  
> **Project Team:**
> - **K.P. Miyuru Sandeepa** (Leader / Networking Lead) — `st20344978` / `ICBT/CL/HDNET/CMU/55/33`
> - **E.H. Harshana Adithya** (Cybersecurity & Detection Lead) — `st20344973` / `ICBT/CL/HDNET/CMU/55/29`
> - **A. Isara Kanchana** (Dashboard & Application Lead) — `st20344977` / `ICBT/CL/HDNET/CMU/55/32`
>
> **Lecturer / Supervisor:** Miss Hashini

---

## 🛡️ Project Overview

Small networks in cafes, tutorial centers, hostels, schools, and small branch offices typically lack dedicated network administrators. Traditional routers merely log connected devices without visibility into whether a device is behaving normally. Compromised hosts can silently conduct reconnaissance, connect to command-and-control (C2) nodes, and exfiltrate confidential data undetected.

**NetGuard** solves this problem by shifting from packet-payload signatures and complex, unaffordable enterprise machine learning to **empirical per-device behavioral baselining**:
$$\text{Behaviour Drift} = \text{Current Behaviour} - \text{Historical Normal Behaviour}$$

When a host exhibits anomalous behavioral drift exceeding defined weighted risk thresholds, NetGuard issues real-time administrator alerts and automatically enforces isolation (via router ACL scripts, Linux iptables, macOS pfctl, or Windows firewall).

---

## 🌟 Key Features

1. **Passive Traffic Metadata Capture (Dual-Mode)**:
   - **Lab / Simulated Mode (Default)**: Ingests synthetic network traffic for the 5 canonical devices without requiring root privileges or risk of interrupting local network connectivity. Works on **Windows, macOS, and Linux**.
   - **Live Mode**: Uses Scapy to passively sniff raw L3/L4 packet headers (MAC, IP, TCP/UDP ports, DNS queries, transfer volumes) on a designated interface.
2. **Per-Device Empirical Baselining**:
   - Maintains historical moving averages across 4 behavioral dimensions:
     - DNS queries per interval
     - Distinct remote external IP destinations
     - Destination ports contacted
     - Data volume transferred (KB)
3. **Multi-Dimensional Behaviour Drift Calculation**:
   - Quantifies individual metric deviations ($\uparrow \%$) and computes a composite 0–100% drift score.
4. **Weighted Anomaly Risk Scoring Engine**:
   - Port scanning detected: **+30 points**
   - Unknown / rogue device: **+20 points**
   - DNS anomaly / tunneling: **+20 points**
   - Traffic volume surge: **+15 points**
   - Unfamiliar destination connection: **+15 points**
   - **Risk Bands**: Low (0–39: Green), Medium (40–69: Amber / Suspicious), High (70–100: Red / Critical).
5. **Automated & Manual Multi-Backend Quarantine**:
   - **Simulated Cisco / Mikrotik ACL**: Formats real router access-lists for classroom demonstrations.
   - **Windows Firewall**: `netsh advfirewall` execution.
   - **Linux Firewall**: `iptables` / `nftables` forwarding drop rules.
   - **macOS Packet Filter**: `pfctl` quarantine table entries.
   - Whitelist protection prevents critical infrastructure from being isolated.
6. **Polished Dark-Mode Web Dashboard**:
   - Real-time Threat Gauge & KPI cards.
   - Searchable device inventory table with live status badges.
   - Device deep-dive profile with Chart.js Radar chart comparing baseline vs current activity.
   - Interactive Live Demo Lab with 1-click viva presentation controls.
   - Academic evaluation and metrics export (PDF/Print view answering RQ1, RQ2, RQ3).

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.9+ (Installed on Windows, macOS, or Linux)
- Standard web browser (Chrome, Edge, Safari, Firefox)

### 1. Installation

Clone or copy the `NetGuard` directory to your computer, then install the lightweight dependencies:

```bash
# Navigate to NetGuard folder
cd NetGuard

# Create and activate a Python virtual environment
# On macOS / Linux:
python3 -m venv .venv
source .venv/bin/activate

# On Windows (Command Prompt or PowerShell):
python -m venv .venv
.venv\Scripts\activate

# Install dependencies (Flask and Scapy)
pip install -r requirements.txt
```

### 2. Launching NetGuard

Run the one-click launcher:

```bash
python run.py
```

Then open your browser and navigate to:
👉 **[http://localhost:5000](http://localhost:5000)**

*(Optional flags: `python run.py --port 8080`, `python run.py --live`)*

---

## 🎓 Viva Presentation & Live Demonstration (Section 15)

NetGuard includes a dedicated **Live Demo Lab** (`/simulation`) with a 4-phase sequence designed explicitly for the final project assessment:

1. **Phase 1 (Normal Baseline)**: Populates all 5 canonical devices (Laptop 01, Phone 01, Printer, Laptop 02, CCTV). All devices display **LOW** risk (Green).
2. **Phase 2 (Port Scan Attack)**: Initiates a port scan from Laptop 02. The dashboard updates in real time, elevating Laptop 02 to **SUSPICIOUS** (Amber, score ~40–50).
3. **Phase 3 (Escalate & Isolate)**: Injects DNS tunneling and suspicious C2 destinations. Risk score crosses the critical threshold ($\ge 70$), and NetGuard enforces **AUTOMATIC QUARANTINE**! The host is blocked, and router ACL commands are generated.
4. **Phase 4 (Admin Unblock)**: Demonstrates the administrator review workflow and one-click unblock to restore normal access.

*For speaking points and script for the 3 students, see [docs/VIVA_DEMO_GUIDE.md](docs/VIVA_DEMO_GUIDE.md).*

---

## 🧪 Running Automated Unit Tests

NetGuard includes an automated test suite verifying all mathematical models, risk scores, quarantine enforcement, and REST API routes:

```bash
python -m unittest discover -s tests
```

---

## 📂 Project Structure

```
NetGuard/
├── app.py                      # Flask Application & REST API
├── config.py                   # Thresholds, indicator weights, and settings
├── requirements.txt            # Python dependencies (Flask, Scapy)
├── run.py                      # Cross-platform one-click launcher
│
├── core/                       # Core Networking & Detection Engines
│   ├── device_profiler.py      # Device discovery and hardware categorization
│   ├── capture_engine.py       # Dual-mode traffic sniffer & interval evaluator
│   ├── baseline_engine.py      # Rolling averages and baseline builder
│   ├── drift_engine.py         # Behaviour Drift Score mathematical calculator
│   ├── risk_engine.py          # Anomaly indicator evaluation and risk scoring
│   └── quarantine_manager.py   # Multi-backend quarantine controller
│
├── database/                   # SQLite Persistence Layer
│   ├── db.py                   # Connection manager and table schemas
│   ├── models.py               # Data models (Devices, Baselines, Alerts, Logs)
│   └── seed_data.py            # Canonical device seeder (Section 15 devices)
│
├── simulator/                  # Attack Simulation & Demo Engine
│   ├── normal_traffic.py       # Benign background traffic generator
│   ├── attack_scenarios.py     # Port scan, DNS tunneling, exfiltration, rogue device
│   └── scenario_runner.py      # 4-phase viva demo sequence runner
│
├── static/                     # CSS and Vanilla JavaScript
│   ├── css/styles.css          # Dark-mode styling and glowing accents
│   └── js/                     # Real-time dashboard, charts, and demo controls
│
├── templates/                  # Jinja2 HTML Views
│   ├── base.html               # Navigation bar and master layout
│   ├── index.html              # Main dashboard with threat gauge & device inventory
│   ├── device_detail.html      # Baseline comparison radar chart & drift table
│   ├── alerts.html             # Security incidents feed
│   ├── quarantine.html         # Active isolation control and Cisco ACL scripts
│   ├── simulation.html         # Interactive viva presentation control deck
│   ├── reports.html            # Academic evaluation report (RQ1, RQ2, RQ3)
│   └── settings.html           # Indicator weights and threshold tuning
│
├── tests/                      # Automated Verification Test Suite
│   ├── test_drift.py           # Mathematical drift model tests
│   ├── test_risk.py            # Weighted risk scoring tests
│   ├── test_quarantine.py      # Isolation and whitelist tests
│   └── test_api.py             # Web API endpoint tests
│
└── docs/                       # Academic Documentation Kit
    ├── ARCHITECTURE.md         # Full dissertation technical writeup
    ├── VIVA_DEMO_GUIDE.md      # Script and spoken dialogue for the 3 students
    └── EVALUATION_METRICS.md   # Empirical findings for RQ1, RQ2, and RQ3
```

---

## 📜 Academic Integrity & License
Developed for the Cardiff Metropolitan University / ICBT Campus BSc (Hons) Computing Project (Module CNT 5015). Released under the MIT License.
