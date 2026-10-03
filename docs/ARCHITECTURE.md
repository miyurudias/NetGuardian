# NetGuard: System Architecture & Technical Specifications

> **Computing Project (CNT 5015) — Technical Specification Document**  
> **Cardiff Metropolitan University / ICBT Campus**

---

## 1. System Overview & High-Level Architecture

NetGuard operates as a lightweight, passive behavior-based Network Intrusion Detection and Prevention System (NIDPS). It sits logically within the local area network (LAN), capturing L3/L4 packet metadata, calculating per-device behavioral drift, computing risk scores, and dispatching containment actions.

```
+---------------------------------------------------------------------------------+
|                                Local Subnet (LAN)                               |
|   [Laptop 01]     [Phone 01]     [Printer]     [Laptop 02]     [CCTV Camera]    |
+---------------------------------------------------------------------------------+
                                      |
                         (Passive Traffic Metadata)
                                      v
+---------------------------------------------------------------------------------+
|                                 NetGuard Core                                   |
|                                                                                 |
|  +------------------------+   +-----------------------+   +------------------+  |
|  | Device Discovery       |   | Dual-Mode Sniffer     |   | Baseline Engine  |  |
|  | - MAC/IP mapping       |-->| - Live Scapy capture  |-->| - Rolling window |  |
|  | - Hardware heuristics  |   | - Lab Traffic Replay  |   | - Moving average |  |
|  +------------------------+   +-----------------------+   +------------------+  |
|                                                                     |           |
|  +------------------------------------------------------------------+           |
|  |                                                                              |
|  v                                                                              |
|  +-----------------------+    +-----------------------+   +------------------+  |
|  | Behaviour Drift Engine|--->| Weighted Risk Engine  |-->| Quarantine Engine|  |
|  | - DNS, IPs, Ports, KB |    | - Anomaly Indicators  |   | - Router ACL gen |  |
|  | - Delta calculations  |    | - 0 to 100 scoring    |   | - OS firewall    |  |
|  +-----------------------+    +-----------------------+   +------------------+  |
+---------------------------------------------------------------------------------+
                                      |
                     (Database & Web Application Layer)
                                      v
+---------------------------------------------------------------------------------+
|  SQLite Storage: [devices] [baselines] [traffic] [risk_history] [alerts] [logs] |
|  Flask Web Server: REST API, Chart.js Visualizer, Live Demo Lab, Audit Exporter  |
+---------------------------------------------------------------------------------+
```

---

## 2. Mathematical Formulations

### 2.1 Behaviour Drift Score ($S_{\text{drift}}$)
For each device $d$ across metrics $m \in \{\text{ports}, \text{ips}, \text{dns}, \text{bytes}\}$:

$$\text{Drift}_{\text{raw}, m} = \max\left(0, \frac{\text{Observed}_m - \text{Baseline}_m}{\max(1, \text{Baseline}_m)}\right) \times 100$$

$$\text{Score}_{\text{norm}, m} = \min\left(100.0, \frac{\text{Observed}_m / \text{Baseline}_m - 1.0}{M_m - 1.0} \times 100.0\right)$$

Where $M_m$ is the saturation multiplier for metric $m$:
- $M_{\text{ports}} = 9.0$
- $M_{\text{ips}} = 8.0$
- $M_{\text{dns}} = 9.0$
- $M_{\text{bytes}} = 20.0$

The composite Behaviour Drift Score is a convex combination:
$$S_{\text{drift}} = \sum_{m} w_m \cdot \text{Score}_{\text{norm}, m}$$
Where $w_{\text{ports}} = 0.30$, $w_{\text{ips}} = 0.25$, $w_{\text{dns}} = 0.25$, $w_{\text{bytes}} = 0.20$.

### 2.2 Weighted Risk Scoring Model
$$\text{Total Risk Score} = \min\left(100, \sum_{i=1}^{5} I_i \cdot W_i\right)$$

Where active indicators $I_i \in \{0, 1\}$:
1. **$I_{\text{scan}}$ (Port Scanning)**: $W_1 = 30$ (Triggered if ports probed $\ge 8$ or $> 3.5\times$ baseline)
2. **$I_{\text{rogue}}$ (Unknown Device)**: $W_2 = 20$ (Triggered if MAC has no prior profile)
3. **$I_{\text{dns}}$ (DNS Anomaly)**: $W_3 = 20$ (Triggered if DNS count $\ge 3.0\times$ baseline and $> 30$)
4. **$I_{\text{spike}}$ (Traffic Surge)**: $W_4 = 15$ (Triggered if transfer $\ge 4.0\times$ baseline and $> 200$ KB)
5. **$I_{\text{dest}}$ (Unfamiliar Destinations)**: $W_5 = 15$ (Triggered if distinct external IPs $\ge \text{baseline} + 3$)

---

## 3. Database Schema (SQLite)

- **`devices`**: Core identity table storing MAC, IP, hardware type, status (`Normal`, `Suspicious`, `Critical`, `Quarantined`), and current scores.
- **`baselines`**: Historical empirical averages per device (`dns_queries_avg`, `distinct_ips_avg`, `ports_contacted_avg`, `bytes_transferred_kb_avg`, `sample_count`, `is_locked`).
- **`traffic_samples`**: Interval-based raw telemetry (`dns_count`, `distinct_ips_count`, `port_count`, `bytes_sent`, `bytes_recv`).
- **`risk_history`**: Chronological risk assessments and points breakdown.
- **`alerts`**: High and critical security incidents (`severity`, `indicator`, `message`, `acknowledged`).
- **`quarantine_logs`**: Audit trail of every automated and manual containment or release event.
- **`system_config`**: Dynamically tunable thresholds and weights.

---

## 4. Multi-Backend Quarantine Architecture

When `Total Risk Score` $\ge 70$, NetGuard invokes `core/quarantine_manager.py`:
1. **Cisco IOS / Mikrotik ACL Simulation**:
   ```
   ip access-list extended NETGUARD-QUARANTINE
     deny ip host <IP> any log
     permit ip any any
   ```
2. **Linux Backend**: `iptables -I FORWARD -s <IP> -j DROP`
3. **macOS Backend**: `pfctl -t netguard_quarantine -T add <IP>`
4. **Windows Backend**: `netsh advfirewall firewall add rule name="NetGuard_Block_<IP>" dir=in/out action=block remoteip=<IP>`
