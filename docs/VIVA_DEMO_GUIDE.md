# NetGuard: Live Viva Demonstration & Presentation Guide

> **Module:** Computing Project (CNT 5015)  
> **Institution:** ICBT Campus & Cardiff Metropolitan University  
> **Supervisor:** Miss Hashini  
> **Team Members:**  
> - **Member 1 (Leader / Networking Lead):** K.P. Miyuru Sandeepa  
> - **Member 2 (Cybersecurity & Detection Lead):** E.H. Harshana Adithya  
> - **Member 3 (Dashboard & Application Lead):** A. Isara Kanchana  

---

## 🎯 Demonstration Objective
To demonstrate to the examiners a complete, real-time lifecycle of network threat mitigation in an unmanaged small network environment:
$$\text{Normal Baseline} \longrightarrow \text{Reconnaissance Attack} \longrightarrow \text{Threat Escalation} \longrightarrow \text{Automated Quarantine} \longrightarrow \text{Admin Remediation}$$

---

## 🖥️ Setup Before the Demonstration

1. Open a terminal on the presentation laptop:
   ```bash
   cd NetGuard
   python run.py
   ```
2. Open your web browser and navigate to:
   **`http://localhost:5050`**
3. Keep two browser tabs open:
   - **Tab 1:** Main Dashboard (`/`)
   - **Tab 2:** Live Demo Lab (`/simulation`)

---

## 🎙️ Step-by-Step Presentation Script

### Introduction (Shared / Leader Miyuru)
> *"Good morning / afternoon Miss Hashini and respected examiners. We are proud to present **NetGuard**, a lightweight, behavior-based network security solution designed specifically for resource-constrained small networks like cafes, coaching centers, hostels, and small offices.*
>
> *Unlike enterprise security appliances that cost thousands of dollars or complex machine learning models that require massive training datasets, NetGuard answers one fundamental question: **'Is this device behaving as it usually does?'**"*

---

### Phase 1: Normal Network Baseline (Spoken by Member 1: Miyuru Sandeepa)
1. In **Tab 2 (`/simulation`)**, click **"1. Run Baseline"**.
2. Switch to **Tab 1 (`/`)**.
3. **Talking Points (Miyuru):**
   > *"As Networking Lead, I designed the device discovery and traffic ingestion architecture. Here on the dashboard, you see five devices connected to our lab subnet:*
   > - *Laptop 01 (Staff Workstation)*
   > - *Phone 01 (Staff Mobile)*
   > - *Office Network Printer*
   > - *Laptop 02 (Student Lab Laptop)*
   > - *CCTV Security Camera*
   >
   > *NetGuard passively collects L3/L4 metadata: MAC/IP addresses, destination ports, DNS request rates, and byte transfer volumes. Notice that all five devices have a **LOW risk score** (colored green), operating safely within their historical behavioral baselines. The peak threat gauge sits at 0."*

---

### Phase 2: Controlled Port Scan Attack (Spoken by Member 2: Harshana Adithya)
1. In **Tab 2 (`/simulation`)**, click **"2. Trigger Scan"**.
2. Switch to **Tab 1 (`/`)**.
3. **Talking Points (Harshana):**
   > *"As Cybersecurity & Detection Lead, I developed the behavioral drift algorithm and the weighted risk scoring engine. In this scenario, Laptop 02 has become infected or compromised and initiates a reconnaissance port scan across 30 ports on the network.*
   >
   > *Notice what happens immediately on the dashboard:*
   > - *Laptop 02's status changes from Green (Normal) to **Amber (SUSPICIOUS)**.*
   > - *Its risk score jumps by **+30 points** due to our Port Scanning detection indicator.*
   > - *A security warning alert appears in real-time in the incident feed.*
   > - *However, notice that NetGuard does **not** prematurely block the device yet, preventing false-positive disruption during minor anomalies."*

---

### Phase 3: Threat Escalation & Automated Quarantine (Spoken by Member 2: Harshana & Member 1: Miyuru)
1. In **Tab 2 (`/simulation`)**, click **"3. Escalate Risk"**.
2. Switch to **Tab 1 (`/`)** and then click into **Quarantine (`/quarantine`)**.
3. **Talking Points (Harshana):**
   > *"The synthetic scenario now adds a high DNS query rate, unfamiliar destinations, and a traffic-volume spike. These are indicators of suspicious behaviour; the demo does not prove DNS tunneling or data exfiltration.*
   > - *Our DNS anomaly indicator adds **+20 points**.*
   > - *The unfamiliar destinations indicator adds **+15 points**.*
   > - *The traffic surge adds **+15 points**.*
   >
   > *The combined risk score surpasses 70 points, crossing into the **CRITICAL** band."*

4. **Talking Points (Miyuru - Simulated Quarantine):**
   > *"Once the score crosses the threshold, NetGuard records a quarantine decision for Laptop 02 in the demonstration database.*
   > - *The default backend generates an ACL policy preview; it does not change the router or disconnect a real client.*
   > - *On the Quarantine page, we can inspect the proposed access-list:*
   >   `ip access-list extended NETGUARD-QUARANTINE`
   >   `deny ip host 192.168.1.45 any log`
   > - *A real containment claim would need an authorized gateway or router integration and an independent connectivity test."*

---

### Phase 4: Forensic Investigation & Remediation (Spoken by Member 3: Isara Kanchana)
1. Click on **Laptop 02** in the device list to open `/device/4`.
2. **Talking Points (Isara):**
   > *"As Dashboard and Application Lead, I built the Flask backend, SQLite persistence schema, and interactive monitoring dashboard.*
   >
   > *When the administrator inspects the compromised device:*
   > - *They are presented with our **Behavior Drift Radar Chart**, contrasting the historical baseline in blue against the anomalous surge in orange across all four dimensions.*
   > - *The Behaviour Drift table mathematically shows the exact drift percentages: DNS queries surged over 600%, ports contacted surged over 700%, and data transfer surged proportionally.*
   > - *After the simulated investigation, they can click **'Release from Quarantine'** to clear the simulated state and resume monitoring."*

3. Click **"Release from Quarantine"** and show that Laptop 02 returns to Green (Normal).

---

### Phase 5: Academic Evaluation & Answering Research Questions (Shared)
1. Navigate to **Evaluation (`/reports`)**.
2. **Talking Points (Isara & Team):**
   > *"The automated runner repeats eight synthetic scenarios three times each. The report page shows the run-level outcomes and provides the CSV used to calculate the summary. These results verify the demonstration pipeline. Live detection accuracy, false-positive rate, and isolation time require controlled network measurements before we claim them as findings."*

---

## ❓ Probable Examiner Questions & Suggested Answers

**Q1: Why did you choose behavioral fingerprinting instead of signature-based IDS like Snort?**  
*Answer:* "Signature-based IDSs require constant updates and only detect known attack patterns. In small networks with IoT devices and laptops, zero-day malware or custom scripts easily bypass signatures. Behavioral fingerprinting detects the anomaly regardless of what malware is used, based on how the device behaves compared to its historical normal."

**Q2: What happens if an authorized server or admin laptop gets infected? Will it break the network?**  
*Answer:* "NetGuard includes a **Whitelist Protection** mechanism. Critical servers or administrator workstations can be marked as whitelisted. If they exceed the risk threshold, NetGuard raises high-priority alerts for human intervention without severing mission-critical connections."

**Q3: Can this system run in an actual physical network?**  
*Answer:* "The application has a Scapy live-capture path, but it requires a working capture interface and a topology that exposes the devices' traffic to the monitoring laptop. On a normal switched Wi-Fi network, that laptop cannot see all client traffic. Windows or macOS host-firewall rules protect the monitoring host; they do not isolate another client from the LAN. Our default demonstration therefore labels quarantine as simulated."
