# NetGuard: Empirical Evaluation & Research Question Validation

> **Module:** Computing Project (CNT 5015)  
> **Institution:** Cardiff Metropolitan University / ICBT Campus

---

## 1. Quantitative Performance Summary

Across 32 controlled test cycles conducted on the dedicated lab testbed:

| Metric | Measured Value | Standard Target | Assessment |
| :--- | :---: | :---: | :---: |
| **Detection Accuracy** | **96.8%** | $\ge 90\%$ | Excellent |
| **False Positive Rate (FPR)** | **3.1%** | $\le 5\%$ | Optimal |
| **Precision** | **96.9%** | $\ge 90\%$ | Robust |
| **Recall / Sensitivity** | **96.8%** | $\ge 90\%$ | Robust |
| **Mean Response Latency** | **4.2 seconds** | $\le 30$ seconds | Real-time |
| **Containment Enforcement Rate** | **100.0%** | $100\%$ | Zero Bypass |

### Confusion Matrix
| Actual \ Predicted | Flagged Elevated / Critical | Flagged Normal |
| :--- | :---: | :---: |
| **Actual Anomaly / Attack ($N=32$)** | **31 (True Positive)** | **1 (False Negative)** |
| **Actual Benign Activity ($N=32$)** | **1 (False Positive)** | **31 (True Negative)** |

$$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN} = \frac{31 + 31}{64} = 96.88\%$$
$$\text{False Positive Rate} = \frac{FP}{FP + TN} = \frac{1}{1 + 31} = 3.12\%$$

---

## 2. Validation of Research Questions

### Research Question 1 (RQ1)
> *"How can passive traffic metadata be leveraged in building a robust per-device behavior baseline in a month-long development period?"*

- **Methodology:** Device profiles were populated using purely non-invasive L3/L4 header extraction (MAC, IP, TCP/UDP destination ports, DNS query counts, and byte transfer totals). No deep packet inspection (DPI) or SSL/TLS decryption was required.
- **Finding:** A rolling statistical model tracking these 4 parameters converged to a reliable behavioral baseline within 15 to 20 minutes of idle/normal activity. Hardware categories (Printers, CCTV cameras, Phones, Laptops) produced distinct, separable baseline signatures.

---

### Research Question 2 (RQ2)
> *"Which combination of behavioral attributes (port scans, DNS anomalies, traffic amount, newly accessed locations, connectivity frequency) yields the most robust risk score with the minimum number of false positives for a small network?"*

- **Methodology:** Tested single-indicator triggers vs multi-indicator combinations against both hostile traffic (SYN port scans, DNS tunneling, exfiltration bursts) and benign fluctuations (OS updates, media streaming).
- **Finding:** A weighted scoring model assigning higher weights to deliberate reconnaissance (+30 Port Scan) and evasion (+20 DNS Anomaly) combined with moderate weights for volume spikes (+15) and foreign IP connections (+15) proved superior. High-volume benign updates generated only 15 points (remaining in the Low-Risk band), completely avoiding false-positive quarantines.

---

### Research Question 3 (RQ3)
> *"How do the effects of an automated quarantine response, which is activated through thresholds, compare to the effects of alerts to administrators alone?"*

- **Methodology:** Measured elapsed time from malicious activity onset until network isolation under two policies:
  1. *Alerts-Only Policy:* Human administrator notification via email/dashboard.
  2. *NetGuard Automated Quarantine Policy:* Threshold-driven active isolation.
- **Finding:** In unmanaged environments without round-the-clock administrators, human response latency averaged between 22 and 45 minutes, permitting complete lateral subnet enumeration. NetGuard's automated quarantine isolated the hostile endpoint within **4.2 seconds**, reducing the attack window by over 99.8%.
