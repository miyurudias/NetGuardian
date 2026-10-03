# NetGuardian evaluation evidence and remaining lab measurements

The automated evaluation in `evaluation/run_lab.py` uses synthetic traffic and a temporary SQLite database. It exercises eight scenarios three times each: normal traffic, port scan, DNS volume, traffic spike, unfamiliar destinations, combined escalation, rogue device, and benign software update. The saved run-level results are in `evaluation/results/lab-runs.csv`; `evaluation/results/lab-runs.summary.json` gives the number of expected outcomes matched. Rerun the script after changing detection logic.

```bash
python evaluation/run_lab.py --output evaluation/results/lab-runs.csv --repetitions 3
```

The recorded `processing_elapsed_ms` includes local scenario generation and evaluation. It is **not** packet-capture latency or network isolation latency. A simulated quarantine flag and ACL preview do **not** prove that a real device lost network access. The 24 synthetic checks cannot establish a field detection-accuracy or false-positive percentage for small networks.

## Proposal research questions

### RQ1 Per-device behavioural baseline

Record the lab topology, monitor interface, IP subnet, and how the monitoring laptop can observe each client. Capture normal traffic from each device for at least 20 clean intervals. Keep the traffic sample and baseline history so the source of each learned value can be checked. Compare learned DNS count, distinct destination count, port count, and bytes per interval with the device's later observed activity.

### RQ2 Risk scoring and false positives

Repeat each proposal scenario at least three times on the authorized lab network. For every run, record the expected indicator, observed indicator, risk score, alert outcome, and whether the action was justified. Include benign software updates and other legitimate bursts. Define true positive, false positive, true negative, and false negative before calculating accuracy, precision, recall, or false-positive rate.

### RQ3 Alert-only versus automatic quarantine

Run the same controlled scenario under both policies. Measure timestamps from the first observed anomalous packet to the alert, the enforcement command, and an independent connectivity check from the affected client. A Windows or macOS host firewall rule protects the monitoring laptop's traffic to that IP; it does not by itself isolate the client from the router or the rest of the LAN. For whole-network isolation, place enforcement at the gateway or use an authorized router/VLAN mechanism. If that topology is unavailable, demonstrate a clearly labelled simulated quarantine as the proposal permits.

## Run record for live lab tests

For each repetition capture: scenario ID, device MAC/IP, topology and monitor interface, expected result, observed indicator and score, first anomaly timestamp, alert timestamp, enforcement timestamp, independent connectivity result, false-positive decision, and screenshot/log reference. Preserve the raw records alongside the final report so every reported figure can be recalculated.
