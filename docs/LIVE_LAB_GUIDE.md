# Windows and macOS live lab validation

Use only the team-owned or explicitly authorized lab network described in the proposal. Keep the default simulated backend for the viva unless a network device that can actually isolate a client is part of the test topology.

## 1. Establish traffic visibility

A Windows or macOS laptop on ordinary switched Wi-Fi can normally observe its own traffic and some broadcast or multicast traffic. To assess every client, place the monitor at a gateway, bridge, or mirrored switch port that exposes those packets. Record a simple topology diagram and the exact adapter used. Confirm with a harmless packet from each client that NetGuardian sees the correct source MAC and IP. Do not infer coverage from a successful subnet scan; scanning discovers hosts but does not prove their traffic is visible.

## 2. Prepare the application

- Windows: install Npcap, run with capture permission, and select the correct Wi-Fi or Ethernet adapter. If auto-detection chooses the wrong adapter, set `NETGUARD_IFACE` to the adapter Scapy can open.
- macOS: use a permitted capture interface and set `NETGUARD_IFACE` when auto-detection is wrong. If `/api/mode/status` reports `Permission denied` for `/dev/bpf`, the saved Live setting was applied but the NetGuard process cannot open the capture device. Arrange capture access for the lab process before trying Live LAN; do not interpret a successful subnet scan as a capture permission check.
- In Settings, select `LIVE` capture, save, and click **Restart NetGuard**. Check `/api/mode/status`: `capture.ready` must be `true`. Then switch to Live LAN. If capture reports an error, keep the system in lab mode and resolve the interface or permission problem before claiming live monitoring. The restart button requires launching the app with `python run.py`.
- Discover/import devices, then check that each new baseline starts unlocked and advances only after clean observed intervals. Wait for 20 clean samples before treating the profile as established.

## 3. Measure the proposal scenarios

Run normal traffic, an unknown device, a controlled port scan, a traffic-volume spike, a combined scenario, and a legitimate software update at least three times each. Use `evaluation/live-runs-template.csv` for one row per attempt. Capture the expected and observed indicator, risk score, first anomalous packet time, alert time, and evidence reference. For false-positive analysis, record benign activity that did and did not raise an inappropriate alert or quarantine.

## 4. Verify containment independently

The default `SIMULATED` backend records a policy preview and a simulated quarantine state. A Windows or macOS host-firewall rule controls traffic to or from the monitoring laptop; it does not cut off the client from the router or other LAN devices. A whole-network containment test requires a controlled gateway, bridge, or router/VLAN integration. Before reporting isolation time, verify loss of connectivity from the affected client to another LAN host and to the gateway, and verify connectivity returns after release. Record those checks and timestamps in the live-run table.

## 5. Report only measured values

The saved `evaluation/results/lab-runs.csv` is synthetic pipeline evidence. Calculate live detection accuracy, false-positive rate, and response time only from completed live-run records with clear expected outcomes and timestamps. Separate simulated policy generation from verified network isolation in the final report and viva.
