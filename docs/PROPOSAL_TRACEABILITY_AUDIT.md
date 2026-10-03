# NetGuard Proposal Traceability Audit

## Scope

This review compares `CLHDNETCMU5533.docx` with the runnable NetGuard codebase. It distinguishes a working prototype, a controlled simulation, and a claim that still needs evidence on a real authorised lab network.

## Summary

The project has a credible end-to-end academic prototype. Its strongest parts are the weighted risk model, the simulation workflow, the web dashboard, audit storage, and the basic quarantine state machine. It should not yet be presented as a fully validated live network prevention system.

## Requirement matrix

| Proposal requirement | Evidence in the application | Assessment |
| --- | --- | --- |
| Discover LAN devices and identify them by MAC and IP | `core/network_scanner.py`, `core/device_profiler.py`, device inventory UI | Implemented, but the real discovery path is active probing rather than passive observation. |
| Capture ports, DNS, destinations and traffic volume | `core/capture_engine.py` records these four metrics; simulated and Scapy paths exist | Partially implemented. Live capture needs a correctly positioned monitoring interface; received bytes are not populated, and DNS detection covers UDP DNS only. |
| Build a per-device behavioural baseline | Baseline schema, seeded canonical baselines, and clean-sample EWMA learning in `core/capture_engine.py` | Implemented for the four tracked metrics. A new device remains under review until it has 20 clean samples; this still requires live-lab validation. |
| Calculate a multi-dimensional behaviour drift score | `core/drift_engine.py`; proposal worked example is unit-tested | Implemented for the stated four metrics. |
| Weighted configurable risk scoring (30/20/20/15/15) | `core/risk_engine.py`, `config.py`, settings UI | Implemented. Settings validation now prevents total weights above 100. |
| Alert when a threshold is crossed | Alert database model, `/api/alerts`, dashboard and incident screen | Implemented in the application flow. |
| Automatic quarantine at critical risk | `core/quarantine_manager.py`, quarantine logs, demo step 3 | Implemented as a lab workflow. The default backend produces a simulated ACL preview, not a live router change. |
| Firewall, VLAN or router isolation | Host-firewall command paths plus Cisco/MikroTik policy text | Partially implemented. Host-command exit status is now checked before a device state changes, but there is no router API/VLAN integration. |
| Controlled port scan, rogue device and traffic scenarios | `simulator/attack_scenarios.py`, `/academic` | Implemented as safe, synthetic demonstration scenarios. |
| Evaluate detection accuracy, false positives and response time | Static academic/evaluation content and `docs/EVALUATION_METRICS.md` | Not yet evidenced by a repeatable results dataset. The required three-run lab measurements are still needed. |
| Live web dashboard, device history and reports | Flask templates, REST API, SQLite history tables | Dashboard and history are implemented. The advertised report/PDF export path is not present; `/reports` redirects to the academic page. |

## Verified checks

The project test suite passes in its included virtual environment: **11 tests passed**. Coverage includes the risk bands, drift calculation, whitelist protection, quarantine/release cycle, key API routes, and the four-stage demonstration sequence.

## High-priority work before final assessment

1. Test live capture on an authorised topology with a SPAN/mirror port, TAP, bridge, or gateway position. Record the topology and capture evidence; a standard switched Wi-Fi/LAN interface normally cannot observe every device’s traffic.
2. Produce a reproducible evaluation dataset for each test run: attack type, expected result, detected result, alert time, isolation time, false-positive decision, and evidence screenshot/log identifier.
3. Replace static empirical figures and the missing report-export claim with results generated from the actual test dataset.

## UI changes completed in this pass

- The UI now identifies the default data source as **simulated**, not a live enterprise/SOC deployment.
- Policy output is clearly labelled as a preview in lab mode instead of implying it has changed a router.
- Active subnet discovery, direct probes, port checks, quarantine, and release actions now request confirmation at the interface level.
- The dashboard and navigation now use clearer labels, keyboard focus states, accessible action names, reduced-motion support, and a calmer card/border system.
- Settings reject unsupported values and risk weights above the 100-point model limit.
- Newly discovered devices are now explicitly held for review while the system learns a clean, 20-sample behavioural baseline.
- Active network operations require an explicit authorisation acknowledgement in both the interface and API route, and probes are restricted to the detected local subnet.
- A host is marked quarantined or released only when the chosen local firewall command reports success; failures are recorded as audit events instead.
