"""
NetGuard - Behaviour Drift Score Engine
Implements the core mathematical model for measuring device behavioral deviation.
(Section 8.2 of Computing Project Proposal)
"""


def calculate_metric_drift(observed, baseline, max_expected_multiplier=8.0):
    """
    Calculates percentage drift for a single metric:
    Drift % = ((Observed - Baseline) / Baseline) * 100
    Returns:
        drift_pct (float): Raw percentage drift (e.g. 650.0%)
        normalized_score (float): Scaled 0.0 to 100.0 sub-score
    """
    baseline_safe = max(1.0, float(baseline))
    observed_float = float(observed)

    # Calculate raw drift percentage
    if observed_float <= baseline_safe:
        return 0.0, 0.0

    raw_drift_pct = ((observed_float - baseline_safe) / baseline_safe) * 100.0

    # Normalized score scales up to 100% when observed reaches max_expected_multiplier * baseline
    multiplier_observed = observed_float / baseline_safe
    normalized_score = min(100.0, ((multiplier_observed - 1.0) / (max_expected_multiplier - 1.0)) * 100.0)

    return round(raw_drift_pct, 1), round(normalized_score, 1)


def compute_behavior_drift_score(current_sample, baseline):
    """
    Calculates composite multi-dimensional Behaviour Drift Score (0 - 100%).
    
    Current Sample Dict:
        - dns_count
        - distinct_ips_count
        - port_count
        - bytes_transferred_kb
    
    Baseline Dict:
        - dns_queries_avg
        - distinct_ips_avg
        - ports_contacted_avg
        - bytes_transferred_kb_avg

    Returns:
        composite_drift (float): Overall drift percentage (0.0 - 100.0)
        breakdown (dict): Per-metric drifts and normalized scores
    """
    if not baseline:
        # Default benign baseline if none registered
        baseline = {
            "dns_queries_avg": 20.0,
            "distinct_ips_avg": 5.0,
            "ports_contacted_avg": 3.0,
            "bytes_transferred_kb_avg": 150.0
        }

    # 1. DNS Drift
    dns_pct, dns_norm = calculate_metric_drift(
        current_sample.get("dns_count", 0),
        baseline.get("dns_queries_avg", 20.0),
        max_expected_multiplier=9.0
    )

    # 2. Distinct External IPs Drift
    ips_pct, ips_norm = calculate_metric_drift(
        current_sample.get("distinct_ips_count", 0),
        baseline.get("distinct_ips_avg", 5.0),
        max_expected_multiplier=8.0
    )

    # 3. Ports Contacted Drift
    ports_pct, ports_norm = calculate_metric_drift(
        current_sample.get("port_count", 0),
        baseline.get("ports_contacted_avg", 3.0),
        max_expected_multiplier=9.0
    )

    # 4. Data Volume Transferred Drift
    bytes_pct, bytes_norm = calculate_metric_drift(
        current_sample.get("bytes_transferred_kb", 0),
        baseline.get("bytes_transferred_kb_avg", 150.0),
        max_expected_multiplier=20.0
    )

    # Dimension Weights (must sum to 1.0)
    # Ports and IPs are heavily weighted as indicators of reconnaissance and C2 communication
    weights = {
        "ports": 0.30,
        "ips": 0.25,
        "dns": 0.25,
        "bytes": 0.20
    }

    composite_drift = (
        (ports_norm * weights["ports"]) +
        (ips_norm * weights["ips"]) +
        (dns_norm * weights["dns"]) +
        (bytes_norm * weights["bytes"])
    )

    composite_drift = min(100.0, max(0.0, round(composite_drift, 1)))

    breakdown = {
        "composite_drift": composite_drift,
        "metrics": {
            "dns": {
                "baseline": baseline.get("dns_queries_avg", 20.0),
                "observed": current_sample.get("dns_count", 0),
                "drift_pct": dns_pct,
                "score": dns_norm
            },
            "distinct_ips": {
                "baseline": baseline.get("distinct_ips_avg", 5.0),
                "observed": current_sample.get("distinct_ips_count", 0),
                "drift_pct": ips_pct,
                "score": ips_norm
            },
            "ports": {
                "baseline": baseline.get("ports_contacted_avg", 3.0),
                "observed": current_sample.get("port_count", 0),
                "drift_pct": ports_pct,
                "score": ports_norm
            },
            "traffic_kb": {
                "baseline": baseline.get("bytes_transferred_kb_avg", 150.0),
                "observed": current_sample.get("bytes_transferred_kb", 0),
                "drift_pct": bytes_pct,
                "score": bytes_norm
            }
        }
    }

    return composite_drift, breakdown
