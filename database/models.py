"""
NetGuard - Data Access Models
Encapsulates CRUD operations for Devices, Baselines, Risk Scores, Alerts, and Logs.
"""

import json
from database.db import get_db

DEMO_MACS = tuple(f"00:1A:2B:3C:4D:{suffix:02X}" for suffix in range(1, 6))


class DeviceModel:
    @staticmethod
    def get_all():
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT d.*, 
                       b.dns_queries_avg, b.distinct_ips_avg, b.ports_contacted_avg, b.bytes_transferred_kb_avg,
                       b.sample_count as baseline_samples, b.is_locked as baseline_locked
                FROM devices d
                LEFT JOIN baselines b ON d.id = b.device_id
                ORDER BY d.current_risk_score DESC, d.id ASC
            """)
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def get_by_id(device_id):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT d.*, 
                       b.dns_queries_avg, b.distinct_ips_avg, b.ports_contacted_avg, b.bytes_transferred_kb_avg,
                       b.sample_count as baseline_samples, b.is_locked as baseline_locked
                FROM devices d
                LEFT JOIN baselines b ON d.id = b.device_id
                WHERE d.id = ?
            """, (device_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    @staticmethod
    def get_by_mac(mac):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac.upper(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    @staticmethod
    def get_by_ip(ip):
        with get_db() as conn:
            row = conn.execute("SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def create(mac, ip, name, device_type="Unknown", is_whitelisted=False):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO devices (mac, ip, name, device_type, is_whitelisted, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    name = excluded.name,
                    device_type = excluded.device_type,
                    last_seen = CURRENT_TIMESTAMP
            """, (mac.upper(), ip, name, device_type, 1 if is_whitelisted else 0))
            
            cursor.execute("SELECT id FROM devices WHERE mac = ?", (mac.upper(),))
            row = cursor.fetchone()
            device_id = row[0] if row else cursor.lastrowid

            # Create default baseline if not exists
            cursor.execute("""
                INSERT INTO baselines
                (device_id, dns_queries_avg, distinct_ips_avg, ports_contacted_avg, bytes_transferred_kb_avg, sample_count)
                VALUES (?, 0.0, 0.0, 0.0, 0.0, 0)
                ON CONFLICT(device_id) DO NOTHING
            """, (device_id,))
            return device_id

    @staticmethod
    def update_last_seen(device_id, ip=None):
        with get_db() as conn:
            cursor = conn.cursor()
            if ip:
                cursor.execute("""
                    UPDATE devices SET ip = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?
                """, (ip, device_id))
            else:
                cursor.execute("""
                    UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE id = ?
                """, (device_id,))

    @staticmethod
    def update_metadata(device_id, name=None, device_type=None, ip=None):
        with get_db() as conn:
            cursor = conn.cursor()
            updates = ["last_seen = CURRENT_TIMESTAMP"]
            params = []
            if name:
                updates.append("name = ?")
                params.append(name)
            if device_type:
                updates.append("device_type = ?")
                params.append(device_type)
            if ip:
                updates.append("ip = ?")
                params.append(ip)
            params.append(device_id)
            cursor.execute(f"UPDATE devices SET {', '.join(updates)} WHERE id = ?", params)

    @staticmethod
    def update_scores(device_id, risk_score, drift_score, status=None):
        with get_db() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("""
                    UPDATE devices 
                    SET current_risk_score = ?, current_drift_score = ?, status = ?, last_seen = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (risk_score, drift_score, status, device_id))
            else:
                cursor.execute("""
                    UPDATE devices 
                    SET current_risk_score = ?, current_drift_score = ?, last_seen = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (risk_score, drift_score, device_id))

    @staticmethod
    def set_quarantined(device_id, is_quarantined, reason=None):
        with get_db() as conn:
            cursor = conn.cursor()
            status = "Quarantined" if is_quarantined else "Normal"
            cursor.execute("""
                UPDATE devices 
                SET is_quarantined = ?, status = ?, quarantine_reason = ?
                WHERE id = ?
            """, (1 if is_quarantined else 0, status, reason, device_id))

    @staticmethod
    def set_whitelisted(device_id, is_whitelisted):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE devices SET is_whitelisted = ? WHERE id = ?
            """, (1 if is_whitelisted else 0, device_id))

    @staticmethod
    def clear_all_devices():
        """Cleans all devices, baselines, traffic samples, alerts, and quarantine logs."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM quarantine_logs")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM risk_history")
            cursor.execute("DELETE FROM traffic_samples")
            cursor.execute("DELETE FROM baselines")
            cursor.execute("DELETE FROM devices")

    @staticmethod
    def clear_mock_devices():
        """Removes only proposal mock / synthetic demonstration devices."""
        with get_db() as conn:
            placeholders = ", ".join("?" for _ in DEMO_MACS)
            conn.execute(f"DELETE FROM devices WHERE mac IN ({placeholders})", DEMO_MACS)


class BaselineModel:
    @staticmethod
    def get_by_device(device_id):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM baselines WHERE device_id = ?", (device_id,))
            row = cursor.fetchone()
            if not row:
                return None
            baseline = dict(row)
            baseline["known_dest_ips"] = json.loads(baseline.get("known_dest_ips") or "[]")
            return baseline

    @staticmethod
    def update_baseline(device_id, dns_avg, ips_avg, ports_avg, bytes_kb_avg, increment_sample=True):
        with get_db() as conn:
            cursor = conn.cursor()
            if increment_sample:
                cursor.execute("""
                    UPDATE baselines
                    SET dns_queries_avg = ?, distinct_ips_avg = ?, ports_contacted_avg = ?, 
                        bytes_transferred_kb_avg = ?, sample_count = sample_count + 1, updated_at = CURRENT_TIMESTAMP
                    WHERE device_id = ? AND is_locked = 0
                """, (dns_avg, ips_avg, ports_avg, bytes_kb_avg, device_id))
            else:
                cursor.execute("""
                    UPDATE baselines
                    SET dns_queries_avg = ?, distinct_ips_avg = ?, ports_contacted_avg = ?, 
                        bytes_transferred_kb_avg = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE device_id = ?
                """, (dns_avg, ips_avg, ports_avg, bytes_kb_avg, device_id))

    @staticmethod
    def set_lock(device_id, is_locked):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE baselines SET is_locked = ? WHERE device_id = ?", (1 if is_locked else 0, device_id))

    @staticmethod
    def add_known_destinations(device_id, ips):
        if not ips:
            return
        with get_db() as conn:
            row = conn.execute("SELECT known_dest_ips FROM baselines WHERE device_id = ? AND is_locked = 0", (device_id,)).fetchone()
            if row:
                known = set(json.loads(row["known_dest_ips"] or "[]"))
                known.update(ips)
                conn.execute("UPDATE baselines SET known_dest_ips = ? WHERE device_id = ?", (json.dumps(sorted(known)), device_id))


class TrafficModel:
    @staticmethod
    def record_sample(device_id, dns_count, distinct_ips_count, port_count, bytes_sent, bytes_recv, ports_list=None, dest_ips=None):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO traffic_samples 
                (device_id, dns_count, distinct_ips_count, port_count, bytes_sent, bytes_recv, ports_probed_list, dest_ips_list)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device_id, dns_count, distinct_ips_count, port_count, bytes_sent, bytes_recv,
                json.dumps(ports_list) if ports_list else "[]",
                json.dumps(dest_ips) if dest_ips else "[]"
            ))

    @staticmethod
    def get_recent_samples(device_id, limit=20):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM traffic_samples 
                WHERE device_id = ? 
                ORDER BY id DESC LIMIT ?
            """, (device_id, limit))
            rows = cursor.fetchall()
            return [dict(r) for r in reversed(rows)]


class RiskModel:
    @staticmethod
    def record_assessment(device_id, drift_score, port_scan, unknown_dev, dns_anom, traffic_spk, unfam_dest, total, band, notes=""):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO risk_history 
                (device_id, drift_score, port_scan_score, unknown_device_score, dns_anomaly_score,
                 traffic_spike_score, unfamiliar_dest_score, total_risk_score, risk_band, trigger_notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (device_id, drift_score, port_scan, unknown_dev, dns_anom, traffic_spk, unfam_dest, total, band, notes))

    @staticmethod
    def get_history(device_id, limit=30):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM risk_history 
                WHERE device_id = ? 
                ORDER BY id DESC LIMIT ?
            """, (device_id, limit))
            rows = cursor.fetchall()
            return [dict(r) for r in reversed(rows)]


class AlertModel:
    @staticmethod
    def create(device_id, severity, indicator, message, drift_pct=0.0, risk_score=0):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (device_id, severity, indicator, message, drift_pct, risk_score)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (device_id, severity, indicator, message, drift_pct, risk_score))
            return cursor.lastrowid

    @staticmethod
    def create_or_update_active(device_id, severity, indicator, message, drift_pct=0.0, risk_score=0):
        """Keep one open alert per device and indicator during a continuous incident."""
        with get_db() as conn:
            row = conn.execute("""
                SELECT id FROM alerts
                WHERE device_id = ? AND indicator = ? AND resolved = 0
                ORDER BY id DESC LIMIT 1
            """, (device_id, indicator)).fetchone()
            if row:
                conn.execute("""
                    UPDATE alerts SET severity = ?, message = ?, drift_pct = ?, risk_score = ?
                    WHERE id = ?
                """, (severity, message, drift_pct, risk_score, row["id"]))
                return row["id"]
            cursor = conn.execute("""
                INSERT INTO alerts (device_id, severity, indicator, message, drift_pct, risk_score)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (device_id, severity, indicator, message, drift_pct, risk_score))
            return cursor.lastrowid

    @staticmethod
    def resolve_inactive_indicators(device_id, active_indicators):
        risk_indicators = (
            "Port Scanning Detected", "Unknown / Rogue Device", "DNS Anomaly / Tunneling",
            "Traffic Volume Spike", "Unfamiliar External Destinations"
        )
        with get_db() as conn:
            if active_indicators:
                placeholders = ", ".join("?" for _ in active_indicators)
                conn.execute(f"""
                    UPDATE alerts SET resolved = 1
                    WHERE device_id = ? AND resolved = 0
                    AND indicator IN ({', '.join('?' for _ in risk_indicators)})
                    AND indicator NOT IN ({placeholders})
                """, (device_id, *risk_indicators, *active_indicators))
            else:
                conn.execute(f"""
                    UPDATE alerts SET resolved = 1 WHERE device_id = ? AND resolved = 0
                    AND indicator IN ({', '.join('?' for _ in risk_indicators)})
                """, (device_id, *risk_indicators))

    @staticmethod
    def resolve_all(device_id):
        with get_db() as conn:
            conn.execute("UPDATE alerts SET resolved = 1 WHERE device_id = ? AND resolved = 0", (device_id,))

    @staticmethod
    def get_all(limit=50, unacknowledged_only=False):
        with get_db() as conn:
            cursor = conn.cursor()
            query = """
                SELECT a.*, d.name as device_name, d.ip as device_ip, d.mac as device_mac
                FROM alerts a
                JOIN devices d ON a.device_id = d.id
            """
            if unacknowledged_only:
                query += " WHERE a.acknowledged = 0 AND a.resolved = 0 "
            query += " ORDER BY a.id DESC LIMIT ?"
            cursor.execute(query, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def acknowledge(alert_id):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))

    @staticmethod
    def acknowledge_all():
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET acknowledged = 1")


class QuarantineLogModel:
    @staticmethod
    def log(device_id, action, mechanism, command, reason):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO quarantine_logs (device_id, action, mechanism, command_executed, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (device_id, action, mechanism, command, reason))

    @staticmethod
    def get_logs(limit=50):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT q.*, d.name as device_name, d.ip as device_ip, d.mac as device_mac
                FROM quarantine_logs q
                JOIN devices d ON q.device_id = d.id
                ORDER BY q.id DESC LIMIT ?
            """, (limit,))
            return [dict(r) for r in cursor.fetchall()]


class ConfigModel:
    @staticmethod
    def get(key, default=None):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM system_config WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else default

    @staticmethod
    def set(key, value, description=""):
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_config (key, value, description)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, description = excluded.description
            """, (key, str(value), description))

    @staticmethod
    def get_all():
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM system_config")
            return {row["key"]: row["value"] for row in cursor.fetchall()}
