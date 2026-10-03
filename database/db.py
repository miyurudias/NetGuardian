"""
NetGuard - Database Layer
SQLite connection manager and schema initialization.
Cross-platform, single-file zero configuration storage.
"""

import sqlite3
import os
from contextlib import contextmanager
from config import DATABASE_PATH


def get_connection():
    """Returns a new SQLite connection with Row factory and WAL mode enabled."""
    conn = sqlite3.connect(DATABASE_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def get_db():
    """Context manager for safe database transactions."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initializes the database schema with all required tables and indexes."""
    os.makedirs(os.path.dirname(os.path.abspath(DATABASE_PATH)), exist_ok=True)
    with get_db() as conn:
        cursor = conn.cursor()

        # 1. Devices Inventory
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT UNIQUE NOT NULL,
            ip TEXT NOT NULL,
            name TEXT NOT NULL,
            device_type TEXT NOT NULL DEFAULT 'Unknown',
            status TEXT NOT NULL DEFAULT 'Normal',
            current_risk_score INTEGER NOT NULL DEFAULT 0,
            current_drift_score REAL NOT NULL DEFAULT 0.0,
            is_whitelisted BOOLEAN NOT NULL DEFAULT 0,
            is_quarantined BOOLEAN NOT NULL DEFAULT 0,
            quarantine_reason TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # 2. Behavioral Baseline Profiles
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER UNIQUE NOT NULL,
            dns_queries_avg REAL NOT NULL DEFAULT 20.0,
            distinct_ips_avg REAL NOT NULL DEFAULT 5.0,
            ports_contacted_avg REAL NOT NULL DEFAULT 3.0,
            bytes_transferred_kb_avg REAL NOT NULL DEFAULT 150.0,
            sample_count INTEGER NOT NULL DEFAULT 1,
            is_locked BOOLEAN NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        )
        """)

        # 3. Traffic Samples (Interval Measurements)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            dns_count INTEGER NOT NULL DEFAULT 0,
            distinct_ips_count INTEGER NOT NULL DEFAULT 0,
            port_count INTEGER NOT NULL DEFAULT 0,
            bytes_sent INTEGER NOT NULL DEFAULT 0,
            bytes_recv INTEGER NOT NULL DEFAULT 0,
            ports_probed_list TEXT,
            dest_ips_list TEXT,
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        )
        """)

        # 4. Risk Scoring History
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            drift_score REAL NOT NULL DEFAULT 0.0,
            port_scan_score INTEGER NOT NULL DEFAULT 0,
            unknown_device_score INTEGER NOT NULL DEFAULT 0,
            dns_anomaly_score INTEGER NOT NULL DEFAULT 0,
            traffic_spike_score INTEGER NOT NULL DEFAULT 0,
            unfamiliar_dest_score INTEGER NOT NULL DEFAULT 0,
            total_risk_score INTEGER NOT NULL DEFAULT 0,
            risk_band TEXT NOT NULL DEFAULT 'Low',
            trigger_notes TEXT,
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        )
        """)

        # 5. Security Alerts Feed
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            severity TEXT NOT NULL,
            indicator TEXT NOT NULL,
            message TEXT NOT NULL,
            drift_pct REAL DEFAULT 0.0,
            risk_score INTEGER DEFAULT 0,
            acknowledged BOOLEAN NOT NULL DEFAULT 0,
            resolved BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        )
        """)

        # 6. Quarantine Actions & Isolation Log
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS quarantine_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            mechanism TEXT NOT NULL,
            command_executed TEXT,
            reason TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
        )
        """)

        # 7. System Dynamic Configurations
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            description TEXT
        )
        """)

        # Indexes for fast querying in real-time web dashboard
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_dev_time ON traffic_samples(device_id, timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_dev_time ON risk_history(device_id, timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dev_sev ON alerts(device_id, severity, acknowledged)")


def reset_db():
    """Drops and reinitializes all tables (useful for fresh demo resets)."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS quarantine_logs")
        cursor.execute("DROP TABLE IF EXISTS alerts")
        cursor.execute("DROP TABLE IF EXISTS risk_history")
        cursor.execute("DROP TABLE IF EXISTS traffic_samples")
        cursor.execute("DROP TABLE IF EXISTS baselines")
        cursor.execute("DROP TABLE IF EXISTS devices")
        cursor.execute("DROP TABLE IF EXISTS system_config")
    init_db()
