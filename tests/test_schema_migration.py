"""Existing project databases gain destination history without losing baselines."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from database.db import init_db, get_db


class TestSchemaMigration(unittest.TestCase):
    def test_existing_baseline_table_gains_destination_column(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = str(Path(directory) / "legacy.db")
            connection = sqlite3.connect(database_path)
            connection.execute("CREATE TABLE baselines (id INTEGER PRIMARY KEY, device_id INTEGER UNIQUE, sample_count INTEGER)")
            connection.execute("INSERT INTO baselines (id, device_id, sample_count) VALUES (1, 5, 20)")
            connection.commit()
            connection.close()

            with patch("database.db.DATABASE_PATH", database_path):
                init_db()
                with get_db() as migrated:
                    row = migrated.execute("SELECT sample_count, known_dest_ips FROM baselines WHERE id = 1").fetchone()
            self.assertEqual(row["sample_count"], 20)
            self.assertEqual(row["known_dest_ips"], "[]")


if __name__ == "__main__":
    unittest.main()
