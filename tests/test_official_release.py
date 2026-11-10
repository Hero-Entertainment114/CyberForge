from __future__ import annotations
import hashlib
import json
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import patch
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class OfficialReleaseCLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "server.py"), *args],
            cwd=ROOT, text=True, capture_output=True, timeout=20,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_preflight_initializes_additive_security_schemas(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = self.run_cli("--data-dir", tmp, "preflight")
            self.assertEqual(cp.returncode, 0, cp.stderr)
            data = json.loads(cp.stdout)
            self.assertTrue(data["ok"])
            self.assertTrue(data["audit"]["valid"])
            self.assertIn("rules_total", data["detection_engine"])
            db = Path(tmp) / "server.sqlite3"
            self.assertTrue(db.is_file())
            import sqlite3
            con = sqlite3.connect(db)
            try:
                names = {x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                con.close()
            self.assertTrue({"detection_rules", "detection_rule_versions", "detection_matches", "threat_iocs"}.issubset(names))

    def test_sqlite_backup_is_readable_hashed_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            dbdir = Path(tmp) / "data"
            out = Path(tmp) / "backups" / "official.sqlite3"
            init = self.run_cli("--data-dir", str(dbdir), "init-admin")
            self.assertEqual(init.returncode, 0, init.stderr)
            cp = self.run_cli("--data-dir", str(dbdir), "backup", "--output", str(out))
            self.assertEqual(cp.returncode, 0, cp.stderr)
            result = json.loads(cp.stdout)
            self.assertTrue(result["verified"])
            self.assertEqual(result["sha256"], hashlib.sha256(out.read_bytes()).hexdigest())
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            verify = self.run_cli("--data-dir", str(dbdir), "verify-backup", "--path", str(out))
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertTrue(json.loads(verify.stdout)["valid"])

    def test_corrupt_sqlite_backup_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.sqlite3"
            bad.write_bytes(b"SQLite format 3\x00" + b"not-a-real-database")
            cp = self.run_cli("--data-dir", tmp, "verify-backup", "--path", str(bad))
            self.assertEqual(cp.returncode, 2)
            self.assertFalse(json.loads(cp.stdout)["valid"])

    def test_missing_backup_is_rejected_without_opening_live_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "must-not-be-created"
            cp = self.run_cli("--data-dir", str(data_dir), "verify-backup", "--path", str(Path(tmp) / "missing.sqlite3"))
            self.assertEqual(cp.returncode, 2)
            self.assertEqual(json.loads(cp.stdout)["reason"], "backup_missing_or_empty")
            self.assertFalse(data_dir.exists())

    def test_backup_refuses_to_overwrite_existing_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "data"
            self.assertEqual(self.run_cli("--data-dir", str(data_dir), "init-admin").returncode, 0)
            out = Path(tmp) / "existing.sqlite3"
            out.write_bytes(b"preserve-existing-file")
            cp = self.run_cli("--data-dir", str(data_dir), "backup", "--output", str(out))
            self.assertNotEqual(cp.returncode, 0)
            self.assertIn("Backup failed", cp.stderr + cp.stdout)
            self.assertEqual(out.read_bytes(), b"preserve-existing-file")


    def test_postgres_backup_uses_private_pgpass_and_minimal_child_environment(self):
        import distributed
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "db.dump"
            observed = {}
            def fake_run(command, **kwargs):
                observed["command"] = command
                observed["env"] = kwargs["env"]
                passfile = Path(kwargs["env"]["PGPASSFILE"])
                observed["pass_mode"] = passfile.stat().st_mode & 0o777
                observed["pass_data"] = passfile.read_text(encoding="utf-8")
                Path(command[command.index("--file") + 1]).write_bytes(b"fake-custom-dump")
                return SimpleNamespace(returncode=0, stderr="")
            store = object.__new__(distributed.PostgresStore)
            store.dsn = "postgresql://backup-user:p%40ss%3Aword@127.0.0.1:5432/cyberforge?sslmode=require"
            env = {**os.environ, "CF_DATABASE_URL": store.dsn, "CF_AI_API_KEY": "must-not-leak"}
            with patch.dict(os.environ, env, clear=True), patch("shutil.which", return_value="/usr/bin/pg_dump"), patch("subprocess.run", side_effect=fake_run):
                result = store.backup_database(target)
            self.assertEqual(result["sha256"], hashlib.sha256(b"fake-custom-dump").hexdigest())
            self.assertEqual(observed["pass_mode"], 0o600)
            self.assertIn(r"backup-user:p@ss\:word", observed["pass_data"])
            self.assertNotIn("CF_DATABASE_URL", observed["env"])
            self.assertNotIn("CF_AI_API_KEY", observed["env"])
            self.assertNotIn(store.dsn, observed["command"])
            self.assertFalse(Path(observed["env"]["PGPASSFILE"]).exists())

    def test_installer_stages_before_switch_and_contains_rollback(self):
        script = (ROOT / "deploy/install.sh").read_text(encoding="utf-8")
        self.assertIn("mktemp -d", script)
        self.assertIn("preflight", script)
        self.assertIn("backup --output", script)
        self.assertIn("mv -Tf", script)
        self.assertIn("rolling back the active release", script)
        self.assertIn("HEALTH_OK", script)
        self.assertNotIn('cp -a "$ROOT/." "$APP_ROOT/"', script)


    def test_installer_restores_previous_enabled_state_on_rollback(self):
        script = (ROOT / "deploy/install.sh").read_text(encoding="utf-8")
        self.assertIn('SERVICE_ENABLED_STATE="$(systemctl is-enabled cyberforge-server.service', script)
        self.assertIn('enabled) systemctl enable cyberforge-server.service', script)
        self.assertIn('enabled-runtime) systemctl enable --runtime cyberforge-server.service', script)
        self.assertIn('*) systemctl disable cyberforge-server.service', script)
        self.assertIn('if [[ "$SERVICE_WAS_ACTIVE" == "1" ]]; then', script)

    def test_installer_preserves_existing_environment_file(self):
        script = (ROOT / "deploy/install.sh").read_text(encoding="utf-8")
        self.assertIn('if [[ ! -f "$ETC_DIR/server.env" ]]; then', script)
        self.assertIn('install -m 0640 -o root -g cyberforge-server "$ROOT/.env.example" "$ETC_DIR/server.env"', script)
        # The example is only installed if the operator's existing file is absent.
        self.assertNotIn('cp -f "$ROOT/.env.example"', script)

    def test_manifest_and_edition_are_consistent_official_stable(self):
        manifest = json.loads((ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
        edition = json.loads((ROOT / "edition.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["release_channel"], "official-stable")
        self.assertTrue(manifest["official_stable"])
        self.assertEqual(edition["release_channel"], "official-stable")
        self.assertEqual(manifest["version"], (ROOT / "VERSION.txt").read_text().strip())
        self.assertEqual(manifest["tests_discovered"], manifest["tests_passed"] + manifest["tests_skipped"])
        self.assertEqual(manifest["test_modules"], len(list((ROOT / "tests").glob("test_*.py"))))

    def test_systemd_uses_versioned_current_release_venv(self):
        unit = (ROOT / "deploy/systemd/cyberforge-server.service").read_text(encoding="utf-8")
        self.assertIn("/opt/cyberforge-server/current/.venv/bin/python", unit)
        self.assertIn("ReadWritePaths=/var/lib/cyberforge-server", unit)
        self.assertNotIn("PrivateDevices=true", unit, "host GPU devices must remain visible to read-only inventory probes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
