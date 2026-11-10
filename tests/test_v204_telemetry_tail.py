from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from tools import tail_jsonl


class TelemetryTailTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.log = self.root / "falco.jsonl"
        self.state_path = self.root / "state" / "checkpoints.sqlite3"
        self.state_path.parent.mkdir(mode=0o700)
        self.state = tail_jsonl.CheckpointDB(self.state_path)
        self.sent = []

    def tearDown(self):
        self.state.close()
        self.tmp.cleanup()

    def sender(self, server, source, token, records, timeout):
        self.sent.append([dict(x) for x in records])
        return {"accepted": len(records), "duplicates": 0, "ignored": 0}

    def runner(self, start_at_end=False, batch=2, sender=None, path=None):
        return tail_jsonl.TailRunner(path or self.log, "falco", self.state, "http://127.0.0.1:8787",
            "cf_sensor_test_token", batch_size=batch, start_at_end=start_at_end, sender=sender or self.sender)

    def test_checkpoint_db_is_private(self):
        if os.name == "posix":
            self.assertEqual(os.stat(self.state_path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(self.state_path.parent).st_mode & 0o777, 0o700)

    def test_first_start_defaults_to_end_of_existing_file(self):
        self.log.write_text('{"id":"old"}\n', encoding="utf-8")
        runner = self.runner(start_at_end=True)
        try:
            self.assertEqual(runner.poll_once()["sent"], 0)
            with self.log.open("a", encoding="utf-8") as f:
                f.write('{"id":"new"}\n')
            self.assertEqual(runner.poll_once()["sent"], 1)
            self.assertEqual(self.sent[0][0]["id"], "new")
        finally:
            runner.close()

    def test_from_beginning_and_batch_send(self):
        self.log.write_text('{"id":"a"}\n{"id":"b"}\n{"id":"c"}\n', encoding="utf-8")
        runner = self.runner(start_at_end=False, batch=2)
        try:
            stats = runner.poll_once()
            self.assertEqual(stats["sent"], 3)
            self.assertEqual([len(x) for x in self.sent], [2, 1])
        finally:
            runner.close()

    def test_partial_line_is_not_checkpointed_until_completed(self):
        self.log.write_text('{"id":"a"}\n{"id":"b"', encoding="utf-8")
        runner = self.runner(start_at_end=False, batch=1)
        try:
            first = runner.poll_once()
            self.assertEqual(first["sent"], 1)
            self.assertEqual(first["partial_lines"], 1)
            before = runner.offset
            with self.log.open("a", encoding="utf-8") as f:
                f.write('}\n')
            second = runner.poll_once()
            self.assertEqual(second["sent"], 1)
            self.assertGreater(runner.offset, before)
        finally:
            runner.close()

    def test_failed_send_does_not_advance_checkpoint(self):
        self.log.write_text('{"id":"retry"}\n', encoding="utf-8")
        calls = {"n": 0}
        def sender(*args):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("network timeout")
            return {"accepted": 1, "duplicates": 0}
        runner = self.runner(start_at_end=False, batch=1, sender=sender)
        try:
            with self.assertRaisesRegex(RuntimeError, "network timeout"):
                runner.poll_once()
            self.assertEqual(runner.offset, 0)
            self.assertEqual(runner.poll_once()["sent"], 1)
            self.assertEqual(calls["n"], 2)
        finally:
            runner.close()

    def test_malformed_line_is_skipped_without_logging_payload(self):
        self.log.write_text('not-json-secret=DO_NOT_PRINT\n{"id":"good"}\n', encoding="utf-8")
        runner = self.runner(start_at_end=False, batch=5)
        try:
            stats = runner.poll_once()
            self.assertEqual(stats["invalid_lines"], 1)
            self.assertEqual(stats["sent"], 1)
            self.assertEqual(self.sent[0][0]["id"], "good")
        finally:
            runner.close()

    def test_empty_and_blank_lines_checkpoint(self):
        self.log.write_text('\n  \n', encoding="utf-8")
        runner = self.runner(start_at_end=False)
        try:
            self.assertEqual(runner.poll_once()["sent"], 0)
            self.assertEqual(runner.offset, self.log.stat().st_size)
        finally:
            runner.close()

    def test_rotation_switches_to_new_path_after_old_eof(self):
        self.log.write_text('{"id":"old"}\n', encoding="utf-8")
        runner = self.runner(start_at_end=False, batch=1)
        try:
            runner.poll_once()
            old_inode = runner.inode
            rotated = self.root / "falco.jsonl.1"
            self.log.rename(rotated)
            self.log.write_text('{"id":"new"}\n', encoding="utf-8")
            # First poll sees EOF on the old descriptor and switches to new inode.
            runner.poll_once()
            self.assertNotEqual(runner.inode, old_inode)
            runner.poll_once()
            self.assertEqual(self.sent[-1][0]["id"], "new")
        finally:
            runner.close()

    def test_restart_recovers_rotated_inode_by_device_and_inode(self):
        self.log.write_text('{"id":"first"}\n', encoding="utf-8")
        runner = self.runner(start_at_end=False, batch=1)
        runner.poll_once()
        old_device, old_inode = runner.device, runner.inode
        runner.close()
        rotated = self.root / "falco.jsonl.1"
        self.log.rename(rotated)
        self.log.write_text('{"id":"next"}\n', encoding="utf-8")
        recovered = self.runner(start_at_end=False, batch=1)
        try:
            self.assertEqual((recovered.device, recovered.inode), (old_device, old_inode))
            recovered.poll_once()  # old rotated file is at EOF, switches to current path.
            recovered.poll_once()
            self.assertEqual(self.sent[-1][0]["id"], "next")
        finally:
            recovered.close()

    def test_copytruncate_resets_offset_and_replays_idempotently(self):
        self.log.write_text('{"id":"one"}\n{"id":"two"}\n', encoding="utf-8")
        runner = self.runner(start_at_end=False, batch=1)
        try:
            runner.poll_once()
            self.log.write_text('{"id":"fresh"}\n', encoding="utf-8")
            runner.poll_once()
            self.assertEqual(self.sent[-1][0]["id"], "fresh")
        finally:
            runner.close()

    def test_symlink_input_rejected(self):
        target = self.root / "target.jsonl"
        target.write_text('{"id":"x"}\n', encoding="utf-8")
        link = self.root / "link.jsonl"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            self.runner(path=link)


    def test_replaced_log_path_with_symlink_is_rejected_on_rotation(self):
        self.log.write_text("", encoding="utf-8")
        runner = self.runner(start_at_end=False)
        try:
            target = self.root / "target.jsonl"
            target.write_text('{"id":"must-not-follow"}\n', encoding="utf-8")
            rotated = self.root / "falco.jsonl.1"
            self.log.rename(rotated)
            self.log.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "regular non-symlink"):
                runner.poll_once()
        finally:
            runner.close()

    def test_symlink_checkpoint_rejected(self):
        target = self.root / "target.db"
        target.write_bytes(b"")
        link = self.root / "state" / "link.db"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            tail_jsonl.CheckpointDB(link)

    def test_checkpointed_inode_missing_is_not_silently_reset(self):
        self.log.write_text('{"id":"x"}\n', encoding="utf-8")
        runner = self.runner(start_at_end=False)
        runner.close()
        # Avoid filesystem inode reuse making delete/recreate nondeterministic.
        self.state.save(str(self.log.absolute()), runner.device, runner.inode + 999999, runner.offset)
        with self.assertRaisesRegex(RuntimeError, "checkpointed log inode"):
            self.runner(start_at_end=False)

    def test_invalid_source_is_rejected(self):
        self.log.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Trivy reports use batch ingestion"):
            tail_jsonl.TailRunner(self.log, "trivy", self.state, "http://127.0.0.1", "token")

    def test_remote_http_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "require HTTPS"):
            tail_jsonl.validate_server("http://cyberforge.example")

    def test_local_http_is_allowed(self):
        self.assertEqual(tail_jsonl.validate_server("http://127.0.0.1:8787/"), "http://127.0.0.1:8787")


    def test_lock_is_scoped_per_input_file(self):
        second = self.root / "zeek.jsonl"
        second.write_text("", encoding="utf-8")
        a = tail_jsonl.instance_lock_path(self.state_path, self.log)
        b = tail_jsonl.instance_lock_path(self.state_path, second)
        self.assertNotEqual(a, b)
        self.assertEqual(a, tail_jsonl.instance_lock_path(self.state_path, self.log))


    def test_same_input_cannot_be_tailed_twice_but_other_input_can_share_db(self):
        second = self.root / "zeek.jsonl"
        second.write_text("", encoding="utf-8")
        lock_a = tail_jsonl.instance_lock_path(self.state_path, self.log)
        lock_b = tail_jsonl.instance_lock_path(self.state_path, second)
        with tail_jsonl.InstanceLock(lock_a):
            with self.assertRaisesRegex(RuntimeError, "another telemetry shipper"):
                with tail_jsonl.InstanceLock(lock_a):
                    pass
            with tail_jsonl.InstanceLock(lock_b):
                pass

    def test_token_file_permissions(self):
        token = self.root / "sensor.token"
        token.write_text("cf_sensor_secret", encoding="utf-8")
        if os.name == "posix":
            os.chmod(token, 0o644)
            with self.assertRaisesRegex(ValueError, "0600"):
                tail_jsonl.load_token(str(token), "UNUSED")
            os.chmod(token, 0o600)
        self.assertEqual(tail_jsonl.load_token(str(token), "UNUSED"), "cf_sensor_secret")


if __name__ == "__main__":
    unittest.main(verbosity=2)
