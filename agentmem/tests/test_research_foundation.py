"""Foundation regression tests (schema version + migration, real transaction
rollback, content-addressed artifacts, bounded/redacted projection). Stdlib."""
import os
import sqlite3
import tempfile
import unittest

from agentmem import migrations
from agentmem.security import SecretsVault, project_text
from agentmem.store import Store


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "research.db")

    def tearDown(self):
        self.dir.cleanup()


class TestSchemaVersionAndMigration(_Tmp):
    def test_fresh_db_is_current_version_with_research_tables(self):
        s = Store(self.path)
        self.assertEqual(s.schema_version, migrations.CURRENT_SCHEMA_VERSION)
        tables = {r["name"] for r in s.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for t in ("snapshots", "source_refs", "value_identities", "flow_edges",
                  "guards", "evidence", "hypotheses", "validation_runs", "findings",
                  "research_chains", "artifacts", "provenance", "audit_events",
                  "idempotency_keys"):
            self.assertIn(t, tables, f"migration must create {t}")
        s.close()

    def test_existing_v1_db_migrates_without_data_loss(self):
        # simulate a pre-versioning v1 database: base schema + a row, no version key
        with open(os.path.join(os.path.dirname(migrations.__file__), "schema.sql"),
                  encoding="utf-8") as fh:
            base = fh.read()
        raw = sqlite3.connect(self.path)
        raw.executescript(base)
        raw.execute("INSERT INTO nodes(type,canonical_key,attrs_json) VALUES('finding','k1','{\"x\":1}')")
        raw.execute("INSERT INTO observations(step,request,trust,source) VALUES(0,'req','agent_asserted','http')")
        raw.commit()
        self.assertIsNone(raw.execute(
            "SELECT value FROM kv_meta WHERE key='schema_version'").fetchone())
        raw.close()

        s = Store(self.path)                               # opening runs the migration
        self.assertEqual(s.schema_version, migrations.CURRENT_SCHEMA_VERSION)
        self.assertEqual(s.conn.execute("SELECT COUNT(*) c FROM nodes").fetchone()["c"], 1)
        self.assertEqual(s.conn.execute(
            "SELECT attrs_json FROM nodes WHERE canonical_key='k1'").fetchone()["attrs_json"],
            '{"x":1}')
        self.assertEqual(s.conn.execute("SELECT COUNT(*) c FROM observations").fetchone()["c"], 1)
        self.assertIn("snapshots", {r["name"] for r in s.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()})
        s.close()

    def test_newer_schema_is_refused_with_instruction(self):
        s = Store(self.path)
        s.conn.execute("INSERT INTO kv_meta(key,value) VALUES('schema_version','99') "
                       "ON CONFLICT(key) DO UPDATE SET value='99'")
        s.close()
        with self.assertRaises(RuntimeError) as ctx:
            Store(self.path)
        self.assertIn("newer", str(ctx.exception).lower())


class TestTransactionRollback(_Tmp):
    def test_failed_transaction_rolls_back_after_reopen(self):
        s = Store(self.path)
        with self.assertRaises(ValueError):
            with s.transaction():
                s.conn.execute("INSERT INTO audit_events(ts,op) VALUES(1.0,'should_rollback')")
                # row is visible inside the open transaction...
                self.assertEqual(s.conn.execute(
                    "SELECT COUNT(*) c FROM audit_events").fetchone()["c"], 1)
                raise ValueError("boom")
        self.assertEqual(s.conn.execute(
            "SELECT COUNT(*) c FROM audit_events").fetchone()["c"], 0)  # rolled back live
        s.close()
        s2 = Store(self.path)                               # and still gone after reopen
        self.assertEqual(s2.conn.execute(
            "SELECT COUNT(*) c FROM audit_events").fetchone()["c"], 0)
        s2.close()

    def test_successful_transaction_persists(self):
        s = Store(self.path)
        with s.transaction():
            s.conn.execute("INSERT INTO audit_events(ts,op) VALUES(1.0,'keep')")
        s.close()
        s2 = Store(self.path)
        self.assertEqual(s2.conn.execute(
            "SELECT COUNT(*) c FROM audit_events WHERE op='keep'").fetchone()["c"], 1)
        s2.close()

    def test_nested_savepoint_rolls_back_inner_only(self):
        s = Store(self.path)
        with s.transaction():
            s.conn.execute("INSERT INTO audit_events(ts,op) VALUES(1.0,'outer')")
            try:
                with s.transaction():                       # inner savepoint
                    s.conn.execute("INSERT INTO audit_events(ts,op) VALUES(2.0,'inner')")
                    raise ValueError("inner fails")
            except ValueError:
                pass
            s.conn.execute("INSERT INTO audit_events(ts,op) VALUES(3.0,'after_inner')")
        s.close()
        s2 = Store(self.path)
        ops = {r["op"] for r in s2.conn.execute("SELECT op FROM audit_events").fetchall()}
        self.assertEqual(ops, {"outer", "after_inner"})     # inner rolled back, rest kept
        s2.close()


class TestContentAddressedArtifacts(_Tmp):
    def test_roundtrip_and_digest_preserved(self):
        s = Store(self.path)
        raw = b"SARIF or crash log bytes \x00\x01 preserved verbatim" * 100
        info = s.put_artifact(raw, media_type="application/sarif+json")
        self.assertEqual(len(info["sha256"]), 64)
        got = s.get_artifact_bytes(info["id"])
        self.assertEqual(got, raw)                          # exact bytes, not truncated
        import hashlib
        self.assertEqual(hashlib.sha256(got).hexdigest(), info["sha256"])
        s.close()

    def test_identical_bytes_dedupe(self):
        s = Store(self.path)
        a = s.put_artifact(b"same bytes")
        b = s.put_artifact(b"same bytes")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(a["sha256"], b["sha256"])
        s.close()

    def test_corruption_is_detected_not_returned(self):
        s = Store(self.path)
        info = s.put_artifact(b"trustworthy evidence")
        disk = os.path.join(s.artifacts.root, info["storage_path"])
        with open(disk, "wb") as fh:
            fh.write(b"tampered")
        with self.assertRaises(ValueError):
            s.get_artifact_bytes(info["id"], verify=True)
        self.assertFalse(s.artifacts.verify(info["sha256"]))
        s.close()


class TestBoundedProjection(_Tmp):
    def test_projection_is_bounded(self):
        raw = "A" * 5000
        proj, truncated = project_text(raw, max_chars=100)
        self.assertTrue(truncated)
        self.assertLess(len(proj), 200)
        self.assertIn("in artifact", proj)

    def test_projection_redacts_secrets_before_truncating(self):
        s = Store(self.path)
        vault = SecretsVault(s)
        handle = vault.put("supersecrettoken123456", kind="token")
        raw = "leak supersecrettoken123456 then " + ("x" * 5000)
        proj, truncated = project_text(raw, vault=vault, max_chars=200)
        self.assertNotIn("supersecrettoken123456", proj)    # secret never reaches a prompt
        self.assertIn(handle, proj)
        self.assertTrue(truncated)
        s.close()

    def test_empty_projection(self):
        self.assertEqual(project_text("", max_chars=100), ("", False))


if __name__ == "__main__":
    unittest.main()
