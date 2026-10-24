"""Firefox record model (symbols, call/inheritance relations, boundaries),
schema v3 migration, and backup/restore/verify. Stdlib unittest."""
import os
import tempfile
import unittest

from agentmem import ResearchMemory, backup, migrations
from agentmem.store import Store


class _R(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "r.db")
        self.m = ResearchMemory(self.path)
        self.snap = self.m.register_snapshot("firefox", "a" * 40, scope="dom/media")

    def tearDown(self):
        self.m.close(); self.dir.cleanup()


class TestSchemaV3(_R):
    def test_firefox_tables_exist_at_v3(self):
        self.assertEqual(self.m.store.schema_version, migrations.CURRENT_SCHEMA_VERSION)
        self.assertGreaterEqual(migrations.CURRENT_SCHEMA_VERSION, 3)
        tables = {r["name"] for r in self.m.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for t in ("code_symbols", "symbol_relations", "boundaries"):
            self.assertIn(t, tables)


class TestFirefoxRecords(_R):
    def test_symbols_calls_and_boundary_crossing(self):
        self.m.register_symbol(self.snap, "cpp:Parser::Parse", qualified_name="mozilla::Parser::Parse",
                               language="cpp", kind="method", path="dom/Parser.cpp", start_line=100)
        self.m.register_symbol(self.snap, "cpp:Sink::Exec", qualified_name="mozilla::Sink::Exec",
                               language="cpp", kind="method", path="ipc/Sink.cpp", start_line=5)
        b = self.m.add_boundary(self.snap, "content->parent", kind="process",
                                description="content process to parent process IPC")
        self.m.link_symbols(self.snap, "cpp:Parser::Parse", "cpp:Sink::Exec", relation="calls",
                            dispatch="virtual", callsite_path="dom/Parser.cpp", callsite_line=140)
        self.m.link_symbols(self.snap, "cpp:Parser::Parse", "cpp:Sink::Exec",
                            relation="crosses_boundary", boundary_id=b)
        callees = self.m.callees(self.snap, "cpp:Parser::Parse")
        self.assertEqual(len(callees), 1)
        self.assertEqual(callees[0]["dispatch"], "virtual")       # uncertainty preserved
        callers = self.m.callers(self.snap, "cpp:Sink::Exec")
        self.assertEqual(callers[0]["src_symbol"], "cpp:Parser::Parse")

    def test_boundary_must_exist_for_crossing(self):
        self.m.register_symbol(self.snap, "a")
        self.m.register_symbol(self.snap, "b")
        with self.assertRaises(ValueError):
            self.m.link_symbols(self.snap, "a", "b", relation="crosses_boundary", boundary_id=999)

    def test_record_analysis_result_preserves_raw_and_bounds_projection(self):
        raw = '{"runs":[{"results":[' + ("{\"ruleId\":\"x\"}," * 500) + "]}]}"  # big SARIF-ish
        res = self.m.record_analysis_result(self.snap, tool="codeql", raw=raw,
                                            query_id="cpp/tainted-length")
        ev = self.m.get_evidence(res["evidence_id"])
        self.assertEqual(ev["status"], "observed")
        self.assertTrue(ev["artifact_id"])
        raw_back = self.m.store.get_artifact_bytes(ev["artifact_id"]).decode()
        self.assertEqual(raw_back, raw)                           # raw preserved verbatim
        self.assertLess(len(ev["projection"]), len(raw))          # projection bounded

    def test_audit_log_records_mutations(self):
        self.m.register_symbol(self.snap, "cpp:X")
        ops = {e["op"] for e in self.m.audit_log()}
        self.assertIn("register_symbol", ops)
        self.assertIn("register_snapshot", ops)


class TestBackupRestore(_R):
    def test_backup_restore_verify_resolves_artifacts_by_digest(self):
        res = self.m.record_analysis_result(self.snap, tool="codeql",
                                            raw="important SARIF evidence bytes")
        self.m.register_symbol(self.snap, "cpp:Keep::Me", qualified_name="Keep::Me")
        ev_id = res["evidence_id"]
        self.m.close()                                            # quiesce before backup

        dest = os.path.join(self.dir.name, "bak")
        manifest = backup.backup(self.path, dest)
        self.assertGreaterEqual(manifest["artifact_files"], 1)

        restored = os.path.join(self.dir.name, "restored.db")
        vr = backup.restore(dest, restored)
        self.assertTrue(vr["ok"])                                 # every artifact resolved
        self.assertEqual(vr["missing_or_corrupt"], [])

        m2 = ResearchMemory(restored)
        try:
            ev = m2.get_evidence(ev_id)
            self.assertIsNotNone(ev)
            self.assertEqual(m2.store.get_artifact_bytes(ev["artifact_id"]).decode(),
                             "important SARIF evidence bytes")
            self.assertEqual(m2.conn.execute(
                "SELECT COUNT(*) c FROM code_symbols").fetchone()["c"], 1)
        finally:
            m2.close()
        # reopen self.m so tearDown can close cleanly
        self.m = ResearchMemory(self.path)

    def test_verify_detects_corruption(self):
        res = self.m.record_analysis_result(self.snap, tool="t", raw="bytes")
        row = self.m.store.artifact_row(self.m.get_evidence(res["evidence_id"])["artifact_id"])
        disk = os.path.join(self.m.store.artifacts.root, row["storage_path"])
        self.m.close()
        with open(disk, "wb") as fh:
            fh.write(b"corrupted")
        vr = backup.verify(self.path)
        self.assertFalse(vr["ok"])
        self.assertEqual(len(vr["missing_or_corrupt"]), 1)
        self.m = ResearchMemory(self.path)


if __name__ == "__main__":
    unittest.main()
