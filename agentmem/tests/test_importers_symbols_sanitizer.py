"""Symbol-index importer and ASan/UBSan log parser. Stdlib unittest."""
import os
import tempfile
import unittest

from agentmem import ResearchMemory
from agentmem.importers import import_sanitizer_log, import_symbols, parse_sanitizer_log

_ASAN = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000d10
WRITE of size 4 at 0x602000000d10 thread T0
    #0 0x55f0 in mozilla::Foo::Parse dom/Foo.cpp:142:7
    #1 0x55a0 in mozilla::Handler::OnData dom/Handler.cpp:88:5
    #2 0x5500 in main main.cpp:10
SUMMARY: AddressSanitizer: heap-buffer-overflow dom/Foo.cpp:142:7 in mozilla::Foo::Parse
"""


class _R(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.m = ResearchMemory(os.path.join(self.dir.name, "r.db"))
        self.snap = self.m.register_snapshot("firefox", "a" * 40, scope="dom")

    def tearDown(self):
        self.m.close(); self.dir.cleanup()


class TestSymbolImport(_R):
    INDEX = {
        "tool": "searchfox", "version": "2024-06",
        "symbols": [
            {"symbol_id": "cpp:Foo::Parse", "qualified_name": "mozilla::Foo::Parse",
             "language": "cpp", "kind": "method", "path": "dom/Foo.cpp", "start_line": 120,
             "trust_domain": "content-process"},
            {"symbol_id": "cpp:Bar::Write", "qualified_name": "mozilla::Bar::Write",
             "language": "cpp", "kind": "method", "path": "ipc/Bar.cpp", "start_line": 5},
        ],
        "relations": [
            {"src": "cpp:Foo::Parse", "dst": "cpp:Bar::Write", "relation": "calls",
             "dispatch": "virtual", "callsite_path": "dom/Foo.cpp", "callsite_line": 142},
            {"src": "cpp:Foo::Parse", "dst": "cpp:External::Thing", "relation": "calls"},
        ],
    }

    def test_import_populates_symbols_and_relations(self):
        s = import_symbols(self.m, self.snap, self.INDEX)
        self.assertEqual(s["symbols"], 2)
        self.assertEqual(s["relations"], 2)
        self.assertEqual(s["unknown_relation_endpoints"], 1)   # External::Thing not in the set
        callees = self.m.callees(self.snap, "cpp:Foo::Parse")
        self.assertEqual({c["dst_symbol"] for c in callees}, {"cpp:Bar::Write", "cpp:External::Thing"})
        virt = [c for c in callees if c["dst_symbol"] == "cpp:Bar::Write"][0]
        self.assertEqual(virt["dispatch"], "virtual")          # call uncertainty preserved
        self.assertEqual(self.m.callers(self.snap, "cpp:Bar::Write")[0]["src_symbol"], "cpp:Foo::Parse")

    def test_malformed_index_rejected(self):
        with self.assertRaises(ValueError):
            import_symbols(self.m, self.snap, {"nope": 1})


class TestSanitizerImport(_R):
    def test_parse_extracts_type_access_and_frames(self):
        d = parse_sanitizer_log(_ASAN)
        self.assertEqual(d["type"], "heap-buffer-overflow")
        self.assertEqual(d["access"], "WRITE")
        self.assertEqual(d["access_size"], 4)
        self.assertIn("mozilla::Foo::Parse dom/Foo.cpp:142:7", d["top_frames"][0])

    def test_import_records_crash_evidence_and_validation_without_severity(self):
        res = import_sanitizer_log(self.m, self.snap, _ASAN)
        self.assertEqual(res["diagnostic"]["type"], "heap-buffer-overflow")
        ev = self.m.get_evidence(res["evidence_id"])
        self.assertEqual(ev["kind"], "crash")
        self.assertEqual(ev["status"], "observed")             # a crash is observed, not 'reproduced'
        # raw log preserved verbatim by digest
        self.assertEqual(self.m.store.get_artifact_bytes(ev["artifact_id"]).decode(), _ASAN)
        vr = self.m.conn.execute("SELECT kind,status FROM validation_runs WHERE id=?",
                                 (res["validation_run_id"],)).fetchone()
        self.assertEqual((vr["kind"], vr["status"]), ("repro", "failed"))
        # no finding was created and no severity assigned
        self.assertEqual(self.m.conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"], 0)

    def test_unclassified_log_still_preserved(self):
        d = parse_sanitizer_log("some unrelated output with no sanitizer markers")
        self.assertEqual(d["type"], "unclassified")


if __name__ == "__main__":
    unittest.main()
