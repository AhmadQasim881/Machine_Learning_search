"""CodeQL/SARIF importer: codeFlows become scoped value identities + explicit
flow edges + evidence, with the raw SARIF preserved verbatim. Stdlib unittest."""
import json
import os
import tempfile
import unittest

from agentmem import ResearchMemory
from agentmem.importers import import_sarif

SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "CodeQL", "version": "2.16.0"}},
        "results": [
            {
                "ruleId": "cpp/sql-injection",
                "message": {"text": "user input flows to a SQL query"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "db/exec.cpp"}, "region": {"startLine": 40}}}],
                "codeFlows": [{"threadFlows": [{"locations": [
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": "dom/a.cpp"}, "region": {"startLine": 10}},
                        "message": {"text": "req.body"},
                        "logicalLocations": [{"fullyQualifiedName": "Handler::read"}]}},
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": "lib/util.cpp"}, "region": {"startLine": 5}},
                        "message": {"text": "buf"},
                        "logicalLocations": [{"fullyQualifiedName": "util::build"}]}},
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": "db/exec.cpp"}, "region": {"startLine": 40}},
                        "message": {"text": "stmt"},
                        "logicalLocations": [{"fullyQualifiedName": "Db::exec"}]}},
                ]}]}],
            },
            {   # no codeFlows -> sink-only evidence
                "ruleId": "cpp/command-line-injection",
                "message": {"text": "tainted arg reaches system()"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "os/run.cpp"}, "region": {"startLine": 7}},
                    "logicalLocations": [{"fullyQualifiedName": "os::run"}]}],
            },
        ],
    }],
}


class TestSarifImport(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.m = ResearchMemory(os.path.join(self.dir.name, "r.db"))
        self.snap = self.m.register_snapshot("firefox", "a" * 40, scope="dom")

    def tearDown(self):
        self.m.close(); self.dir.cleanup()

    def test_import_builds_flow_graph_and_preserves_raw(self):
        s = import_sarif(self.m, self.snap, SARIF)
        self.assertEqual(s["results"], 2)
        self.assertEqual(s["flows"], 1)
        self.assertEqual(s["value_identities"], 4)        # 3 in the path + 1 sink-only
        self.assertEqual(s["flow_edges"], 2)              # source->transform->sink
        self.assertEqual(s["evidence"], 2)

        # the codeQL path becomes a chain — but only 'supported' (tool evidence is
        # not a runtime demonstration)
        chains = self.m.chains(self.snap)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["goal"], "full_db_read")
        self.assertEqual(chains[0]["status"], "supported")
        self.assertNotEqual(chains[0]["status"], "demonstrated")

        # raw SARIF preserved verbatim, retrievable by digest
        art = self.m.conn.execute("SELECT id FROM artifacts WHERE sha256=?",
                                  (s["sarif_artifact"],)).fetchone()
        self.assertEqual(self.m.store.get_artifact_bytes(art["id"]).decode(),
                         json.dumps(SARIF))

    def test_identities_are_scoped_not_name_matched(self):
        import_sarif(self.m, self.snap, SARIF)
        rows = self.m.conn.execute(
            "SELECT path, role, sink_type, symbol_id FROM value_identities "
            "WHERE snapshot_id=? ORDER BY id", (self.snap,)).fetchall()
        paths = {r["path"] for r in rows}
        self.assertEqual(paths, {"dom/a.cpp", "lib/util.cpp", "db/exec.cpp", "os/run.cpp"})
        sinks = {(r["path"], r["sink_type"]) for r in rows if r["role"] == "sink"}
        self.assertIn(("db/exec.cpp", "sql"), sinks)
        self.assertIn(("os/run.cpp", "command"), sinks)   # ruleId -> sink_type mapping

    def test_string_input_and_malformed(self):
        s = import_sarif(self.m, self.snap, json.dumps(SARIF))   # accepts a JSON string
        self.assertEqual(s["results"], 2)
        with self.assertRaises(ValueError):
            import_sarif(self.m, self.snap, '{"not":"sarif"}')


if __name__ == "__main__":
    unittest.main()
