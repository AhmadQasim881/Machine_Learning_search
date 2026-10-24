"""E3 active staleness / dependency invalidation: a changed source path marks the
old snapshot's dependent records stale (and retracts chains through changed code),
while unrelated well-scoped records stay current. Stdlib unittest."""
import os
import tempfile
import unittest

from agentmem import ResearchMemory


class _R(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.m = ResearchMemory(os.path.join(self.dir.name, "r.db"))
        self.snap = self.m.register_snapshot("firefox", "a" * 40, scope="dom")

    def tearDown(self):
        self.m.close(); self.dir.cleanup()


class TestActiveStaleness(_R):
    def _chain_on(self, path):
        src = self.m.add_value_identity(self.snap, path, "x", role="source", symbol_id="S",
                                        start_line=1)
        sink = self.m.add_value_identity(self.snap, path, "q", role="sink", symbol_id="K",
                                         start_line=9, sink_type="sql")
        self.m.add_flow_edge(self.snap, src, sink, status="demonstrated", trust="tool_verified")
        return src, sink

    def test_changed_path_stales_dependent_records_and_retracts_chain(self):
        src, sink = self._chain_on("dom/Parser.cpp")
        ev = self.m.add_evidence(self.snap, "static_analysis", projection="codeql path on Parser",
                                 value_identity_id=sink, status="supported", trust="tool_verified")
        self.assertEqual({c["goal"] for c in self.m.chains(self.snap)}, {"full_db_read"})

        counts = self.m.invalidate_changed_paths(self.snap, ["dom/Parser.cpp"],
                                                 reason="Parser.cpp edited")
        self.assertGreaterEqual(counts["identities"], 2)
        self.assertGreaterEqual(counts["evidence"], 1)
        # chain through the changed file is retracted
        self.assertEqual(self.m.chains(self.snap), [])
        # the evidence is now stale
        self.assertEqual(self.m.get_evidence(ev)["status"], "stale")

    def test_unrelated_records_stay_current(self):
        self._chain_on("dom/Parser.cpp")                 # will be invalidated
        self._chain_on("net/Http.cpp")                   # unrelated, must stay
        self.m.invalidate_changed_paths(self.snap, ["dom/Parser.cpp"])
        goals_paths = [s["src_vid"] for c in self.m.chains(self.snap) for s in c["steps"]]
        # exactly the Http.cpp chain remains
        chains = self.m.chains(self.snap)
        self.assertEqual(len(chains), 1)
        remaining_vid = chains[0]["steps"][0]["src_vid"]
        row = self.m.conn.execute("SELECT path FROM value_identities WHERE id=?",
                                  (remaining_vid,)).fetchone()
        self.assertEqual(row["path"], "net/Http.cpp")

    def test_supported_hypothesis_reverts_and_finding_impact_downgrades(self):
        src, sink = self._chain_on("dom/Parser.cpp")
        ev = self.m.add_evidence(self.snap, "static_analysis", projection="e",
                                 value_identity_id=sink, status="supported", trust="tool_verified")
        h = self.m.add_hypothesis(self.snap, "overflow", status="supported")
        self.m.link_evidence(h, "supports", evidence_id=ev)
        f = self.m.add_finding(self.snap, "F", root_cause="rc", impact_state="demonstrated",
                               hypothesis_id=h)
        # finding got demonstrated impact (a demonstrated chain existed)
        self.assertEqual(self.m.conn.execute(
            "SELECT impact_state FROM findings WHERE id=?", (f,)).fetchone()["impact_state"],
            "demonstrated")
        self.m.invalidate_changed_paths(self.snap, ["dom/Parser.cpp"])
        self.assertEqual(self.m.get_hypothesis(h)["status"], "open")        # support staled
        self.assertEqual(self.m.conn.execute(
            "SELECT impact_state FROM findings WHERE id=?", (f,)).fetchone()["impact_state"],
            "suspected")

    def test_new_revision_cannot_silently_refresh_old_evidence(self):
        # evidence on the old snapshot, then a new snapshot for the same repo/scope
        self._chain_on("dom/Parser.cpp")
        self.m.invalidate_changed_paths(self.snap, ["dom/Parser.cpp"])
        new_snap = self.m.register_snapshot("firefox", "b" * 40, scope="dom")
        # the new snapshot has no chains until facts are recorded against IT
        self.assertEqual(self.m.chains(new_snap), [])
        # and the old staled records are not resurrected by the new snapshot existing
        self.assertEqual(self.m.chains(self.snap), [])


if __name__ == "__main__":
    unittest.main()
