"""Evidence/provenance/state regression tests: FK-checked ids, trust-gated
status, independent-provenance consensus, append-only sink reclassification
(stales the old chain), and cross-revision staleness labelling. Stdlib."""
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


class TestProvenanceAndIds(_R):
    def test_nonexistent_observation_id_rejected(self):
        with self.assertRaises(ValueError):
            self.m.add_evidence(self.snap, "note", projection="x", obs_id=999999)

    def test_nonexistent_evidence_id_rejected_in_link(self):
        h = self.m.add_hypothesis(self.snap, "H1")
        with self.assertRaises(ValueError):
            self.m.link_evidence(h, "supports", evidence_id=999999)

    def test_nonexistent_evidence_id_rejected_in_consensus(self):
        h = self.m.add_hypothesis(self.snap, "H1")
        with self.assertRaises(ValueError):
            self.m.consensus_promote(h, [999999])

    def test_flow_edge_evidence_id_must_exist(self):
        a = self.m.add_value_identity(self.snap, "f.cpp", "x", role="source", symbol_id="A")
        b = self.m.add_value_identity(self.snap, "f.cpp", "y", role="sink", symbol_id="B",
                                      sink_type="sql")
        # evidence_id referencing a nonexistent evidence row is rejected
        with self.assertRaises(Exception):
            self.m.add_flow_edge(self.snap, a, b, status="supported", evidence_id=424242)


class TestTrustGate(_R):
    def test_untrusted_evidence_cannot_self_promote(self):
        e = self.m.add_evidence(self.snap, "note", projection="looks bad",
                                status="reproduced", trust="target_derived")
        self.assertEqual(self.m.get_evidence(e)["status"], "observed")  # gated down

    def test_llm_inferred_cannot_claim_reproduced(self):
        e = self.m.add_evidence(self.snap, "note", projection="maybe",
                                status="reproduced", trust="llm_inferred")
        self.assertEqual(self.m.get_evidence(e)["status"], "supported")  # not reproduced

    def test_tool_verified_may_be_reproduced(self):
        e = self.m.add_evidence(self.snap, "static_analysis", projection="codeql path",
                                status="reproduced", trust="tool_verified")
        self.assertEqual(self.m.get_evidence(e)["status"], "reproduced")


class TestConsensus(_R):
    def _ev(self, actor, tool, trust="tool_verified", kind="static_analysis"):
        p = self.m.add_provenance(self.snap, tool=tool, actor=actor, actor_kind="tool", trust=trust)
        return self.m.add_evidence(self.snap, kind, projection=f"{tool} says so",
                                   status="supported", trust=trust, provenance_id=p)

    def test_independent_evidence_promotes_to_supported_only(self):
        h = self.m.add_hypothesis(self.snap, "buffer overflow in parser")
        e1 = self._ev("codeql", "codeql")
        e2 = self._ev("reviewer", "human-review", trust="human_verified", kind="note")
        res = self.m.consensus_promote(h, [e1, e2])
        self.assertTrue(res["promoted"])
        self.assertEqual(res["status"], "supported")                 # never 'demonstrated'
        self.assertEqual(self.m.get_hypothesis(h)["status"], "supported")

    def test_same_provenance_does_not_promote(self):
        h = self.m.add_hypothesis(self.snap, "H")
        p = self.m.add_provenance(self.snap, tool="codeql", actor="codeql", trust="tool_verified")
        e1 = self.m.add_evidence(self.snap, "static_analysis", projection="a",
                                 status="supported", trust="tool_verified", provenance_id=p)
        e2 = self.m.add_evidence(self.snap, "static_analysis", projection="b",
                                 status="supported", trust="tool_verified", provenance_id=p)
        res = self.m.consensus_promote(h, [e1, e2])                  # same provenance => not independent
        self.assertFalse(res["promoted"])
        self.assertEqual(self.m.get_hypothesis(h)["status"], "open")

    def test_untrusted_evidence_does_not_promote(self):
        h = self.m.add_hypothesis(self.snap, "H")
        p1 = self.m.add_provenance(self.snap, tool="t1", actor="a1", trust="target_derived")
        p2 = self.m.add_provenance(self.snap, tool="t2", actor="a2", trust="target_derived")
        e1 = self.m.add_evidence(self.snap, "note", projection="x", status="observed",
                                 trust="target_derived", provenance_id=p1)
        e2 = self.m.add_evidence(self.snap, "note", projection="y", status="observed",
                                 trust="target_derived", provenance_id=p2)
        res = self.m.consensus_promote(h, [e1, e2])
        self.assertFalse(res["promoted"])


class TestReclassificationStalesChain(_R):
    def test_reclassifying_a_sink_retracts_the_old_classification_chain(self):
        src = self.m.add_value_identity(self.snap, "db.cpp", "raw", role="source",
                                        symbol_id="Read", start_line=1)
        sink = self.m.add_value_identity(self.snap, "db.cpp", "q", role="sink", symbol_id="Exec",
                                         start_line=9, sink_type="sql")
        self.m.add_flow_edge(self.snap, src, sink, status="demonstrated", trust="tool_verified")
        self.assertEqual({c["goal"] for c in self.m.chains(self.snap)}, {"full_db_read"})
        self.m.reclassify_sink(sink, "log", reason="actually a logging call, not a query")
        goals = {c["goal"] for c in self.m.chains(self.snap)}
        self.assertNotIn("full_db_read", goals)                      # old chain retracted
        self.assertIn("injection", goals)                            # log -> injection


class TestCrossRevisionStaleness(_R):
    def test_other_revision_evidence_is_labelled_stale(self):
        snap_b = self.m.register_snapshot("firefox", "b" * 40, scope="dom")
        ea = self.m.add_evidence(self.snap, "note", projection="finding on revision A")
        res = self.m.evidence_for(snap_b, include_historical=True)
        self.assertEqual(res["current"], [])                         # nothing current on B
        hist_ids = {h["id"]: h for h in res["historical"]}
        self.assertIn(ea, hist_ids)
        self.assertTrue(hist_ids[ea]["stale"])
        self.assertTrue(hist_ids[ea]["revision_mismatch"])
        # on revision A it is current, not stale
        res_a = self.m.evidence_for(self.snap)
        self.assertTrue(any(e["id"] == ea and not e["stale"] for e in res_a["current"]))


if __name__ == "__main__":
    unittest.main()
