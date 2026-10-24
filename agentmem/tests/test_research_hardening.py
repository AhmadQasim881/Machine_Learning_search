"""E1 hardening regression tests: bounded chain search, finding-impact gating,
true idempotency (arg-aware), strict-revision retrieval, FTS sync on status
change, and reclassification evidence carry-forward. Stdlib unittest."""
import os
import tempfile
import unittest

from agentmem import ResearchMemory
from agentmem.research import _MAX_CHAIN_RESULTS
from agentmem.research_tools import CONFLICT, ResearchTools


class _R(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.m = ResearchMemory(os.path.join(self.dir.name, "r.db"))
        self.snap = self.m.register_snapshot("firefox", "a" * 40, scope="dom")

    def tearDown(self):
        self.m.close(); self.dir.cleanup()


class TestBoundedChainSearch(_R):
    def test_diamond_terminates_and_is_bounded(self):
        src = self.m.add_value_identity(self.snap, "f.cpp", "x", role="source", symbol_id="S")
        a = self.m.add_value_identity(self.snap, "f.cpp", "a", role="transform", symbol_id="A")
        b = self.m.add_value_identity(self.snap, "f.cpp", "b", role="transform", symbol_id="B")
        sink = self.m.add_value_identity(self.snap, "f.cpp", "q", role="sink", symbol_id="K",
                                         sink_type="sql")
        for mid in (a, b):
            self.m.add_flow_edge(self.snap, src, mid, status="supported")
            self.m.add_flow_edge(self.snap, mid, sink, status="supported")
        chains = self.m.chains(self.snap)
        self.assertEqual(len(chains), 2)                      # two distinct paths to the sink
        self.assertLessEqual(len(chains), _MAX_CHAIN_RESULTS)  # always bounded


class TestFindingImpactGate(_R):
    def test_demonstrated_impact_requires_backing(self):
        # no demonstrated chain, no passed validation -> impact downgraded
        fid = self.m.add_finding(self.snap, "F1", root_cause="rc1", impact_state="demonstrated")
        self.assertEqual(self.m.conn.execute(
            "SELECT impact_state FROM findings WHERE id=?", (fid,)).fetchone()["impact_state"],
            "suspected")

    def test_demonstrated_impact_allowed_with_demonstrated_chain(self):
        src = self.m.add_value_identity(self.snap, "f.cpp", "x", role="source", symbol_id="S")
        sink = self.m.add_value_identity(self.snap, "f.cpp", "q", role="sink", symbol_id="K",
                                         sink_type="sql")
        self.m.add_flow_edge(self.snap, src, sink, status="demonstrated", trust="tool_verified")
        fid = self.m.add_finding(self.snap, "F2", root_cause="rc2", impact_state="demonstrated")
        self.assertEqual(self.m.conn.execute(
            "SELECT impact_state FROM findings WHERE id=?", (fid,)).fetchone()["impact_state"],
            "demonstrated")


class TestTrueIdempotency(_R):
    def test_same_key_different_args_conflicts(self):
        t = ResearchTools(self.m)
        snap = t.register_repository_snapshot("firefox", "b" * 40)["data"]["snapshot_id"]
        r1 = t.record_hypothesis(snap, "statement ONE", idempotency_key="k9")
        self.assertTrue(r1["ok"])
        r2 = t.record_hypothesis(snap, "statement TWO", idempotency_key="k9")  # same key, new args
        self.assertFalse(r2["ok"])
        self.assertEqual(r2["error"]["code"], CONFLICT)

    def test_same_key_same_args_replays(self):
        t = ResearchTools(self.m)
        snap = t.register_repository_snapshot("firefox", "c" * 40)["data"]["snapshot_id"]
        r1 = t.record_hypothesis(snap, "same", idempotency_key="k10")
        r2 = t.record_hypothesis(snap, "same", idempotency_key="k10")
        self.assertEqual(r1["data"]["hypothesis_id"], r2["data"]["hypothesis_id"])
        self.assertTrue(r2["data"].get("idempotent_replay"))


class TestStrictRevisionRetrieval(_R):
    def test_revision_current_excludes_other_revisions(self):
        other = self.m.register_snapshot("firefox", "b" * 40, scope="dom")
        self.m.add_evidence(other, "note", projection="memcpy on B")
        self.m.add_evidence(self.snap, "note", projection="memcpy on A")
        hits = self.m.search_evidence(snapshot_id=self.snap, text="memcpy", revision="current")
        self.assertTrue(hits)
        self.assertTrue(all(h["snapshot_id"] == self.snap and not h["stale"] for h in hits))


class TestFtsSync(_R):
    def test_rejected_evidence_drops_out_of_free_text_search(self):
        if self.m.text_search_backend() != "fts5":
            self.skipTest("FTS5 not available in this SQLite build")
        e = self.m.add_evidence(self.snap, "note", projection="zzsentinel token here")
        self.assertTrue(self.m.search_evidence(snapshot_id=self.snap, text="zzsentinel"))
        self.m.set_evidence_status(e, "rejected", reason="false positive")
        self.assertEqual(self.m.search_evidence(snapshot_id=self.snap, text="zzsentinel"), [])


class TestReclassifyCarriesEvidenceForward(_R):
    def test_evidence_follows_the_repointed_edge(self):
        src = self.m.add_value_identity(self.snap, "f.cpp", "x", role="source", symbol_id="S")
        sink = self.m.add_value_identity(self.snap, "f.cpp", "q", role="sink", symbol_id="K",
                                         sink_type="sql")
        edge = self.m.add_flow_edge(self.snap, src, sink, status="demonstrated", trust="tool_verified")
        ev = self.m.add_evidence(self.snap, "static_analysis", projection="codeql path",
                                 flow_edge_id=edge)
        self.m.reclassify_sink(sink, "log")
        new_edge = self.m.get_evidence(ev)["flow_edge_id"]
        self.assertNotEqual(new_edge, edge)                   # no longer points at the closed edge
        row = self.m.conn.execute("SELECT valid_to FROM flow_edges WHERE id=?", (new_edge,)).fetchone()
        self.assertIsNone(row["valid_to"])                    # points at a current edge


if __name__ == "__main__":
    unittest.main()
