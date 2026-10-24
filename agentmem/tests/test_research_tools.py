"""MCP contract-layer tests: stable error codes, idempotency, validation,
revision-aware query, and chain-gap review. Stdlib unittest."""
import os
import tempfile
import unittest

from agentmem import ResearchMemory
from agentmem.research_tools import (CONFLICT, INVALID_ARGUMENT, NOT_FOUND,
                                     RESOURCE_LIMIT, REVISION_MISMATCH, ResearchTools)


class _T(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.m = ResearchMemory(os.path.join(self.dir.name, "r.db"))
        self.t = ResearchTools(self.m)
        self.snap = self.t.register_repository_snapshot("firefox", "a" * 40)["data"]["snapshot_id"]

    def tearDown(self):
        self.m.close(); self.dir.cleanup()


class TestValidationAndErrorCodes(_T):
    def test_missing_args_is_invalid_argument(self):
        r = self.t.register_repository_snapshot(repo_id="", commit_id="")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"]["code"], INVALID_ARGUMENT)

    def test_unknown_snapshot_is_not_found(self):
        r = self.t.record_value_identity(snapshot_id=999999, path="f.cpp", value_name="x",
                                         role="source")
        self.assertEqual(r["error"]["code"], NOT_FOUND)

    def test_cross_snapshot_flow_is_revision_mismatch(self):
        other = self.t.register_repository_snapshot("firefox", "b" * 40)["data"]["snapshot_id"]
        a = self.t.record_value_identity(self.snap, "f.cpp", "x", role="source")["data"]["value_identity_id"]
        b = self.t.record_value_identity(other, "f.cpp", "y", role="sink",
                                         sink_type="sql")["data"]["value_identity_id"]
        r = self.t.link_flow_transition(self.snap, a, b, status="supported")
        self.assertEqual(r["error"]["code"], REVISION_MISMATCH)

    def test_query_limit_exceeded_is_resource_limit(self):
        r = self.t.query_history(snapshot_id=self.snap, limit=10_000)
        self.assertEqual(r["error"]["code"], RESOURCE_LIMIT)

    def test_bad_source_range_is_invalid_argument(self):
        r = self.t.record_source_reference(self.snap, "f.cpp", start_line=50, end_line=10)
        self.assertEqual(r["error"]["code"], INVALID_ARGUMENT)


class TestIdempotency(_T):
    def test_duplicate_mutation_replays_without_creating_a_new_record(self):
        k = "idem-123"
        r1 = self.t.record_hypothesis(self.snap, "H one", idempotency_key=k)
        r2 = self.t.record_hypothesis(self.snap, "H one", idempotency_key=k)
        self.assertEqual(r1["data"]["hypothesis_id"], r2["data"]["hypothesis_id"])
        self.assertTrue(r2["data"].get("idempotent_replay"))
        n = self.m.conn.execute("SELECT COUNT(*) c FROM hypotheses").fetchone()["c"]
        self.assertEqual(n, 1)                                   # no duplicate created

    def test_key_reused_for_different_op_conflicts(self):
        k = "shared-key"
        self.t.record_hypothesis(self.snap, "H", idempotency_key=k)
        r = self.t.record_value_identity(self.snap, "f.cpp", "x", role="source", idempotency_key=k)
        self.assertEqual(r["error"]["code"], CONFLICT)


class TestEvidenceTrustThroughContract(_T):
    def test_untrusted_evidence_status_is_gated(self):
        r = self.t.record_analysis_evidence(self.snap, kind="note", projection="looks bad",
                                            status="reproduced", trust="target_derived")
        self.assertTrue(r["ok"])
        self.assertEqual(r["data"]["stored_status"], "observed")  # gated down from reproduced


class TestReviewChainGaps(_T):
    def test_review_reports_missing_transitions(self):
        a = self.t.record_value_identity(self.snap, "f.cpp", "p0", role="source",
                                         symbol_id="A")["data"]["value_identity_id"]
        mid = self.t.record_value_identity(self.snap, "f.cpp", "p1", role="transform",
                                           symbol_id="B")["data"]["value_identity_id"]
        c = self.t.record_value_identity(self.snap, "f.cpp", "p2", role="sink", symbol_id="C",
                                         sink_type="exec")["data"]["value_identity_id"]
        self.t.link_flow_transition(self.snap, a, mid, status="demonstrated", trust="tool_verified")
        self.t.link_flow_transition(self.snap, mid, c, status="hypothesis")  # the gap
        rv = self.t.review_chain(self.snap)
        self.assertTrue(rv["ok"])
        chain = rv["data"]["chains"][0]
        self.assertFalse(chain["demonstrated"])
        self.assertEqual(len(chain["missing_transitions"]), 1)
        self.assertEqual(chain["missing_transitions"][0]["status"], "hypothesis")

    def test_fully_demonstrated_chain_has_no_gaps(self):
        a = self.t.record_value_identity(self.snap, "f.cpp", "p0", role="source",
                                         symbol_id="A")["data"]["value_identity_id"]
        c = self.t.record_value_identity(self.snap, "f.cpp", "p2", role="sink", symbol_id="C",
                                         sink_type="exec")["data"]["value_identity_id"]
        self.t.link_flow_transition(self.snap, a, c, status="demonstrated", trust="tool_verified")
        chain = self.t.review_chain(self.snap)["data"]["chains"][0]
        self.assertTrue(chain["demonstrated"])
        self.assertEqual(chain["missing_transitions"], [])


class TestExportBundle(_T):
    def test_unknown_snapshot_bundle_is_not_found(self):
        self.assertEqual(self.t.export_evidence_bundle(999999)["error"]["code"], NOT_FOUND)

    def test_bundle_contains_snapshot_identity(self):
        b = self.t.export_evidence_bundle(self.snap)
        self.assertTrue(b["ok"])
        self.assertEqual(b["data"]["snapshot"]["commit_id"], "a" * 40)


if __name__ == "__main__":
    unittest.main()
