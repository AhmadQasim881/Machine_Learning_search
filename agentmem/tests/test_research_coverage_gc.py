"""Final enhancements: claim-coverage view, trust-boundary composition in
review_chain, disclosure-grade bundle export, and artifact GC/retention. Stdlib."""
import json
import os
import tempfile
import unittest

from agentmem import ResearchMemory
from agentmem.research_tools import ResearchTools


class _R(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.m = ResearchMemory(os.path.join(self.dir.name, "r.db"))
        self.snap = self.m.register_snapshot("firefox", "a" * 40, scope="dom")

    def tearDown(self):
        self.m.close(); self.dir.cleanup()


class TestClaimCoverage(_R):
    def test_coverage_classifies_support(self):
        h = self.m.add_hypothesis(self.snap, "H")
        e_dir = self.m.add_evidence(self.snap, "static_analysis", projection="codeql", trust="tool_verified")
        e_dyn = self.m.add_evidence(self.snap, "crash", projection="asan", trust="tool_verified")
        self.m.link_evidence(h, "supports", evidence_id=e_dir)
        self.m.link_evidence(h, "supports", evidence_id=e_dyn)
        cov = self.m.claim_coverage(h)
        self.assertEqual(cov["coverage"]["direct"], 1)
        self.assertEqual(cov["coverage"]["dynamic"], 1)
        self.assertFalse(cov["uncovered"])

    def test_uncovered_and_counter_evidence(self):
        h = self.m.add_hypothesis(self.snap, "H2")
        cov = self.m.claim_coverage(h)
        self.assertTrue(cov["uncovered"])
        e = self.m.add_evidence(self.snap, "note", projection="disproves it")
        self.m.link_evidence(h, "contradicts", evidence_id=e)
        self.assertTrue(self.m.claim_coverage(h)["has_counter_evidence"])


class TestBoundaryComposition(_R):
    def test_boundary_crossing_without_evidence_is_not_demonstrated(self):
        # a fully 'demonstrated' edge, but the two symbols live in different trust
        # domains with no recorded crosses_boundary relation -> composed chain is
        # NOT demonstrated (the boundary crossing is unproven).
        self.m.register_symbol(self.snap, "content:read", path="a.cpp", trust_domain="content-process")
        self.m.register_symbol(self.snap, "parent:exec", path="b.cpp", trust_domain="parent-process")
        src = self.m.add_value_identity(self.snap, "a.cpp", "x", role="source", symbol_id="content:read")
        sink = self.m.add_value_identity(self.snap, "b.cpp", "y", role="sink", symbol_id="parent:exec",
                                         sink_type="exec")
        self.m.add_flow_edge(self.snap, src, sink, status="demonstrated", trust="tool_verified")
        t = ResearchTools(self.m)
        chain = t.review_chain(self.snap)["data"]["chains"][0]
        self.assertFalse(chain["demonstrated"])                # boundary gap caps it
        self.assertEqual(len(chain["boundary_gaps"]), 1)
        self.assertEqual(chain["boundary_gaps"][0]["from_domain"], "content-process")

    def test_recorded_boundary_crossing_clears_the_gap(self):
        self.m.register_symbol(self.snap, "content:read", path="a.cpp", trust_domain="content-process")
        self.m.register_symbol(self.snap, "parent:exec", path="b.cpp", trust_domain="parent-process")
        b = self.m.add_boundary(self.snap, "content->parent", kind="process")
        self.m.link_symbols(self.snap, "content:read", "parent:exec", relation="crosses_boundary",
                            boundary_id=b)
        src = self.m.add_value_identity(self.snap, "a.cpp", "x", role="source", symbol_id="content:read")
        sink = self.m.add_value_identity(self.snap, "b.cpp", "y", role="sink", symbol_id="parent:exec",
                                         sink_type="exec")
        self.m.add_flow_edge(self.snap, src, sink, status="demonstrated", trust="tool_verified")
        chain = ResearchTools(self.m).review_chain(self.snap)["data"]["chains"][0]
        self.assertEqual(chain["boundary_gaps"], [])
        self.assertTrue(chain["demonstrated"])


class TestBundleExport(_R):
    def test_bundle_is_self_contained_and_resolves_by_digest(self):
        res = self.m.record_analysis_result(self.snap, tool="codeql", raw="SARIF evidence bytes")
        dest = os.path.join(self.dir.name, "bundle")
        summary = self.m.export_bundle_to_dir(self.snap, dest)
        self.assertGreaterEqual(summary["evidence"], 1)
        self.assertGreaterEqual(summary["artifacts"], 1)
        with open(os.path.join(dest, "manifest.json")) as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["snapshot"]["commit_id"], "a" * 40)
        # each referenced artifact is present in the bundle and matches its digest
        import hashlib
        for a in manifest["artifacts"]:
            p = os.path.join(dest, "artifacts", a["sha256"])
            self.assertTrue(os.path.exists(p))
            with open(p, "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), a["sha256"])


class TestArtifactGC(_R):
    def test_unreferenced_expirable_is_swept_referenced_and_keep_are_not(self):
        exp = self.m.store.put_artifact(b"temp junk", retention="expirable")          # unreferenced
        keep = self.m.store.put_artifact(b"keep me", retention="keep")                # unreferenced but keep
        res = self.m.record_analysis_result(self.snap, tool="t", raw="referenced bytes")
        referenced_sha = self.m.store.artifact_row(
            self.m.get_evidence(res["evidence_id"])["artifact_id"])["sha256"]

        gc = self.m.store.gc_artifacts(grace_seconds=0)
        self.assertIn(exp["sha256"], gc["deleted"])
        self.assertNotIn(keep["sha256"], gc["deleted"])
        self.assertNotIn(referenced_sha, gc["deleted"])
        # the swept blob is gone; the kept and referenced ones resolve
        self.assertFalse(self.m.store.artifacts.exists(exp["sha256"]))
        self.assertTrue(self.m.store.artifacts.exists(keep["sha256"]))
        self.assertTrue(self.m.store.artifacts.verify(referenced_sha))

    def test_referenced_expirable_is_kept(self):
        a = self.m.store.put_artifact(b"expirable but used", retention="expirable")
        # reference it from a validation run
        self.m.conn.execute("INSERT INTO validation_runs(snapshot_id,kind,status,artifact_id,created_ts)"
                            " VALUES(?,?,?,?,?)", (self.snap, "repro", "failed", a["id"], 1.0))
        gc = self.m.store.gc_artifacts(grace_seconds=0)
        self.assertNotIn(a["sha256"], gc["deleted"])


if __name__ == "__main__":
    unittest.main()
