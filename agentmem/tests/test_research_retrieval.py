"""Retrieval regression tests: free-text works without embeddings, bounded
retrieval avoids N+1, and exact-revision matches rank first with historical rows
labelled stale. Stdlib unittest."""
import os
import tempfile
import unittest

from agentmem import Memory, ResearchMemory


class _R(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.m = ResearchMemory(os.path.join(self.dir.name, "r.db"))
        self.snap = self.m.register_snapshot("firefox", "a" * 40, scope="dom")

    def tearDown(self):
        self.m.close(); self.dir.cleanup()


def _count_statements(conn, fn):
    n = {"c": 0}
    conn.set_trace_callback(lambda _s: n.__setitem__("c", n["c"] + 1))
    try:
        fn()
    finally:
        conn.set_trace_callback(None)
    return n["c"]


class TestFreeTextWithoutEmbeddings(_R):
    def test_research_free_text_search(self):
        self.m.add_evidence(self.snap, "static_analysis",
                            projection="tainted length used in memcpy at nsFoo::Copy")
        self.m.add_evidence(self.snap, "note", projection="unrelated styling note")
        hits = self.m.search_evidence(snapshot_id=self.snap, text="memcpy")
        self.assertEqual(len(hits), 1)
        self.assertIn("memcpy", hits[0]["preview"])
        # a text backend is always reported (fts5 or the documented like fallback)
        self.assertIn(self.m.text_search_backend(), ("fts5", "like"))

    def test_legacy_recall_query_not_ignored_without_embeddings(self):
        with tempfile.TemporaryDirectory() as d:
            m = Memory(os.path.join(d, "w.db"))                 # embeddings OFF
            m.add_finding("open_redirect", host="app.target.com", path="/out", param="url",
                          confirmed=True, oracle="302 reflects", attrs={"host": "app.target.com"})
            m.add_finding("idor", host="api.target.com", path="/u/1", param="id",
                          confirmed=True, oracle="read other user")
            hits = m.recall(query="redirect")
            self.assertTrue(any(h["attrs"].get("vuln_class") == "open_redirect" for h in hits),
                            "a free-text query must still match without embeddings")
            m.close()


class TestBoundedRetrievalAvoidsNPlusOne(_R):
    def _seed(self, n):
        conn = self.m.conn
        import time
        now = time.time()
        with self.m.store.transaction():
            for i in range(n):
                conn.execute(
                    "INSERT INTO evidence(snapshot_id,kind,projection,projection_truncated,"
                    "status,trust,version,valid_from,valid_to,created_ts,meta_json) "
                    "VALUES(?,?,?,0,'observed','tool_verified',1,?,NULL,?,'{}')",
                    (self.snap, "static_analysis", f"finding {i} memcpy length", now, now + i))

    def test_statement_count_is_bounded_and_independent_of_n(self):
        # structured, bounded query: one SQL statement does filter+rank+paginate, so
        # the executed-statement count is a small constant, NOT proportional to rows
        # (the old N+1 pattern issued ~N statements). Uses the structured path so the
        # assertion is deterministic (free-text correctness is covered separately).
        self._seed(400)
        c_small = _count_statements(self.m.conn, lambda: self.m.search_evidence(
            snapshot_id=self.snap, status="observed", limit=20))
        self._seed(1200)                                        # now 1600 rows
        c_big = _count_statements(self.m.conn, lambda: self.m.search_evidence(
            snapshot_id=self.snap, status="observed", limit=20))
        self.assertEqual(c_small, c_big, "bounded query must not scale with store size")
        self.assertLessEqual(c_big, 5, "a bounded query must issue a small constant # of statements")


class TestExactRevisionFirst(_R):
    def test_exact_revision_ranks_first_and_historical_is_labelled(self):
        snap_b = self.m.register_snapshot("firefox", "b" * 40, scope="dom")
        self.m.add_evidence(snap_b, "note", projection="memcpy finding on revision B")
        self.m.add_evidence(self.snap, "note", projection="memcpy finding on revision A")
        hits = self.m.search_evidence(snapshot_id=self.snap, text="memcpy", limit=10)
        self.assertEqual(hits[0]["snapshot_id"], self.snap)     # exact revision first
        self.assertFalse(hits[0]["stale"])
        self.assertTrue(any(h["snapshot_id"] == snap_b and h["stale"] and h["revision_mismatch"]
                            for h in hits))                     # other revision labelled stale


if __name__ == "__main__":
    unittest.main()
