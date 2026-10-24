"""Tests for the backlog features: consensus promotion + provenance, persisted
hypothesis nodes, portrait summaries, embeddings/semantic recall + SAME_AS, and
incremental chain detection across separate writes. Stdlib unittest."""
import os
import tempfile
import unittest

from agentmem import Memory
from agentmem.profiles import CODEREVIEW


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def mk(self, **kw):
        return Memory(os.path.join(self.dir.name, "b.db"), **kw)


class TestConsensus(_Base):
    def test_two_observations_promote_suspected(self):
        m = self.mk()
        o1 = m.observe("GET /u/1", "looks like idor")
        fid = m.add_finding("idor", host="h", path="/u/1", param="id", confirmed=False,
                            obs_id=o1, attrs={"object": "user_record", "scope": "any_user"})
        self.assertEqual(m.store.get_node(fid)["status"], "suspected")
        o2 = m.observe("GET /u/2", "same idor on another id")
        fid2 = m.add_finding("idor", host="h", path="/u/2", param="id", confirmed=False,
                             obs_id=o2, attrs={"object": "user_record", "scope": "any_user"})
        self.assertEqual(fid, fid2)                      # same canonical node (/u/{id})
        node = m.store.get_node(fid)
        self.assertEqual(node["status"], "confirmed")    # consensus promoted it
        self.assertEqual(m.store.node_attrs(fid).get("oracle"), "consensus")
        self.assertEqual(len(m.store.node_attrs(fid).get("_provenance", [])), 2)
        m.close()


class TestHypotheses(_Base):
    def test_hypotheses_persist_and_resolve(self):
        m = self.mk()
        m.add_finding("open_redirect", host="app.target.com", path="/out", param="url",
                      confirmed=True, oracle="302", attrs={"host": "app.target.com"})
        m.reflect()
        ws = m.rehydrate()
        self.assertTrue(any(h["goal"] == "token_theft" for h in ws["hypotheses"]))
        # complete the chain -> hypothesis for token_theft resolves
        m.add_finding("oauth_redirect", host="app.target.com", path="/oauth/authorize",
                      param="redirect_uri", confirmed=True, oracle="code",
                      attrs={"allow": "*.target.com"})
        m.reflect()
        ws2 = m.rehydrate()
        self.assertFalse(any(h["goal"] == "token_theft" for h in ws2["hypotheses"]))
        m.close()


class TestPortraits(_Base):
    def test_portrait_built_and_rehydrated(self):
        m = self.mk()
        m.add_finding("xss", host="shop.example.com", path="/s", param="q",
                      confirmed=True, oracle="reflected")
        m.reflect()
        ws = m.rehydrate()
        self.assertIn("shop.example.com", ws["portraits"])
        self.assertIn("xss", ws["portraits"]["shop.example.com"])
        m.close()


class TestEmbeddings(_Base):
    def test_semantic_recall(self):
        m = self.mk(embeddings=True)
        m.add_finding("xss", host="h", path="/s", param="q", confirmed=True,
                      oracle="x", attrs={"name": "reflected cross site scripting"})
        m.add_finding("sqli", host="h", path="/d", param="id", confirmed=True,
                      oracle="y", attrs={"name": "sql injection union select"})
        hits = m.recall(query="cross-site scripting reflected", limit=5)
        self.assertTrue(hits)
        # the XSS node should rank above the SQLi node for this query
        labels = [h["attrs"].get("name", "") for h in hits]
        self.assertIn("reflected cross site scripting", labels)
        self.assertLess(labels.index("reflected cross site scripting"),
                        labels.index("sql injection union select")
                        if "sql injection union select" in labels else 99)
        m.close()

    def test_same_as_edges_on_reflect(self):
        m = self.mk(embeddings=True)
        # two near-identical findings on different hosts -> advisory SAME_AS
        for host in ("a.example.com", "b.example.com"):
            m.add_finding("xss", host=host, path="/search", param="q", confirmed=True,
                          oracle="x", attrs={"name": "reflected xss in search box"})
        res = m.reflect()
        self.assertGreaterEqual(res["synonyms"], 1)
        m.close()


class TestIncrementalDetection(_Base):
    def test_chain_forms_across_separate_writes(self):
        m = self.mk(profile=CODEREVIEW)
        _o = {"confirmed": True, "oracle": "reviewed"}
        m.add_taint_source("h.py", var="name", line=1, **_o)
        self.assertEqual(m.chains(), [])                 # no sink yet; edges built
        m.add_taint_prop("h.py", var_in="name", var_out="q", line=2, **_o)
        self.assertEqual(m.chains(), [])
        m.add_taint_sink("db.py", var="q", sink_type="sql", line=9, **_o)
        # the incremental edge rebuild must connect the newly-added sink
        self.assertIn("full_db_read", {c["goal"] for c in m.chains()})
        m.close()


if __name__ == "__main__":
    unittest.main()
