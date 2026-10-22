"""Proves the engine is domain-agnostic: the CODEREVIEW profile finds taint-flow
chains (source -> propagator -> sink) on the SAME store/chains/capability engine
that powers the web profile. Stdlib unittest."""
import os
import tempfile
import unittest

from agentmem import Memory
from agentmem.profiles import CODEREVIEW, WEB


class _CR(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.m = Memory(os.path.join(self.dir.name, "cr.db"), profile=CODEREVIEW)

    def tearDown(self):
        self.m.close(); self.dir.cleanup()

    def _goals(self):
        return {c["goal"] for c in self.m.chains()}


class TestTaintChains(_CR):
    def test_sql_injection_dataflow(self):
        self.m.add_taint_source("h.py", var="name", line=1)
        self.m.add_taint_prop("h.py", var_in="name", var_out="q", line=2)
        self.m.add_taint_sink("db.py", var="q", sink_type="sql", line=9)
        self.assertIn("full_db_read", self._goals())

    def test_rce_dataflow(self):
        self.m.add_taint_source("h.py", var="cmd", line=1)
        self.m.add_taint_sink("os.py", var="cmd", sink_type="exec", line=3)  # direct source->sink
        self.assertIn("rce", self._goals())

    def test_no_chain_when_var_not_connected(self):
        # taint flows into `a`, but the sink reads `b` (never tainted) -> no chain
        self.m.add_taint_source("h.py", var="a", line=1)
        self.m.add_taint_sink("db.py", var="b", sink_type="sql", line=9)
        self.assertEqual(self._goals(), set())

    def test_sanitizer_breaks_chain(self):
        # a propagator that outputs a DIFFERENT, clean var (sanitized) does not
        # carry taint to the sink
        self.m.add_taint_source("h.py", var="raw", line=1)
        self.m.add_taint_prop("h.py", var_in="raw", var_out="clean_but_unused", line=2)
        self.m.add_taint_sink("db.py", var="raw_rendered", sink_type="sql", line=9)
        self.assertEqual(self._goals(), set())

    def test_narrative_uses_code_labels(self):
        self.m.add_taint_source("app/views.py", var="x", symbol="request.GET", line=5)
        self.m.add_taint_sink("app/db.py", var="x", sink_type="sql", symbol="execute", line=7)
        narr = self.m.chains()[0]["narrative"]
        self.assertIn("app/views.py", narr)
        self.assertIn("FULL_DB_READ", narr)


class TestEngineSharedWithWeb(unittest.TestCase):
    def test_default_profile_is_web_and_unaffected(self):
        with tempfile.TemporaryDirectory() as d:
            m = Memory(os.path.join(d, "w.db"))   # no profile -> web
            self.assertIs(m.profile, WEB)
            m.add_finding("open_redirect", host="app.target.com", path="/out", param="url",
                          confirmed=True, oracle="302", attrs={"host": "app.target.com"})
            m.add_finding("oauth_redirect", host="app.target.com", path="/oauth/authorize",
                          param="redirect_uri", confirmed=True, oracle="code",
                          attrs={"allow": "*.target.com"})
            self.assertIn("token_theft", {c["goal"] for c in m.chains()})
            m.close()

    def test_persistence_with_codereview_profile(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cr.db")
            m = Memory(path, profile=CODEREVIEW)
            m.add_taint_source("h.py", var="name", line=1)
            m.add_taint_sink("db.py", var="name", sink_type="sql", line=9)
            self.assertIn("full_db_read", {c["goal"] for c in m.chains()})
            m.close()
            m2 = Memory(path, profile=CODEREVIEW)
            self.assertIn("full_db_read", {c["goal"] for c in m2.chains()})
            m2.close()


if __name__ == "__main__":
    unittest.main()
