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
        # the first-generation helpers no longer auto-confirm from a generic oracle,
        # so a multi-step chain must be built from reviewed (confirmed) facts
        self.m.add_taint_source("h.py", var="name", line=1, confirmed=True, oracle="reviewed")
        self.m.add_taint_prop("h.py", var_in="name", var_out="q", line=2, confirmed=True, oracle="reviewed")
        self.m.add_taint_sink("db.py", var="q", sink_type="sql", line=9, confirmed=True, oracle="reviewed")
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


class TestExtendedSinkGoals(_CR):
    def test_sink_types_map_to_expected_goals(self):
        cases = {
            "exec": "rce", "eval": "rce", "deserialize": "rce", "template": "rce",
            "pickle": "rce", "command": "rce",
            "sql": "full_db_read", "nosql": "full_db_read",
            "path": "file_read", "file_write": "file_write", "xxe": "file_read",
            "ssrf": "ssrf_exec", "open_redirect": "open_redirect", "xss": "xss_exec",
            "ldap": "injection", "format_string": "memory_corruption",
            "buffer": "memory_corruption", "crypto": "weak_crypto", "auth": "auth_bypass",
        }
        for i, st in enumerate(cases):                      # each pair chains on its own var
            v = f"v{i}"
            self.m.add_taint_source("src.py", var=v, line=i)
            self.m.add_taint_sink("sink.py", var=v, sink_type=st, line=100 + i)
        goals = self._goals()
        for st, goal in cases.items():
            self.assertIn(goal, goals, f"{st} should yield {goal}")

    def test_unknown_sink_type_falls_back_to_injection(self):
        self.m.add_taint_source("s.py", var="x", line=1)
        self.m.add_taint_sink("k.py", var="x", sink_type="totally_unknown", line=2)
        self.assertIn("injection", self._goals())


class TestInterproceduralChain(_CR):
    def test_multi_hop_flow_across_files(self):
        # untrusted -> helper -> formatter -> shell, three propagators across 4 files
        _o = {"confirmed": True, "oracle": "reviewed"}
        self.m.add_taint_source("api/handler.py", var="p0", symbol="handle", line=10, **_o)
        self.m.add_taint_prop("api/handler.py", var_in="p0", var_out="p1", symbol="handle", line=11, **_o)
        self.m.add_taint_prop("lib/util.py", var_in="p1", var_out="p2", symbol="build", line=5, **_o)
        self.m.add_taint_prop("lib/fmt.py", var_in="p2", var_out="p3", symbol="fmt", line=8, **_o)
        self.m.add_taint_sink("lib/sh.py", var="p3", sink_type="command", symbol="popen", line=3, **_o)
        rce = [c for c in self.m.chains() if c["goal"] == "rce"]
        self.assertTrue(rce, "a cross-file command-injection chain should be found")
        self.assertEqual(len(rce[0]["steps"]), 5)           # source + 3 props + sink


class TestExplicitSanitizer(_CR):
    def test_add_taint_sanitizer_is_inert(self):
        # an explicit sanitizer node provides/requires nothing -> no chain, no crash
        self.m.add_taint_source("h.py", var="x", line=1)
        self.m.add_taint_sanitizer("h.py", var="x", symbol="escape", line=2)
        self.m.add_taint_sink("db.py", var="y", sink_type="sql", line=3)   # y never tainted
        self.assertEqual(self._goals(), set())

    def test_sanitizer_is_not_a_chain_step(self):
        self.m.add_taint_source("h.py", var="x", line=1)
        self.m.add_taint_sink("db.py", var="x", sink_type="sql", line=3)
        sid = self.m.add_taint_sanitizer("h.py", var="x", symbol="escape", line=2)
        steps = {s["node_id"] for c in self.m.chains() for s in c["steps"]}
        self.assertNotIn(sid, steps)


class TestTaintProbes(_CR):
    def test_dangling_sink_probes_backward(self):
        self.m.add_taint_sink("w/run.py", var="cmd", sink_type="exec", line=7)
        probes = self.m.next_probes()
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0]["goal"], "rce")
        self.assertIn("DANGLING SINK", probes[0]["suggestion"])

    def test_dangling_source_probes_forward(self):
        self.m.add_taint_source("a/login.py", var="token", line=3)
        probes = self.m.next_probes()
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0]["goal"], "trace_forward")

    def test_complete_chain_yields_no_probes(self):
        self.m.add_taint_source("h.py", var="name", line=1)
        self.m.add_taint_prop("h.py", var_in="name", var_out="q", line=2)
        self.m.add_taint_sink("db.py", var="q", sink_type="sql", line=9)
        self.assertEqual(self.m.next_probes(), [])

    def test_probes_rank_dangerous_sink_first(self):
        self.m.add_taint_source("a.py", var="s", line=1)                   # dangling source (sev 5)
        self.m.add_taint_sink("b.py", var="k", sink_type="exec", line=2)   # dangling sink  (sev 10)
        self.assertEqual(self.m.next_probes()[0]["goal"], "rce")           # highest severity first


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
