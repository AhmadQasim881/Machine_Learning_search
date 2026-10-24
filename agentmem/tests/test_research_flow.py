"""Core design regression tests: scoped value identities + explicit flow edges
replace variable-name chain matching, and sanitizers/guards are explicit and
path-specific. Stdlib unittest.

These encode the acceptance rule: a code chain exists ONLY along explicit,
revision-compatible flow edges — never because two values share a name."""
import os
import tempfile
import unittest

from agentmem import ResearchMemory


class _R(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.m = ResearchMemory(os.path.join(self.dir.name, "r.db"))
        self.snap = self.m.register_snapshot("firefox", "a" * 40, scope="netwerk")

    def tearDown(self):
        self.m.close(); self.dir.cleanup()

    def _src(self, path, fn, var, line=1, **kw):
        return self.m.add_value_identity(self.snap, path, var, role="source",
                                         symbol_id=fn, start_line=line, **kw)

    def _sink(self, path, fn, var, sink_type, line=9, **kw):
        return self.m.add_value_identity(self.snap, path, var, role="sink", symbol_id=fn,
                                         start_line=line, sink_type=sink_type, **kw)


class TestNoNameBasedChaining(_R):
    def test_same_name_in_unrelated_functions_do_not_chain(self):
        # `data` is a source in get_user and a sink arg in exec_cmd — SAME file,
        # SAME name, DIFFERENT functions, NO explicit flow edge between them.
        self._src("net/http.cpp", "mozilla::net::GetUser", "data", line=10)
        self._sink("net/http.cpp", "mozilla::net::ExecCmd", "data", "command", line=50)
        self.assertEqual(self.m.chains(self.snap), [],
                         "same variable name in unrelated functions must not form a chain")

    def test_same_name_in_unrelated_files_do_not_chain(self):
        self._src("a/parser.cpp", "ParseA", "buf", line=5)
        self._sink("b/writer.cpp", "WriteB", "buf", "file_write", line=7)
        self.assertEqual(self.m.chains(self.snap), [])

    def test_case_distinct_paths_are_distinct_identities(self):
        v1 = self._src("dom/Foo.cpp", "Foo::read", "x", line=3)
        v2 = self._sink("dom/foo.cpp", "foo::sink", "x", "sql", line=4)
        self.assertNotEqual(v1, v2)                              # case-sensitive paths
        self.assertEqual(self.m.chains(self.snap), [])           # and no implicit chain


class TestExplicitFlowChains(_R):
    def test_explicit_verified_flow_connects_across_functions(self):
        src = self._src("net/http.cpp", "ReadRequest", "raw", line=10)
        dst = self._sink("sql/db.cpp", "Query::exec", "stmt", "sql", line=40)
        self.m.add_flow_edge(self.snap, src, dst, kind="interprocedural",
                             status="demonstrated", trust="tool_verified",
                             caller_symbol="ReadRequest", callee_symbol="Query::exec",
                             arg_index=0, param_name="stmt")
        chains = self.m.chains(self.snap)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["goal"], "full_db_read")
        self.assertEqual(chains[0]["status"], "demonstrated")

    def test_chain_status_cannot_exceed_weakest_transition(self):
        a = self._src("f.cpp", "A", "p0", line=1)
        b = self.m.add_value_identity(self.snap, "f.cpp", "p1", role="transform",
                                      symbol_id="B", start_line=2)
        c = self._sink("f.cpp", "C", "p2", "exec", line=3)
        self.m.add_flow_edge(self.snap, a, b, status="demonstrated", trust="tool_verified")
        self.m.add_flow_edge(self.snap, b, c, status="hypothesis")   # weakest link
        chains = self.m.chains(self.snap)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["status"], "hypothesis")          # not 'demonstrated'
        self.assertEqual(chains[0]["impact_state"], "unproven")

    def test_untrusted_cannot_assert_demonstrated(self):
        a = self._src("f.cpp", "A", "p0")
        b = self._sink("f.cpp", "C", "p0b", "exec")
        # agent assertion (not strong trust) requesting 'demonstrated' is downgraded
        self.m.add_flow_edge(self.snap, a, b, status="demonstrated", trust="target_derived")
        self.assertEqual(self.m.chains(self.snap)[0]["status"], "supported")


class TestGuards(_R):
    def _two_step(self):
        src = self._src("f.cpp", "In", "raw", line=1)
        sink = self._sink("f.cpp", "Sink", "raw2", "command", line=9)
        eid = self.m.add_flow_edge(self.snap, src, sink, status="demonstrated",
                                   trust="tool_verified")
        return src, sink, eid

    def test_sanitizer_blocks_the_exact_path_it_covers(self):
        _, _, eid = self._two_step()
        self.assertEqual(self.m.chains(self.snap)[0]["status"], "demonstrated")
        self.m.add_guard(self.snap, flow_edge_id=eid, guard_symbol="NS_Escape",
                         kind="sanitizer", condition="escapes shell metachars")
        ch = self.m.chains(self.snap)[0]
        self.assertEqual(ch["status"], "blocked")
        self.assertTrue(ch["steps"][0]["guard_blocked"])

    def test_bypass_evidence_unblocks_the_guard(self):
        _, _, eid = self._two_step()
        self.m.add_guard(self.snap, flow_edge_id=eid, guard_symbol="NS_Escape", status="active")
        self.assertEqual(self.m.chains(self.snap)[0]["status"], "blocked")
        # separate evidence that the sanitizer is bypassable restores the flow
        self.m.add_guard(self.snap, flow_edge_id=eid, guard_symbol="NS_Escape",
                         status="bypassed", condition="incomplete metachar set")
        self.assertEqual(self.m.chains(self.snap)[0]["status"], "demonstrated")

    def test_guard_on_one_path_does_not_block_an_independent_path(self):
        # path 1: a1 -> s1 (guarded);  path 2: a2 -> s2 (independent, unguarded)
        a1 = self._src("f.cpp", "In1", "r1", line=1)
        s1 = self._sink("f.cpp", "Sink1", "r1b", "command", line=9)
        e1 = self.m.add_flow_edge(self.snap, a1, s1, status="demonstrated", trust="tool_verified")
        a2 = self._src("g.cpp", "In2", "r2", line=1)
        s2 = self._sink("g.cpp", "Sink2", "r2b", "exec", line=9)
        self.m.add_flow_edge(self.snap, a2, s2, status="demonstrated", trust="tool_verified")
        self.m.add_guard(self.snap, flow_edge_id=e1, guard_symbol="Escape")
        by_goal = {c["goal"]: c for c in self.m.chains(self.snap)}
        # both reach rce (command, exec); check the guarded path is blocked and the
        # independent one is still demonstrated by inspecting each chain's steps
        statuses = sorted(c["status"] for c in self.m.chains(self.snap))
        self.assertEqual(statuses, ["blocked", "demonstrated"])


class TestRevisionIntegrity(_R):
    def test_flow_edge_cannot_cross_snapshots(self):
        other = self.m.register_snapshot("firefox", "b" * 40, scope="netwerk")
        a = self._src("f.cpp", "A", "x")
        b = self.m.add_value_identity(other, "f.cpp", "y", role="sink", symbol_id="B",
                                      sink_type="sql")
        with self.assertRaises(ValueError):
            self.m.add_flow_edge(self.snap, a, b, status="supported")

    def test_flow_edge_rejects_nonexistent_identity(self):
        a = self._src("f.cpp", "A", "x")
        with self.assertRaises(ValueError):
            self.m.add_flow_edge(self.snap, a, 999999, status="supported")


if __name__ == "__main__":
    unittest.main()
