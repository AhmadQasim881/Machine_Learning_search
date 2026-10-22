#!/usr/bin/env python3
"""
agentmem code-review demo — the SAME engine, a different domain.

Drives agentmem with the CODEREVIEW profile instead of web: a taint-flow path
(source -> propagator -> sink) is detected as a capability chain, exactly like a
web exploit chain, with no change to the store / graph / chain engine.

    python examples/codereview_demo.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agentmem import Memory                      # noqa: E402
from agentmem.profiles import CODEREVIEW         # noqa: E402


def main() -> int:
    db = os.path.join(tempfile.mkdtemp(), "cr.db")
    m = Memory(db, profile=CODEREVIEW)

    # a user-controlled value flows across files into a SQL execution
    m.add_taint_source("handlers/user.py", var="name", symbol="request.args['name']", line=12)
    m.add_taint_prop("handlers/user.py", var_in="name", var_out="query",
                     symbol='query = f"SELECT ... {name}"', line=15)
    m.add_taint_sink("db/exec.py", var="query", sink_type="sql",
                     symbol="cursor.execute(query)", line=40)

    # a second, independent flow into an os.system call -> RCE
    m.add_taint_source("jobs/run.py", var="opts", symbol="payload['opts']", line=3)
    m.add_taint_sink("jobs/run.py", var="opts", sink_type="exec",
                     symbol="os.system(opts)", line=8)

    print("=== taint-flow chains (same engine, code-review profile) ===\n")
    for c in m.chains():
        print(f"  [severity {c['severity']}]  {c['goal'].upper()}  ({c['status']})")
        print(f"      {c['narrative']}\n")

    print("stats:", m.stats()["nodes_by_type"])
    m.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
