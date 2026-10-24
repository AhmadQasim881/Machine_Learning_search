"""
Reproducible retrieval benchmark for agentmem's research-evidence store.

Measures, at several store sizes, the wall-clock latency and the NUMBER OF SQL
STATEMENTS issued for a bounded (limit=20) evidence query, comparing:

  * baseline  — the naive pattern the old retrieval used: select all matching ids,
                then fetch each row individually (N+1), then sort and cut in Python.
  * sql_side  — ResearchMemory.search_evidence: one SQL statement does the filter,
                ranking and pagination.

Run:
    python benchmarks/bench_retrieval.py                # 1000, 10000, 50000
    python benchmarks/bench_retrieval.py 2000 20000     # custom sizes

Numbers are MEASURED on your machine and printed; nothing is hard-coded. The point
the benchmark demonstrates: a bounded query must not issue a statement count
proportional to the number of stored records.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile  # noqa: E402

from agentmem import ResearchMemory  # noqa: E402


class _Counter:
    """Counts SQL statements executed on a connection via the trace callback."""
    def __init__(self, conn):
        self.conn, self.n = conn, 0

    def __enter__(self):
        self.n = 0
        self.conn.set_trace_callback(lambda _stmt: self._tick())
        return self

    def _tick(self):
        self.n += 1

    def __exit__(self, *exc):
        self.conn.set_trace_callback(None)


def _seed(m: ResearchMemory, snap: int, n: int) -> None:
    conn = m.conn
    now = time.time()
    with m.store.transaction():
        for i in range(n):
            conn.execute(
                "INSERT INTO evidence(snapshot_id,kind,projection,projection_truncated,"
                "status,trust,version,valid_from,valid_to,created_ts,meta_json) "
                "VALUES(?,?,?,0,?,?,1,?,NULL,?,'{}')",
                (snap, "static_analysis",
                 f"codeql finding {i}: tainted length used in memcpy call site {i}",
                 "observed" if i % 3 else "supported", "tool_verified", now, now + i))


def _baseline_scan(m: ResearchMemory, snap: int, limit: int = 20) -> int:
    """Old-style N+1: all matching ids, then one SELECT per row, sort, cut."""
    ids = [r["id"] for r in m.conn.execute(
        "SELECT id FROM evidence WHERE snapshot_id=? AND valid_to IS NULL", (snap,)).fetchall()]
    rows = []
    for nid in ids:                                   # N+1 lookups
        rows.append(m.conn.execute("SELECT * FROM evidence WHERE id=?", (nid,)).fetchone())
    rows.sort(key=lambda r: r["created_ts"], reverse=True)
    return len(rows[:limit])


def main() -> None:
    sizes = [int(x) for x in sys.argv[1:]] or [1000, 10000, 50000]
    d = tempfile.mkdtemp(prefix="agentmem-bench-")
    print(f"python {sys.version.split()[0]}  db dir {d}")
    print(f"{'N':>8} | {'baseline stmts':>14} {'baseline ms':>12} | "
          f"{'sql_side stmts':>14} {'sql_side ms':>12} | backend")
    print("-" * 92)
    for n in sizes:
        m = ResearchMemory(os.path.join(d, f"bench_{n}.db"))
        snap = m.register_snapshot("firefox", "c0ffee" + str(n), scope="bench")
        _seed(m, snap, n)

        with _Counter(m.conn) as c:
            t0 = time.perf_counter()
            _baseline_scan(m, snap, limit=20)
            base_ms = (time.perf_counter() - t0) * 1000
            base_stmts = c.n

        with _Counter(m.conn) as c:
            t0 = time.perf_counter()
            m.search_evidence(snapshot_id=snap, text="memcpy", status="observed", limit=20)
            sql_ms = (time.perf_counter() - t0) * 1000
            sql_stmts = c.n

        print(f"{n:>8} | {base_stmts:>14} {base_ms:>12.2f} | "
              f"{sql_stmts:>14} {sql_ms:>12.2f} | {m.text_search_backend()}")
        m.close()
    print("\nsql_side statement count is independent of N (bounded); baseline grows ~N.")


if __name__ == "__main__":
    main()
