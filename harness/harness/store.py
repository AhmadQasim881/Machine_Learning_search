"""
harness.store — the one findings datastore (SQLite).

A single table holds the full finding as a JSON blob, with a handful of columns
promoted out for indexing/querying (status, host, severity, dedup_key, cluster).
This keeps the schema flexible (the record can grow) while still allowing cheap
filters and exact-duplicate detection.

Stdlib only (sqlite3 + json). For a real deployment you would likely adopt a
mature vuln-management backend instead of this table — see README "Build vs
adopt". The interface here is deliberately small so it can be swapped.
"""
from __future__ import annotations

import hashlib
import sqlite3
from typing import Iterable, Iterator, Optional
from urllib.parse import urlparse

from .schema import Finding, Status


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    status       TEXT NOT NULL,
    host         TEXT,
    url          TEXT,
    severity     TEXT,
    dedup_key    TEXT,
    cluster_id   TEXT,
    confidence   REAL,
    priority     REAL,
    updated_at   TEXT,
    data         TEXT NOT NULL      -- full Finding.to_json()
);
CREATE INDEX IF NOT EXISTS idx_findings_status    ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_host      ON findings(host);
CREATE INDEX IF NOT EXISTS idx_findings_dedup     ON findings(dedup_key);
CREATE INDEX IF NOT EXISTS idx_findings_cluster   ON findings(cluster_id);
"""


def dedup_key(f: Finding) -> str:
    """Cheap EXACT-duplicate key: same tool-signature at same location+param.

    This is only the first line of defence — it collapses the identical finding
    reported twice. Near-duplicate collapsing across wording/host variants is
    Stage 4 (embed + cluster), which this scaffold leaves as a stub.
    """
    # include the URL path (not the query string) so distinct endpoints on one
    # host are not collapsed together when the tool doesn't populate `param`.
    path = ""
    if f.url:
        try:
            path = urlparse(f.url if "://" in f.url else f"//{f.url}").path or ""
        except ValueError:
            path = ""
    basis = "|".join([
        (f.source_tool or "").lower(),
        (f.vuln_type or f.title or "").lower().strip(),
        (f.host or "").lower(),
        str(f.port or ""),
        path.lower(),
        (f.param or "").lower(),
    ])
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


class Store:
    def __init__(self, path: str = "harness.db"):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- writes ---------------------------------------------------------- #
    def upsert(self, f: Finding) -> None:
        if not f.dedup_key:
            f.dedup_key = dedup_key(f)
        f.touch()
        self.conn.execute(
            """INSERT INTO findings
               (id,status,host,url,severity,dedup_key,cluster_id,confidence,priority,updated_at,data)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 status=excluded.status, host=excluded.host, url=excluded.url,
                 severity=excluded.severity, dedup_key=excluded.dedup_key,
                 cluster_id=excluded.cluster_id, confidence=excluded.confidence,
                 priority=excluded.priority, updated_at=excluded.updated_at,
                 data=excluded.data""",
            (f.id, f.status.value, f.host, f.url, f.severity, f.dedup_key,
             f.cluster_id, f.confidence, f.priority_score, f.updated_at, f.to_json()),
        )
        self.conn.commit()

    def add_deduped(self, f: Finding) -> tuple[Finding, bool]:
        """Insert, but if an exact duplicate already exists, mark this one
        DUPLICATE and point its cluster at the original. Returns (stored, is_new)."""
        f.dedup_key = dedup_key(f)
        existing = self.find_by_dedup(f.dedup_key)
        if existing and existing.id != f.id:
            f.status = Status.DUPLICATE
            f.cluster_id = existing.cluster_id or existing.id
            self.upsert(f)
            return f, False
        if not f.cluster_id:
            f.cluster_id = f.id
        self.upsert(f)
        return f, True

    # ---- reads ----------------------------------------------------------- #
    def get(self, finding_id: str) -> Optional[Finding]:
        row = self.conn.execute(
            "SELECT data FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        return Finding.from_json(row["data"]) if row else None

    def find_by_dedup(self, key: str) -> Optional[Finding]:
        row = self.conn.execute(
            "SELECT data FROM findings WHERE dedup_key=? AND status != ? "
            "ORDER BY updated_at LIMIT 1",
            (key, Status.DUPLICATE.value),
        ).fetchone()
        return Finding.from_json(row["data"]) if row else None

    def iter_findings(self, status: Optional[Status] = None) -> Iterator[Finding]:
        if status:
            cur = self.conn.execute(
                "SELECT data FROM findings WHERE status=? ORDER BY updated_at",
                (status.value,),
            )
        else:
            cur = self.conn.execute("SELECT data FROM findings ORDER BY updated_at")
        for row in cur:
            yield Finding.from_json(row["data"])

    def count_by_status(self) -> dict[str, int]:
        cur = self.conn.execute(
            "SELECT status, COUNT(*) n FROM findings GROUP BY status"
        )
        return {row["status"]: row["n"] for row in cur}

    def bulk_upsert(self, findings: Iterable[Finding]) -> int:
        n = 0
        for f in findings:
            self.upsert(f)
            n += 1
        return n
