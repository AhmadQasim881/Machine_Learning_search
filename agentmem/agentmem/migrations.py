"""
agentmem.migrations — schema versioning and safe forward migrations.

The base `schema.sql` (v1: web + first-generation code-review tables) is applied
on every open with `CREATE ... IF NOT EXISTS`. On top of that, `migrate()` brings
a database up to `CURRENT_SCHEMA_VERSION` by applying ordered, additive forward
steps and recording the version in `kv_meta`.

Guarantees:
  * Migrations are **additive** — they create new tables/indexes and never drop or
    rewrite v1 data, so an existing database migrates without data loss.
  * A database whose recorded version is **newer** than this library supports is
    refused with a clear backup/upgrade instruction (never silently downgraded).

To add a future migration: bump CURRENT_SCHEMA_VERSION, add a `_migrate_to_N`
function, and register it in `_STEPS`.
"""
from __future__ import annotations

import os
import sqlite3

CURRENT_SCHEMA_VERSION = 2

_RESEARCH_SQL = os.path.join(os.path.dirname(__file__), "schema_research.sql")

# kv_meta keys written by migrations
_K_VERSION = "schema_version"
_K_FTS = "fts5_enabled"


def get_version(conn: sqlite3.Connection) -> int:
    """The database's recorded schema version. A database that predates versioning
    (has the v1 tables but no recorded version) is treated as v1."""
    row = conn.execute("SELECT value FROM kv_meta WHERE key=?", (_K_VERSION,)).fetchone()
    if row is not None:
        return int(row[0] if not isinstance(row, sqlite3.Row) else row["value"])
    return 1


def _set_version(conn: sqlite3.Connection, v: int) -> None:
    conn.execute(
        "INSERT INTO kv_meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (_K_VERSION, str(v)))


def fts5_available(conn: sqlite3.Connection) -> bool:
    """True if this SQLite build has the FTS5 extension (used for text search)."""
    try:
        conn.execute("CREATE VIRTUAL TABLE temp._agentmem_fts_probe USING fts5(x)")
        conn.execute("DROP TABLE temp._agentmem_fts_probe")
        return True
    except sqlite3.Error:
        return False


def fts5_enabled(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT value FROM kv_meta WHERE key=?", (_K_FTS,)).fetchone()
    return bool(row) and str(row[0] if not isinstance(row, sqlite3.Row) else row["value"]) == "1"


def migrate(conn: sqlite3.Connection) -> int:
    """Bring `conn` up to CURRENT_SCHEMA_VERSION. Returns the resulting version.
    Raises RuntimeError if the database is newer than this library supports."""
    v = get_version(conn)
    if v > CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            f"agentmem: database schema version {v} is newer than this library "
            f"supports (max {CURRENT_SCHEMA_VERSION}). Back up the database file "
            f"and upgrade agentmem, or open it with a matching agentmem version. "
            f"Refusing to open it to avoid data loss.")
    for target in range(v + 1, CURRENT_SCHEMA_VERSION + 1):
        _STEPS[target](conn)
        _set_version(conn, target)
    conn.commit()
    return CURRENT_SCHEMA_VERSION


def _migrate_to_2(conn: sqlite3.Connection) -> None:
    """v1 -> v2: add the revision-aware research-evidence tables (additive)."""
    with open(_RESEARCH_SQL, encoding="utf-8") as fh:
        conn.executescript(fh.read())
    # Optional FTS5 text index over evidence projections. Created only when the
    # SQLite build supports it; retrieval degrades to a documented LIKE fallback
    # otherwise (recorded so the retrieval layer can report capability honestly).
    has_fts = fts5_available(conn)
    if has_fts:
        conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5("
            "text, evidence_id UNINDEXED, snapshot_id UNINDEXED, kind UNINDEXED)")
    conn.execute(
        "INSERT INTO kv_meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (_K_FTS, "1" if has_fts else "0"))


_STEPS = {
    2: _migrate_to_2,
}
