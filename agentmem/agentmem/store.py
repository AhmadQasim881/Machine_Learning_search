"""
agentmem.store — the SQLite backbone (spec §5).

Owns the connection (WAL), the schema, the monotonic campaign-step clock, and
low-level CRUD for nodes, edges, capability tokens, observations, payloads,
lessons, summaries, chains, secrets, and the persisted working set. Higher layers
(write/retrieve/chains/reflect) are built on these primitives. Stdlib only.

Ground-truth rule: observations/payloads are append-only; nodes are upserted and
soft-invalidated (status), never hard-deleted.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterable, Optional

from . import capabilities as caps
from . import config
from . import migrations
from .artifacts import ArtifactStore

# status reconciliation ranks (invalidated is special — see upsert_node)
_STATUS_RANK = {"invalidated": 0, "suspected": 1, "confirmed": 2}

_SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")


def _artifact_root(db_path: str) -> str:
    """Where the content-addressed artifact store lives for a given database.
    Beside the DB file (``<db>.artifacts/``); an in-memory DB gets a temp dir."""
    if db_path in (":memory:", "") or db_path.startswith("file::memory:"):
        import tempfile
        return tempfile.mkdtemp(prefix="agentmem-artifacts-")
    return os.path.abspath(db_path) + ".artifacts"


class Store:
    def __init__(self, path: str = "campaign.db", check_same_thread: bool = True):
        self.path = path
        self._tx_depth = 0          # active transaction()/savepoint nesting depth
        self._sp_counter = 0        # monotonic savepoint-name source
        self._dirty = True          # chains need (re)detection (lazy, see memory.chains)
        self._new_cap_nodes: set = set()   # capability nodes changed since last edge rebuild
        self._edges_initialized = False    # first detect does a full ENABLES rebuild
        # check_same_thread=False lets a long-lived connection be driven from a
        # thread pool (e.g. the MCP server's sync-tool offload); callers that do
        # this MUST serialize access themselves (the MCP server holds a lock).
        #
        # isolation_level=None => autocommit: a statement outside an explicit
        # transaction() is immediately durable (matching the old per-write commit),
        # while transaction() owns BEGIN/COMMIT/ROLLBACK + SAVEPOINTs so a failing
        # scope ROLLS BACK instead of committing a partial evidence graph.
        self.conn = sqlite3.connect(path, check_same_thread=check_same_thread,
                                    isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")   # WAL-safe, far fewer fsyncs
        self.conn.execute("PRAGMA foreign_keys=ON")
        with open(_SCHEMA, encoding="utf-8") as fh:
            self.conn.executescript(fh.read())
        if self._meta("step") is None:
            self._set_meta("step", "0")
        migrations.migrate(self.conn)       # additive forward migrations + schema_version
        self.artifacts = ArtifactStore(_artifact_root(path))

    def close(self) -> None:
        self.conn.close()

    # ---- commit control / batching -------------------------------------- #
    def _commit(self) -> None:
        """No-op in autocommit mode (isolation_level=None): statements outside a
        transaction() are already durable, and committing here mid-transaction
        would end a transaction()/SAVEPOINT scope early. transaction() owns
        COMMIT/ROLLBACK. Kept as a method so existing call sites are unaffected."""
        return

    @contextmanager
    def transaction(self):
        """A real, nested, rolling-back transaction scope.

        The outer scope runs BEGIN and then COMMITs on success or ROLLBACKs on any
        exception (the previous implementation committed in `finally`, persisting a
        partial graph even when the body raised — the bug this fixes). Inner scopes
        use SAVEPOINTs so a nested failure rolls back only its own work and
        re-raises, while the outer scope can still decide to commit or roll back.
        Also batches writes into one fsync."""
        outer = self._tx_depth == 0
        sp = None
        if outer:
            self.conn.execute("BEGIN")
        else:
            sp = f"am_sp_{self._sp_counter}"
            self._sp_counter += 1
            self.conn.execute(f"SAVEPOINT {sp}")
        self._tx_depth += 1
        try:
            yield self
        except BaseException:
            if outer:
                self.conn.execute("ROLLBACK")
            else:
                self.conn.execute(f"ROLLBACK TO {sp}")
                self.conn.execute(f"RELEASE {sp}")
            raise
        else:
            if outer:
                self.conn.execute("COMMIT")
            else:
                self.conn.execute(f"RELEASE {sp}")
        finally:
            self._tx_depth -= 1

    # ---- chain-detection dirty flag (lazy detection; see memory.chains) --- #
    def mark_dirty(self) -> None:
        self._dirty = True

    def take_dirty(self) -> bool:
        d = self._dirty
        self._dirty = False
        return d

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- campaign clock -------------------------------------------------- #
    def _meta(self, key: str) -> Optional[str]:
        r = self.conn.execute("SELECT value FROM kv_meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def _set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO kv_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    @property
    def step(self) -> int:
        return int(self._meta("step") or 0)

    def tick(self) -> int:
        s = self.step + 1
        self._set_meta("step", str(s))
        self._commit()
        return s

    # ---- nodes ----------------------------------------------------------- #
    def upsert_node(self, type: str, canonical_key: str, attrs: Optional[dict] = None,
                    importance: int = 5, confidence: float = 0.5,
                    trust: str = "agent_asserted", status: str = "suspected",
                    pinned: bool = False, allow_revive: bool = False) -> int:
        """Insert or merge a node by (type, canonical_key). On conflict, attrs are
        shallow-merged, importance/confidence raised monotonically, and — the fix —
        STATUS and TRUST are reconciled upward too: a later confirmed observation
        promotes a stored 'suspected' node, and trust rises to the stronger source.
        An 'invalidated' node stays invalidated unless allow_revive AND the new
        status is 'confirmed' (a re-observation that fired an oracle)."""
        now = time.time()
        step = self.step
        existing = self.find_node(type, canonical_key)
        if existing is None:
            cur = self.conn.execute(
                "INSERT INTO nodes(type,canonical_key,attrs_json,importance,confidence,"
                "trust,status,pinned,created_step,created_ts,last_access_step) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (type, canonical_key, json.dumps(attrs or {}), importance, confidence,
                 trust, status, int(pinned), step, now, step))
            self._commit()
            return cur.lastrowid
        nid = existing["id"]
        merged = {**json.loads(existing["attrs_json"] or "{}"), **(attrs or {})}

        # status reconciliation (monotonic promotion; invalidated is sticky)
        old_status = existing["status"]
        if old_status == "invalidated" and not (allow_revive and status == "confirmed"):
            new_status = "invalidated"
        elif _STATUS_RANK.get(status, 1) > _STATUS_RANK.get(old_status, 1):
            new_status = status
        else:
            new_status = old_status

        # trust rises to the stronger source
        old_trust = existing["trust"]
        new_trust = trust if config.TRUST_RANK.get(trust, 0) > config.TRUST_RANK.get(old_trust, 0) else old_trust

        self.conn.execute(
            "UPDATE nodes SET attrs_json=?, importance=MAX(importance,?), "
            "confidence=MAX(confidence,?), status=?, trust=?, last_access_step=? WHERE id=?",
            (json.dumps(merged), importance, confidence, new_status, new_trust, step, nid))
        self._commit()
        return nid

    def find_node(self, type: str, canonical_key: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM nodes WHERE type=? AND canonical_key=?",
            (type, canonical_key)).fetchone()

    def get_node(self, node_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()

    def node_attrs(self, node_id: int) -> dict:
        r = self.get_node(node_id)
        return json.loads(r["attrs_json"]) if r else {}

    def update_node(self, node_id: int, **fields) -> None:
        if not fields:
            return
        if "attrs" in fields:
            cur = self.node_attrs(node_id)
            cur.update(fields.pop("attrs"))
            fields["attrs_json"] = json.dumps(cur)
        cols = ", ".join(f"{k}=?" for k in fields)
        self.conn.execute(f"UPDATE nodes SET {cols} WHERE id=?",
                          (*fields.values(), node_id))
        self._commit()

    def set_status(self, node_id: int, status: str, confidence: Optional[float] = None) -> None:
        if confidence is None:
            self.update_node(node_id, status=status)
        else:
            self.update_node(node_id, status=status, confidence=confidence)

    def pin(self, node_id: int) -> None:
        self.update_node(node_id, pinned=1)

    def add_provenance(self, node_id: int, obs_id: int) -> int:
        """Record that `obs_id` supports this node; return the count of distinct
        supporting observations (used for consensus promotion)."""
        attrs = self.node_attrs(node_id)
        prov = set(attrs.get("_provenance", []))
        prov.add(obs_id)
        self.update_node(node_id, attrs={"_provenance": sorted(prov)})
        return len(prov)

    def touch(self, node_id: int) -> None:
        """Reconsolidation: bump last_access_step and strengthen (MemoryBank)."""
        self.conn.execute(
            "UPDATE nodes SET last_access_step=?, strength=strength+1 WHERE id=?",
            (self.step, node_id))
        self._commit()

    def set_embedding(self, node_id: int, blob: bytes) -> None:
        self.conn.execute("UPDATE nodes SET embedding=? WHERE id=?", (blob, node_id))
        self._commit()

    def nodes_with_embeddings(self, type: Optional[str] = None) -> list[sqlite3.Row]:
        q = ("SELECT id,type,embedding,importance,confidence,pinned,status,"
             "last_access_step,created_step,attrs_json FROM nodes "
             "WHERE embedding IS NOT NULL AND status!='invalidated'")
        args: tuple = ()
        if type:
            q += " AND type=?"
            args = (type,)
        return self.conn.execute(q, args).fetchall()

    def nodes_by_type(self, type: str, include_invalid: bool = False) -> list[sqlite3.Row]:
        q = "SELECT * FROM nodes WHERE type=?"
        if not include_invalid:
            q += " AND status!='invalidated'"
        return self.conn.execute(q, (type,)).fetchall()

    def pinned_nodes(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM nodes WHERE pinned=1").fetchall()

    # ---- edges ----------------------------------------------------------- #
    def add_edge(self, src_id: int, dst_id: int, rel_type: str,
                 attrs: Optional[dict] = None, weight: float = 1.0,
                 confidence: float = 0.5, trust: str = "agent_asserted",
                 provenance: Optional[list] = None) -> int:
        """Add an edge, or return the existing open edge of the same (src,dst,rel)."""
        existing = self.conn.execute(
            "SELECT id FROM edges WHERE src_id=? AND dst_id=? AND rel_type=? AND valid_to IS NULL",
            (src_id, dst_id, rel_type)).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE edges SET confidence=MAX(confidence,?), attrs_json=? WHERE id=?",
                (confidence, json.dumps(attrs or {}), existing["id"]))
            self._commit()
            return existing["id"]
        cur = self.conn.execute(
            "INSERT INTO edges(src_id,dst_id,rel_type,attrs_json,weight,confidence,"
            "trust,created_step,valid_from,provenance) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (src_id, dst_id, rel_type, json.dumps(attrs or {}), weight, confidence,
             trust, self.step, self.step, json.dumps(provenance or [])))
        self._commit()
        return cur.lastrowid

    def edges_from(self, src_id: int, rel_type: Optional[str] = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM edges WHERE src_id=? AND valid_to IS NULL"
        args: tuple = (src_id,)
        if rel_type:
            q += " AND rel_type=?"
            args = (src_id, rel_type)
        return self.conn.execute(q, args).fetchall()

    def all_edges(self, rel_type: Optional[str] = None) -> list[sqlite3.Row]:
        if rel_type:
            return self.conn.execute(
                "SELECT * FROM edges WHERE rel_type=? AND valid_to IS NULL", (rel_type,)).fetchall()
        return self.conn.execute("SELECT * FROM edges WHERE valid_to IS NULL").fetchall()

    # ---- capabilities ---------------------------------------------------- #
    def set_capabilities(self, node_id: int, provides: list, requires: list) -> None:
        self._new_cap_nodes.add(node_id)      # mark for incremental edge rebuild
        # DELETE-then-INSERT must be atomic (autocommit would otherwise expose a
        # window with the old rows gone and the new rows not yet written).
        with self.transaction():
            self.conn.execute("DELETE FROM provides WHERE node_id=?", (node_id,))
            self.conn.execute("DELETE FROM requires WHERE node_id=?", (node_id,))
            for name, attrs in provides:
                self.conn.execute(
                    "INSERT OR IGNORE INTO provides(node_id,token,attrs_json) VALUES(?,?,?)",
                    (node_id, name, caps.dump_attrs(attrs)))
            for name, attrs in requires:
                self.conn.execute(
                    "INSERT OR IGNORE INTO requires(node_id,token,attrs_json) VALUES(?,?,?)",
                    (node_id, name, caps.dump_attrs(attrs)))

    def get_provides(self, node_id: int) -> list:
        rows = self.conn.execute(
            "SELECT token,attrs_json FROM provides WHERE node_id=?", (node_id,)).fetchall()
        return [caps.load_token(r["token"], r["attrs_json"]) for r in rows]

    def get_requires(self, node_id: int) -> list:
        rows = self.conn.execute(
            "SELECT token,attrs_json FROM requires WHERE node_id=?", (node_id,)).fetchall()
        return [caps.load_token(r["token"], r["attrs_json"]) for r in rows]

    def nodes_with_requires_token(self, token: str) -> list[int]:
        rows = self.conn.execute(
            "SELECT DISTINCT node_id FROM requires WHERE token=?", (token,)).fetchall()
        return [r["node_id"] for r in rows]

    def nodes_with_provides_token(self, token: str) -> list[int]:
        rows = self.conn.execute(
            "SELECT DISTINCT node_id FROM provides WHERE token=?", (token,)).fetchall()
        return [r["node_id"] for r in rows]

    # ---- schema version -------------------------------------------------- #
    @property
    def schema_version(self) -> int:
        return migrations.get_version(self.conn)

    @property
    def fts_enabled(self) -> bool:
        return migrations.fts5_enabled(self.conn)

    # ---- content-addressed artifacts (immutable raw evidence) ------------ #
    def put_artifact(self, data, media_type: str = "application/octet-stream",
                     original_name: str = "", producing_run: str = "",
                     retention: str = "keep") -> dict:
        """Store raw bytes/str immutably and record them in the `artifacts` table.
        Returns {id, sha256, size, storage_path}. Idempotent on identical bytes:
        the blob dedupes on disk and the row dedupes on sha256. The disk write and
        the metadata row commit together."""
        if isinstance(data, str):
            info = self.artifacts.put_text(data)
        else:
            info = self.artifacts.put_bytes(data)
        with self.transaction():
            row = self.conn.execute(
                "SELECT id FROM artifacts WHERE sha256=?", (info["sha256"],)).fetchone()
            if row is not None:
                return {"id": row["id"], **info}
            cur = self.conn.execute(
                "INSERT INTO artifacts(sha256,media_type,size,storage_path,producing_run,"
                "original_name,retention,created_ts) VALUES(?,?,?,?,?,?,?,?)",
                (info["sha256"], media_type, info["size"], info["storage_path"],
                 producing_run, original_name, retention, time.time()))
            return {"id": cur.lastrowid, **info}

    def get_artifact_bytes(self, artifact_id: int, verify: bool = True):
        """Return the raw bytes for an artifact row id (re-verifying the digest),
        or None if the row or its blob is missing."""
        r = self.conn.execute(
            "SELECT sha256 FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        if r is None:
            return None
        return self.artifacts.get_bytes(r["sha256"], verify=verify)

    def artifact_row(self, artifact_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()

    # ---- audit ----------------------------------------------------------- #
    def add_audit(self, op: str, affected_table: str = "", affected_id: Optional[int] = None,
                  actor: str = "", session: str = "", correlation_id: str = "",
                  old_state: str = "", new_state: str = "", rationale: str = "") -> int:
        """Append an immutable audit event for a state-changing operation."""
        cur = self.conn.execute(
            "INSERT INTO audit_events(ts,actor,session,correlation_id,op,affected_table,"
            "affected_id,old_state,new_state,rationale) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (time.time(), actor, session, correlation_id, op, affected_table,
             affected_id, old_state, new_state, rationale))
        return cur.lastrowid

    def audit_for(self, affected_table: str, affected_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM audit_events WHERE affected_table=? AND affected_id=? ORDER BY id",
            (affected_table, affected_id)).fetchall()

    # ---- episodic -------------------------------------------------------- #
    def add_observation(self, request: str, response_meta: str, trust: str,
                        source: str, blob_ref: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO observations(step,ts,request,response_meta,blob_ref,trust,source) "
            "VALUES(?,?,?,?,?,?,?)",
            (self.step, time.time(), request, response_meta, blob_ref, trust, source))
        self._commit()
        return cur.lastrowid

    def add_payload(self, node_id: Optional[int], endpoint_id: Optional[int],
                    param_id: Optional[int], template: str, value: str,
                    outcome: str, success: bool, obs_id: Optional[int]) -> int:
        cur = self.conn.execute(
            "INSERT INTO payloads(node_id,endpoint_id,param_id,template,value,outcome,"
            "success,obs_id,step) VALUES(?,?,?,?,?,?,?,?,?)",
            (node_id, endpoint_id, param_id, template, value, outcome,
             int(success), obs_id, self.step))
        self._commit()
        return cur.lastrowid

    def payloads_for(self, endpoint_id: int, param_id: Optional[int] = None) -> list[sqlite3.Row]:
        if param_id is None:
            return self.conn.execute(
                "SELECT * FROM payloads WHERE endpoint_id=?", (endpoint_id,)).fetchall()
        return self.conn.execute(
            "SELECT * FROM payloads WHERE endpoint_id=? AND param_id=?",
            (endpoint_id, param_id)).fetchall()

    # ---- reflection ------------------------------------------------------ #
    def add_lesson(self, node_id: Optional[int], kind: str, text: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO lessons(node_id,kind,text,step) VALUES(?,?,?,?)",
            (node_id, kind, text, self.step))
        self._commit()
        return cur.lastrowid

    def lessons_for(self, node_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM lessons WHERE node_id=?", (node_id,)).fetchall()

    def set_summary(self, scope_type: str, scope_key: str, level: int, text: str) -> None:
        self.conn.execute(
            "INSERT INTO summaries(scope_type,scope_key,level,text,step) VALUES(?,?,?,?,?) "
            "ON CONFLICT(scope_type,scope_key,level) DO UPDATE SET text=excluded.text, step=excluded.step",
            (scope_type, scope_key, level, text, self.step))
        self._commit()

    # ---- chains ---------------------------------------------------------- #
    def upsert_chain(self, goal: str, score: float, severity: int, status: str,
                     narrative: str, steps: list[tuple[int, Optional[int]]],
                     dedup_key: str) -> int:
        existing = self.conn.execute(
            "SELECT id FROM chains WHERE dedup_key=?", (dedup_key,)).fetchone()
        if existing:
            cid = existing["id"]
            self.conn.execute(
                "UPDATE chains SET score=?, severity=?, status=?, narrative=?, step=? WHERE id=?",
                (score, severity, status, narrative, self.step, cid))
        else:
            cur = self.conn.execute(
                "INSERT INTO chains(goal,score,severity,status,narrative,step,dedup_key) "
                "VALUES(?,?,?,?,?,?,?)",
                (goal, score, severity, status, narrative, self.step, dedup_key))
            cid = cur.lastrowid
            for ordi, (nid, eid) in enumerate(steps):
                self.conn.execute(
                    "INSERT OR REPLACE INTO chain_steps(chain_id,ord,node_id,edge_id) VALUES(?,?,?,?)",
                    (cid, ordi, nid, eid))
        self._commit()
        return cid

    def chains(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM chains ORDER BY severity DESC, score DESC").fetchall()

    def chain_steps(self, chain_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM chain_steps WHERE chain_id=? ORDER BY ord", (chain_id,)).fetchall()

    # ---- working set ----------------------------------------------------- #
    def set_working(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO working_set(key,value_json,updated_step) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_step=excluded.updated_step",
            (key, json.dumps(value), self.step))
        self._commit()

    def get_working(self, key: str, default=None):
        r = self.conn.execute("SELECT value_json FROM working_set WHERE key=?", (key,)).fetchone()
        return json.loads(r["value_json"]) if r else default
