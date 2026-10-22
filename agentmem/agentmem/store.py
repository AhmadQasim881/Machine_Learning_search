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
from typing import Any, Iterable, Optional

from . import capabilities as caps

_SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")


class Store:
    def __init__(self, path: str = "campaign.db"):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        with open(_SCHEMA, encoding="utf-8") as fh:
            self.conn.executescript(fh.read())
        if self._meta("step") is None:
            self._set_meta("step", "0")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

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
        self.conn.commit()
        return s

    # ---- nodes ----------------------------------------------------------- #
    def upsert_node(self, type: str, canonical_key: str, attrs: Optional[dict] = None,
                    importance: int = 5, confidence: float = 0.5,
                    trust: str = "agent_asserted", status: str = "suspected",
                    pinned: bool = False) -> int:
        """Insert or merge a node by (type, canonical_key). On conflict, attrs are
        shallow-merged and importance/confidence raised (monotonic), never lowered
        silently — ground truth is not downgraded by a later weak observation."""
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
            self.conn.commit()
            return cur.lastrowid
        nid = existing["id"]
        merged = {**json.loads(existing["attrs_json"] or "{}"), **(attrs or {})}
        self.conn.execute(
            "UPDATE nodes SET attrs_json=?, importance=MAX(importance,?), "
            "confidence=MAX(confidence,?), last_access_step=? WHERE id=?",
            (json.dumps(merged), importance, confidence, step, nid))
        self.conn.commit()
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
        self.conn.commit()

    def set_status(self, node_id: int, status: str, confidence: Optional[float] = None) -> None:
        if confidence is None:
            self.update_node(node_id, status=status)
        else:
            self.update_node(node_id, status=status, confidence=confidence)

    def pin(self, node_id: int) -> None:
        self.update_node(node_id, pinned=1)

    def touch(self, node_id: int) -> None:
        """Reconsolidation: bump last_access_step and strengthen (MemoryBank)."""
        self.conn.execute(
            "UPDATE nodes SET last_access_step=?, strength=strength+1 WHERE id=?",
            (self.step, node_id))
        self.conn.commit()

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
            self.conn.commit()
            return existing["id"]
        cur = self.conn.execute(
            "INSERT INTO edges(src_id,dst_id,rel_type,attrs_json,weight,confidence,"
            "trust,created_step,valid_from,provenance) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (src_id, dst_id, rel_type, json.dumps(attrs or {}), weight, confidence,
             trust, self.step, self.step, json.dumps(provenance or [])))
        self.conn.commit()
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
        self.conn.commit()

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

    # ---- episodic -------------------------------------------------------- #
    def add_observation(self, request: str, response_meta: str, trust: str,
                        source: str, blob_ref: str = "") -> int:
        cur = self.conn.execute(
            "INSERT INTO observations(step,ts,request,response_meta,blob_ref,trust,source) "
            "VALUES(?,?,?,?,?,?,?)",
            (self.step, time.time(), request, response_meta, blob_ref, trust, source))
        self.conn.commit()
        return cur.lastrowid

    def add_payload(self, node_id: Optional[int], endpoint_id: Optional[int],
                    param_id: Optional[int], template: str, value: str,
                    outcome: str, success: bool, obs_id: Optional[int]) -> int:
        cur = self.conn.execute(
            "INSERT INTO payloads(node_id,endpoint_id,param_id,template,value,outcome,"
            "success,obs_id,step) VALUES(?,?,?,?,?,?,?,?,?)",
            (node_id, endpoint_id, param_id, template, value, outcome,
             int(success), obs_id, self.step))
        self.conn.commit()
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
        self.conn.commit()
        return cur.lastrowid

    def lessons_for(self, node_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM lessons WHERE node_id=?", (node_id,)).fetchall()

    def set_summary(self, scope_type: str, scope_key: str, level: int, text: str) -> None:
        self.conn.execute(
            "INSERT INTO summaries(scope_type,scope_key,level,text,step) VALUES(?,?,?,?,?) "
            "ON CONFLICT(scope_type,scope_key,level) DO UPDATE SET text=excluded.text, step=excluded.step",
            (scope_type, scope_key, level, text, self.step))
        self.conn.commit()

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
        self.conn.commit()
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
        self.conn.commit()

    def get_working(self, key: str, default=None):
        r = self.conn.execute("SELECT value_json FROM working_set WHERE key=?", (key,)).fetchone()
        return json.loads(r["value_json"]) if r else default
