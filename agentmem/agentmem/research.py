"""
agentmem.research — revision-aware, evidence-based source-code research memory.

This is the reliable replacement for the first-generation code-review profile.
Its core rule: **a code-flow relationship is an explicit, provenance-bearing
record, never an inference from two values sharing a variable name.**

The flow graph has two node/edge types:

  * `value_identities` — a *scoped* value: (snapshot, case-sensitive path,
    qualified symbol, source range, value name, role). A local `data` in function
    A and a local `data` in function B are DIFFERENT identities (different
    `vid_key`), so they never connect by name.
  * `flow_edges` — an explicit transition recorded by an analysis tool, by exact
    source review, or as a labelled hypothesis. Interprocedural edges carry the
    callsite, caller/callee symbols, the argument→parameter mapping, and the
    return→receiver mapping. A chain may traverse ONLY these edges.

`guards` model sanitizers/validators as evidence-backed transitions attached to a
specific flow edge. An active guard with no bypass/incomplete record blocks that
edge from contributing to a confirmed chain.

A research chain's status is the **weakest** transition on it (a chain is never
stronger than its least-supported step), and an active guard caps a step at
`blocked`. Everything is snapshot-scoped; cross-revision records are labelled
`stale`/`revision-mismatch` and never silently presented as current.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Optional

from .profiles import _CR_GOAL_SEVERITY, _SINK_GOAL
from .store import Store

# demonstrated-ness ordering for flow-edge status; a chain is the WEAKEST step.
FLOW_STATUSES = ("rejected", "blocked", "hypothesis", "supported", "demonstrated")
_FLOW_RANK = {s: i for i, s in enumerate(FLOW_STATUSES)}
_RANK_FLOW = {i: s for s, i in _FLOW_RANK.items()}

# trust levels that may ASSERT a demonstrated/reproduced relationship. Untrusted
# repository text, raw LLM output, and arbitrary agent assertions cannot (task 4).
_STRONG_TRUST = {"tool_verified", "human_verified", "reproduced"}

_MAX_PATH_DEPTH = 24          # bound chain search (defensive; research graphs are small)


def _digest(*parts: str) -> str:
    return hashlib.sha256("||".join(parts).encode("utf-8")).hexdigest()


def vid_key(path: str, symbol_id: str, value_name: str,
            start_line: int, end_line: int, role: str) -> str:
    """Canonical scoped-identity key. Path is CASE-SENSITIVE on purpose: `Foo.cpp`
    and `foo.cpp` are distinct identities on a case-sensitive repository."""
    return "|".join(["vid", path or "", symbol_id or "", value_name or "",
                     f"{int(start_line or 0)}-{int(end_line or 0)}", role or "value"])


class ResearchMemory:
    """Facade over the research-evidence tables (built on the same Store/SQLite
    connection and artifact store as the web engine, migrated to schema v2)."""

    def __init__(self, path: str = "research.db", actor: str = "agent",
                 session: str = "", check_same_thread: bool = True):
        self.store = Store(path, check_same_thread=check_same_thread)
        self.conn = self.store.conn
        self.actor = actor
        self.session = session

    def close(self) -> None:
        self.store.close()

    def __enter__(self) -> "ResearchMemory":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- snapshots ------------------------------------------------------- #
    def register_snapshot(self, repo_id: str, commit_id: str, dirty: bool = False,
                          patch_digest: str = "", scope: str = "") -> int:
        """Register (or return) a repository snapshot. Its identity folds in the
        dirty state + patch digest + scope, so a patched run is a DIFFERENT
        snapshot than the clean commit."""
        if not repo_id or not commit_id:
            raise ValueError("snapshot requires repo_id and commit_id")
        uid = _digest(repo_id, commit_id, str(int(dirty)), patch_digest or "", scope or "")[:24]
        row = self.conn.execute("SELECT id FROM snapshots WHERE snapshot_uid=?", (uid,)).fetchone()
        if row is not None:
            return row["id"]
        with self.store.transaction():
            cur = self.conn.execute(
                "INSERT INTO snapshots(snapshot_uid,repo_id,commit_id,dirty,patch_digest,"
                "scope,created_ts,meta_json) VALUES(?,?,?,?,?,?,?,'{}')",
                (uid, repo_id, commit_id, int(dirty), patch_digest or None, scope or None,
                 time.time()))
            sid = cur.lastrowid
            self.store.add_audit("register_snapshot", "snapshots", sid, actor=self.actor,
                                 session=self.session, new_state=uid)
        return sid

    def get_snapshot(self, snapshot_id: int) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        return dict(r) if r else None

    def _require_snapshot(self, snapshot_id: int) -> None:
        if self.conn.execute("SELECT 1 FROM snapshots WHERE id=?", (snapshot_id,)).fetchone() is None:
            raise ValueError(f"unknown snapshot {snapshot_id}")

    # ---- provenance ------------------------------------------------------ #
    def add_provenance(self, snapshot_id: Optional[int] = None, tool: str = "",
                       tool_version: str = "", actor: str = "", actor_kind: str = "agent",
                       trust: str = "agent_asserted", query_id: str = "",
                       config_digest: str = "", raw_artifact_id: Optional[int] = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO provenance(snapshot_id,tool,tool_version,query_id,actor,actor_kind,"
            "trust,config_digest,raw_artifact_id,ts,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?,'{}')",
            (snapshot_id, tool or None, tool_version or None, query_id or None,
             actor or self.actor, actor_kind, trust, config_digest or None,
             raw_artifact_id, time.time()))
        return cur.lastrowid

    # ---- source references ---------------------------------------------- #
    def add_source_ref(self, snapshot_id: int, path: str, start_line: int = 0,
                       end_line: int = 0, start_col: int = 0, end_col: int = 0,
                       symbol_id: str = "", language: str = "",
                       excerpt: Optional[str] = None) -> int:
        self._require_snapshot(snapshot_id)
        art_id, digest = None, None
        if excerpt is not None:
            info = self.store.put_artifact(excerpt, media_type="text/plain",
                                           producing_run="source_excerpt")
            art_id, digest = info["id"], info["sha256"]
        with self.store.transaction():
            cur = self.conn.execute(
                "INSERT INTO source_refs(snapshot_id,path,start_line,start_col,end_line,"
                "end_col,symbol_id,language,excerpt_artifact_id,excerpt_digest,created_ts,"
                "meta_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,'{}')",
                (snapshot_id, path, start_line, start_col, end_line, end_col,
                 symbol_id or None, language or None, art_id, digest, time.time()))
            return cur.lastrowid

    # ---- value identities (flow-graph nodes) ----------------------------- #
    def add_value_identity(self, snapshot_id: int, path: str, value_name: str,
                           role: str = "value", symbol_id: str = "", start_line: int = 0,
                           end_line: int = 0, sink_type: str = "", language: str = "",
                           tool: str = "", run_id: str = "",
                           source_ref_id: Optional[int] = None,
                           provenance_id: Optional[int] = None,
                           status: str = "observed") -> int:
        """Record a scoped value identity (the node a flow edge connects). Dedupes
        on (snapshot, vid_key) current version; path is case-sensitive."""
        self._require_snapshot(snapshot_id)
        if role not in ("source", "sink", "transform", "param", "return", "field", "value"):
            raise ValueError(f"invalid value-identity role: {role}")
        key = vid_key(path, symbol_id, value_name, start_line, end_line, role)
        row = self.conn.execute(
            "SELECT id FROM value_identities WHERE snapshot_id=? AND vid_key=? AND valid_to IS NULL",
            (snapshot_id, key)).fetchone()
        if row is not None:
            return row["id"]
        now = time.time()
        with self.store.transaction():
            cur = self.conn.execute(
                "INSERT INTO value_identities(snapshot_id,vid_key,path,symbol_id,value_name,"
                "start_line,end_line,role,sink_type,language,tool,run_id,source_ref_id,"
                "provenance_id,status,version,valid_from,valid_to,created_ts,meta_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,NULL,?,'{}')",
                (snapshot_id, key, path, symbol_id or None, value_name, start_line, end_line,
                 role, sink_type or None, language or None, tool or None, run_id or None,
                 source_ref_id, provenance_id, status, now, now))
            vid = cur.lastrowid
            self.store.add_audit("add_value_identity", "value_identities", vid,
                                 actor=self.actor, session=self.session, new_state=role)
        return vid

    def get_value_identity(self, vid: int) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM value_identities WHERE id=?", (vid,)).fetchone()
        return dict(r) if r else None

    # ---- explicit flow edges -------------------------------------------- #
    def add_flow_edge(self, snapshot_id: int, src_vid: int, dst_vid: int,
                      kind: str = "intraprocedural", status: str = "hypothesis",
                      callsite_path: str = "", callsite_line: int = 0,
                      caller_symbol: str = "", callee_symbol: str = "",
                      arg_index: Optional[int] = None, param_name: str = "",
                      return_to: str = "", field_id: str = "",
                      confidence: float = 0.5, trust: str = "agent_asserted",
                      provenance_id: Optional[int] = None,
                      evidence_id: Optional[int] = None) -> int:
        """Record an explicit flow transition between two scoped value identities.
        Both identities must exist and belong to the SAME snapshot (a chain may not
        cross revisions). `status` is capped: only strong-trust provenance may
        assert 'demonstrated' (otherwise it is lowered to 'supported')."""
        self._require_snapshot(snapshot_id)
        if status not in _FLOW_RANK:
            raise ValueError(f"invalid flow status: {status}")
        src = self.get_value_identity(src_vid)
        dst = self.get_value_identity(dst_vid)
        if src is None or dst is None:
            raise ValueError("flow edge references a nonexistent value identity")
        if src["snapshot_id"] != snapshot_id or dst["snapshot_id"] != snapshot_id:
            raise ValueError("flow edge must stay within a single snapshot (revision)")
        # trust gate: an untrusted/ordinary assertion cannot claim 'demonstrated'
        if status == "demonstrated" and trust not in _STRONG_TRUST:
            status = "supported"
        now = time.time()
        with self.store.transaction():
            cur = self.conn.execute(
                "INSERT INTO flow_edges(snapshot_id,src_vid,dst_vid,kind,callsite_path,"
                "callsite_line,caller_symbol,callee_symbol,arg_index,param_name,return_to,"
                "field_id,status,confidence,trust,provenance_id,evidence_id,version,"
                "valid_from,valid_to,created_ts,meta_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,NULL,?,'{}')",
                (snapshot_id, src_vid, dst_vid, kind, callsite_path or None, callsite_line or None,
                 caller_symbol or None, callee_symbol or None, arg_index, param_name or None,
                 return_to or None, field_id or None, status, confidence, trust,
                 provenance_id, evidence_id, now, now))
            eid = cur.lastrowid
            self.store.add_audit("add_flow_edge", "flow_edges", eid, actor=self.actor,
                                 session=self.session, new_state=status)
        return eid

    # ---- guards / sanitizers -------------------------------------------- #
    def add_guard(self, snapshot_id: int, flow_edge_id: Optional[int] = None,
                  in_vid: Optional[int] = None, out_vid: Optional[int] = None,
                  guard_symbol: str = "", path: str = "", start_line: int = 0,
                  end_line: int = 0, condition: str = "", transformation: str = "",
                  kind: str = "sanitizer", limits: str = "", status: str = "active",
                  provenance_id: Optional[int] = None,
                  evidence_id: Optional[int] = None) -> int:
        """Record an evidence-backed sanitizer/guard attached to a specific flow
        edge. An `active` guard with no bypass/incomplete record prevents that edge
        from contributing to a confirmed/demonstrated chain."""
        self._require_snapshot(snapshot_id)
        if status not in ("active", "bypassed", "incomplete", "rejected"):
            raise ValueError(f"invalid guard status: {status}")
        if flow_edge_id is not None and self.conn.execute(
                "SELECT 1 FROM flow_edges WHERE id=?", (flow_edge_id,)).fetchone() is None:
            raise ValueError(f"guard references a nonexistent flow edge {flow_edge_id}")
        now = time.time()
        with self.store.transaction():
            cur = self.conn.execute(
                "INSERT INTO guards(snapshot_id,in_vid,out_vid,flow_edge_id,guard_symbol,path,"
                "start_line,end_line,condition,transformation,kind,limits,status,provenance_id,"
                "evidence_id,version,valid_from,valid_to,created_ts,meta_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,NULL,?,'{}')",
                (snapshot_id, in_vid, out_vid, flow_edge_id, guard_symbol or None, path or None,
                 start_line or None, end_line or None, condition or None, transformation or None,
                 kind, limits or None, status, provenance_id, evidence_id, now, now))
            gid = cur.lastrowid
            self.store.add_audit("add_guard", "guards", gid, actor=self.actor,
                                 session=self.session, new_state=status)
        return gid

    def _edge_is_guard_blocked(self, flow_edge_id: int) -> bool:
        """An edge is blocked by a guard iff it has an ACTIVE guard and no
        bypassed/incomplete guard (which would show taint still flows)."""
        rows = self.conn.execute(
            "SELECT status FROM guards WHERE flow_edge_id=? AND valid_to IS NULL",
            (flow_edge_id,)).fetchall()
        if not rows:
            return False
        statuses = {r["status"] for r in rows}
        if statuses & {"bypassed", "incomplete"}:
            return False                      # separate evidence shows the guard is defeated/partial
        return "active" in statuses

    # ---- chain composition (explicit edges only) ------------------------ #
    def _current_edges(self, snapshot_id: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM flow_edges WHERE snapshot_id=? AND valid_to IS NULL "
            "AND status!='rejected'", (snapshot_id,)).fetchall()
        return [dict(r) for r in rows]

    def chains(self, snapshot_id: int, goal: Optional[str] = None) -> list[dict]:
        """Compose chains from explicit flow edges: every source→…→sink path over
        current, non-rejected edges within this snapshot. A chain's status is the
        WEAKEST transition on it (and an active guard caps a step at 'blocked'), so
        a chain can never be stronger than its least-supported step."""
        self._require_snapshot(snapshot_id)
        edges = self._current_edges(snapshot_id)
        by_src: dict[int, list[dict]] = {}
        for e in edges:
            by_src.setdefault(e["src_vid"], []).append(e)

        vids = {r["id"]: dict(r) for r in self.conn.execute(
            "SELECT * FROM value_identities WHERE snapshot_id=? AND valid_to IS NULL",
            (snapshot_id,)).fetchall()}
        sources = [v for v in vids.values() if v["role"] == "source"]

        out, seen_keys = [], set()

        def label(v: dict) -> str:
            loc = f"{v['path']}:{v['start_line']}" if v.get("start_line") else v["path"]
            return f"{v['role']}({v.get('value_name') or ''}@{v.get('symbol_id') or '?'}) {loc}"

        def walk(vid: int, path_edges: list[dict], visited: set):
            if len(path_edges) > _MAX_PATH_DEPTH:
                return
            v = vids.get(vid)
            if v is not None and v["role"] == "sink" and path_edges:
                _emit(path_edges, v)
            for e in by_src.get(vid, []):
                if e["dst_vid"] in visited:
                    continue
                walk(e["dst_vid"], path_edges + [e], visited | {e["dst_vid"]})

        def _emit(path_edges: list[dict], sink_v: dict):
            key = tuple(e["id"] for e in path_edges)
            if key in seen_keys:
                return
            seen_keys.add(key)
            # weakest-link status; an active guard caps a step at 'blocked'
            ranks = []
            steps = []
            for e in path_edges:
                r = _FLOW_RANK[e["status"]]
                guarded = self._edge_is_guard_blocked(e["id"])
                if guarded:
                    r = min(r, _FLOW_RANK["blocked"])
                ranks.append(r)
                steps.append({"flow_edge_id": e["id"], "src_vid": e["src_vid"],
                              "dst_vid": e["dst_vid"], "status": e["status"],
                              "guard_blocked": guarded, "kind": e["kind"]})
            status = _RANK_FLOW[min(ranks)] if ranks else "hypothesis"
            sink_type = sink_v.get("sink_type") or "generic"
            g = _SINK_GOAL.get(sink_type, "injection")
            if goal is not None and g != goal:
                return
            sev = _CR_GOAL_SEVERITY.get(g, 5)
            src_v = vids.get(path_edges[0]["src_vid"], {})
            narrative = " -> ".join([label(src_v)] + [label(vids.get(e["dst_vid"], {})) for e in path_edges])
            impact = "demonstrated" if status == "demonstrated" else (
                "suspected" if status in ("supported",) else "unproven")
            dedup = _digest(str(snapshot_id), *[str(e["id"]) for e in path_edges])
            out.append({"snapshot_id": snapshot_id, "goal": g, "severity": sev,
                        "status": status, "impact_state": impact,
                        "narrative": f"{narrative}  ==>  {g.upper()} [{status}]",
                        "steps": steps, "dedup_key": dedup})

        for s in sources:
            walk(s["id"], [], {s["id"]})
        out.sort(key=lambda c: (_FLOW_RANK[c["status"]], c["severity"]), reverse=True)
        return out
