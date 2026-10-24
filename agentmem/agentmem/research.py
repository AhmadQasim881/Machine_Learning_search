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

from . import config
from .profiles import _CR_GOAL_SEVERITY, _SINK_GOAL
from .store import Store

# research trust ranking extends the engine's with human review (strongest) and a
# reproduced-under-controlled-conditions tier. Higher may assert stronger states.
_TRUST_RANK = {**config.TRUST_RANK, "human_verified": 4, "reproduced": 4}


def _trust_rank(trust: str) -> int:
    return _TRUST_RANK.get(trust, 0)

# demonstrated-ness ordering for flow-edge status; a chain is the WEAKEST step.
FLOW_STATUSES = ("rejected", "blocked", "hypothesis", "supported", "demonstrated")
_FLOW_RANK = {s: i for i, s in enumerate(FLOW_STATUSES)}
_RANK_FLOW = {i: s for s, i in _FLOW_RANK.items()}

# trust levels that may ASSERT a demonstrated/reproduced relationship. Untrusted
# repository text, raw LLM output, and arbitrary agent assertions cannot (task 4).
_STRONG_TRUST = {"tool_verified", "human_verified"}

EVIDENCE_STATUSES = ("observed", "supported", "reproduced", "rejected", "stale")
HYPOTHESIS_STATUSES = ("open", "supported", "rejected", "superseded")
VALIDATION_STATUSES = ("not_run", "passed", "failed", "inconclusive", "intermittent")
FINDING_STATUSES = ("draft", "in_review", "accepted", "duplicate", "closed")

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
        if evidence_id is not None and self.conn.execute(
                "SELECT 1 FROM evidence WHERE id=?", (evidence_id,)).fetchone() is None:
            raise ValueError(f"flow edge cites a nonexistent evidence id {evidence_id}")
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

    # ---- evidence -------------------------------------------------------- #
    def _gate_evidence_status(self, status: str, trust: str) -> str:
        """Untrusted/weak provenance can never independently reach a strong status.
        'reproduced' needs strong trust; 'supported' needs better than target_derived."""
        rank = _trust_rank(trust)
        if status == "reproduced" and trust not in _STRONG_TRUST:
            status = "supported"
        if status == "supported" and rank < _TRUST_RANK["llm_inferred"]:
            status = "observed"
        return status

    def add_evidence(self, snapshot_id: int, kind: str, raw=None,
                     projection: Optional[str] = None, status: str = "observed",
                     trust: str = "agent_asserted", provenance_id: Optional[int] = None,
                     obs_id: Optional[int] = None, value_identity_id: Optional[int] = None,
                     source_ref_id: Optional[int] = None, flow_edge_id: Optional[int] = None,
                     media_type: str = "text/plain") -> int:
        """Record an evidence item. Raw bytes/text are preserved verbatim as an
        immutable artifact; a bounded, sanitized, secret-redacted projection is
        stored for prompts/search. Referenced ids must exist. The status is gated by
        trust so untrusted evidence cannot self-promote to supported/reproduced."""
        self._require_snapshot(snapshot_id)
        if status not in EVIDENCE_STATUSES:
            raise ValueError(f"invalid evidence status: {status}")
        if obs_id is not None and self.store.observation(obs_id) is None:
            raise ValueError(f"unknown observation id {obs_id}")
        if value_identity_id is not None and self.get_value_identity(value_identity_id) is None:
            raise ValueError(f"unknown value identity {value_identity_id}")
        if flow_edge_id is not None and self.conn.execute(
                "SELECT 1 FROM flow_edges WHERE id=?", (flow_edge_id,)).fetchone() is None:
            raise ValueError(f"unknown flow edge {flow_edge_id}")
        status = self._gate_evidence_status(status, trust)

        from .security import project_text
        art_id, truncated = None, 0
        if raw is not None:
            info = self.store.put_artifact(raw, media_type=media_type,
                                           producing_run=f"evidence:{kind}")
            art_id = info["id"]
            raw_text = raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "replace")
            if projection is None:
                projection, tr = project_text(raw_text, vault=self.store.vault if hasattr(self.store, "vault") else None)
                truncated = int(tr)
        if projection is not None and raw is None:
            projection, tr = project_text(projection)
            truncated = int(tr)
        now = time.time()
        with self.store.transaction():
            cur = self.conn.execute(
                "INSERT INTO evidence(snapshot_id,kind,value_identity_id,source_ref_id,"
                "flow_edge_id,artifact_id,projection,projection_truncated,status,trust,"
                "provenance_id,obs_id,version,valid_from,valid_to,created_ts,meta_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,NULL,?,'{}')",
                (snapshot_id, kind, value_identity_id, source_ref_id, flow_edge_id, art_id,
                 projection, truncated, status, trust, provenance_id, obs_id, now, now))
            eid = cur.lastrowid
            if self.store.fts_enabled and projection:
                self.conn.execute(
                    "INSERT INTO evidence_fts(text,evidence_id,snapshot_id,kind) VALUES(?,?,?,?)",
                    (projection, eid, snapshot_id, kind))
            self.store.add_audit("add_evidence", "evidence", eid, actor=self.actor,
                                 session=self.session, new_state=status)
        return eid

    def get_evidence(self, evidence_id: int) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        return dict(r) if r else None

    def set_evidence_status(self, evidence_id: int, status: str, trust: Optional[str] = None,
                            reason: str = "") -> str:
        ev = self.get_evidence(evidence_id)
        if ev is None:
            raise ValueError(f"unknown evidence {evidence_id}")
        if status not in EVIDENCE_STATUSES:
            raise ValueError(f"invalid evidence status: {status}")
        status = self._gate_evidence_status(status, trust or ev["trust"])
        with self.store.transaction():
            self.conn.execute("UPDATE evidence SET status=? WHERE id=?", (status, evidence_id))
            self.store.add_audit("set_evidence_status", "evidence", evidence_id,
                                 actor=self.actor, session=self.session,
                                 old_state=ev["status"], new_state=status, rationale=reason)
        return status

    # ---- hypotheses ------------------------------------------------------ #
    def add_hypothesis(self, snapshot_id: Optional[int], statement: str, invariant: str = "",
                       scope: str = "", status: str = "open", next_action: str = "",
                       trust: str = "agent_asserted", provenance_id: Optional[int] = None) -> int:
        if status not in HYPOTHESIS_STATUSES:
            raise ValueError(f"invalid hypothesis status: {status}")
        now = time.time()
        with self.store.transaction():
            cur = self.conn.execute(
                "INSERT INTO hypotheses(snapshot_id,statement,invariant,scope,status,"
                "next_action,trust,provenance_id,version,valid_from,valid_to,created_ts,"
                "meta_json) VALUES(?,?,?,?,?,?,?,?,1,?,NULL,?,'{}')",
                (snapshot_id, statement, invariant or None, scope or None, status,
                 next_action or None, trust, provenance_id, now, now))
            hid = cur.lastrowid
            self.store.add_audit("add_hypothesis", "hypotheses", hid, actor=self.actor,
                                 session=self.session, new_state=status)
        return hid

    def get_hypothesis(self, hypothesis_id: int) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM hypotheses WHERE id=?", (hypothesis_id,)).fetchone()
        return dict(r) if r else None

    def link_evidence(self, hypothesis_id: int, relation: str, evidence_id: Optional[int] = None,
                      flow_edge_id: Optional[int] = None, validation_run_id: Optional[int] = None,
                      actor: str = "", rationale: str = "") -> int:
        """Link evidence/a flow edge/a validation run to a hypothesis with a typed
        relation (supports|contradicts|tests|requires|crosses_boundary). The target
        must exist — a link can never cite a nonexistent record."""
        if self.get_hypothesis(hypothesis_id) is None:
            raise ValueError(f"unknown hypothesis {hypothesis_id}")
        if relation not in ("supports", "contradicts", "tests", "requires", "crosses_boundary"):
            raise ValueError(f"invalid relation: {relation}")
        if evidence_id is not None and self.get_evidence(evidence_id) is None:
            raise ValueError(f"unknown evidence {evidence_id}")
        if flow_edge_id is not None and self.conn.execute(
                "SELECT 1 FROM flow_edges WHERE id=?", (flow_edge_id,)).fetchone() is None:
            raise ValueError(f"unknown flow edge {flow_edge_id}")
        if validation_run_id is not None and self.conn.execute(
                "SELECT 1 FROM validation_runs WHERE id=?", (validation_run_id,)).fetchone() is None:
            raise ValueError(f"unknown validation run {validation_run_id}")
        if evidence_id is None and flow_edge_id is None and validation_run_id is None:
            raise ValueError("link_evidence needs an evidence, flow_edge, or validation_run id")
        cur = self.conn.execute(
            "INSERT INTO hypothesis_evidence(hypothesis_id,evidence_id,flow_edge_id,"
            "validation_run_id,relation,actor,rationale,created_ts) VALUES(?,?,?,?,?,?,?,?)",
            (hypothesis_id, evidence_id, flow_edge_id, validation_run_id, relation,
             actor or self.actor, rationale or None, time.time()))
        return cur.lastrowid

    def counter_evidence(self, hypothesis_id: int) -> list[dict]:
        """Counter-evidence stays visible: all 'contradicts' links for a hypothesis."""
        rows = self.conn.execute(
            "SELECT * FROM hypothesis_evidence WHERE hypothesis_id=? AND relation='contradicts'",
            (hypothesis_id,)).fetchall()
        return [dict(r) for r in rows]

    def consensus_promote(self, hypothesis_id: int, evidence_ids: list,
                          rationale: str = "") -> dict:
        """Promote a hypothesis open -> supported ONLY when real, independent,
        acceptably-trusted evidence corroborates it. Consensus can establish at
        most 'supported' — never 'demonstrated'/'reproduced' (those require a
        validation run or strong direct evidence). Returns {promoted, status, reason}."""
        hyp = self.get_hypothesis(hypothesis_id)
        if hyp is None:
            raise ValueError(f"unknown hypothesis {hypothesis_id}")
        evs = []
        for eid in evidence_ids:
            e = self.get_evidence(eid)
            if e is None:
                raise ValueError(f"unknown evidence {eid}")     # no fabricated consensus
            evs.append(e)
        # compatible snapshot/scope
        snaps = {e["snapshot_id"] for e in evs}
        if hyp["snapshot_id"] is not None:
            snaps.add(hyp["snapshot_id"])
        if len(snaps) != 1:
            return {"promoted": False, "status": hyp["status"],
                    "reason": "evidence spans incompatible snapshots/scopes"}
        # independent provenance (distinct provenance rows / actors)
        provs = [e["provenance_id"] for e in evs]
        actors = set()
        for pid in provs:
            if pid is None:
                actors.add(("__none__", id(pid)))               # unknown provenance is not independent
            else:
                r = self.conn.execute("SELECT actor,tool FROM provenance WHERE id=?", (pid,)).fetchone()
                actors.add((r["actor"] if r else None, r["tool"] if r else None))
        acceptable = [e for e in evs if _trust_rank(e["trust"]) >= _TRUST_RANK["llm_inferred"]
                      and e["status"] in ("supported", "reproduced", "observed")]
        if len(acceptable) < 2 or len(actors) < 2:
            return {"promoted": False, "status": hyp["status"],
                    "reason": "need >=2 acceptably-trusted evidence records from independent provenance"}
        with self.store.transaction():
            for e in evs:
                self.conn.execute(
                    "INSERT INTO hypothesis_evidence(hypothesis_id,evidence_id,relation,actor,"
                    "rationale,created_ts) VALUES(?,?,'supports',?,?,?)",
                    (hypothesis_id, e["id"], self.actor, rationale or "consensus", time.time()))
            self.conn.execute("UPDATE hypotheses SET status='supported' WHERE id=?", (hypothesis_id,))
            self.store.add_audit("consensus_promote", "hypotheses", hypothesis_id,
                                 actor=self.actor, session=self.session,
                                 old_state=hyp["status"], new_state="supported",
                                 rationale=rationale or "consensus")
        return {"promoted": True, "status": "supported", "reason": "independent corroboration"}

    # ---- validation runs ------------------------------------------------- #
    def add_validation_run(self, snapshot_id: Optional[int], kind: str = "test",
                           status: str = "not_run", hypothesis_id: Optional[int] = None,
                           build_manifest_digest: str = "", config_digest: str = "",
                           logs=None, repeat_summary: str = "",
                           provenance_id: Optional[int] = None) -> int:
        if status not in VALIDATION_STATUSES:
            raise ValueError(f"invalid validation status: {status}")
        art_id = None
        if logs is not None:
            art_id = self.store.put_artifact(logs, media_type="text/plain",
                                             producing_run=f"validation:{kind}")["id"]
        now = time.time()
        with self.store.transaction():
            cur = self.conn.execute(
                "INSERT INTO validation_runs(snapshot_id,hypothesis_id,kind,status,"
                "build_manifest_digest,config_digest,artifact_id,repeat_summary,provenance_id,"
                "created_ts,meta_json) VALUES(?,?,?,?,?,?,?,?,?,?,'{}')",
                (snapshot_id, hypothesis_id, kind, status, build_manifest_digest or None,
                 config_digest or None, art_id, repeat_summary or None, provenance_id, now))
            vid = cur.lastrowid
            self.store.add_audit("add_validation_run", "validation_runs", vid,
                                 actor=self.actor, session=self.session, new_state=status)
        return vid

    # ---- findings -------------------------------------------------------- #
    def add_finding(self, snapshot_id: Optional[int], title: str, root_cause: str = "",
                    severity: str = "", status: str = "draft", impact_state: str = "unproven",
                    hypothesis_id: Optional[int] = None, fingerprint: str = "",
                    provenance_id: Optional[int] = None) -> int:
        """Record a finding. Deduped on a defect FINGERPRINT (root cause + affected
        symbols), not the report title. impact_state is separate from the finding's
        review lifecycle and defaults to 'unproven'."""
        if status not in FINDING_STATUSES:
            raise ValueError(f"invalid finding status: {status}")
        if impact_state not in ("unproven", "suspected", "demonstrated"):
            raise ValueError(f"invalid impact_state: {impact_state}")
        fp = fingerprint or _digest(str(snapshot_id), root_cause or title)
        existing = self.conn.execute("SELECT id FROM findings WHERE fingerprint=?", (fp,)).fetchone()
        if existing is not None:
            return existing["id"]
        now = time.time()
        with self.store.transaction():
            cur = self.conn.execute(
                "INSERT INTO findings(snapshot_id,fingerprint,title,root_cause,status,severity,"
                "impact_state,hypothesis_id,provenance_id,version,valid_from,valid_to,created_ts,"
                "meta_json) VALUES(?,?,?,?,?,?,?,?,?,1,?,NULL,?,'{}')",
                (snapshot_id, fp, title, root_cause or None, status, severity or None,
                 impact_state, hypothesis_id, provenance_id, now, now))
            fid = cur.lastrowid
            self.store.add_audit("add_finding", "findings", fid, actor=self.actor,
                                 session=self.session, new_state=f"{status}/{impact_state}")
        return fid

    # ---- append-only reclassification ----------------------------------- #
    def reclassify_sink(self, vid_id: int, new_sink_type: str, reason: str = "") -> int:
        """Append-only reclassification of a sink's type. Closes the old value
        identity version, creates a new version with the new sink_type, re-points
        the current flow edges onto it, and records an audit event. The chain
        derived from the OLD classification is thereby retracted/staled (its edges
        are closed) and recomputed under the new classification. Returns the new vid."""
        v = self.get_value_identity(vid_id)
        if v is None:
            raise ValueError(f"unknown value identity {vid_id}")
        if v["role"] != "sink":
            raise ValueError("reclassify_sink applies only to a sink value identity")
        if v["valid_to"] is not None:
            raise ValueError("value identity is not the current version")
        now = time.time()
        with self.store.transaction():
            self.conn.execute("UPDATE value_identities SET valid_to=? WHERE id=?", (now, vid_id))
            cur = self.conn.execute(
                "INSERT INTO value_identities(snapshot_id,vid_key,path,symbol_id,value_name,"
                "start_line,end_line,role,sink_type,language,tool,run_id,source_ref_id,"
                "provenance_id,status,version,valid_from,valid_to,created_ts,meta_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,'{}')",
                (v["snapshot_id"], v["vid_key"], v["path"], v["symbol_id"], v["value_name"],
                 v["start_line"], v["end_line"], v["role"], new_sink_type, v["language"],
                 v["tool"], v["run_id"], v["source_ref_id"], v["provenance_id"], v["status"],
                 (v["version"] or 1) + 1, now, now))
            new_vid = cur.lastrowid
            # re-point current flow edges that touch the old vid onto the new version
            edges = self.conn.execute(
                "SELECT * FROM flow_edges WHERE valid_to IS NULL AND (src_vid=? OR dst_vid=?)",
                (vid_id, vid_id)).fetchall()
            for e in edges:
                self.conn.execute("UPDATE flow_edges SET valid_to=? WHERE id=?", (now, e["id"]))
                src = new_vid if e["src_vid"] == vid_id else e["src_vid"]
                dst = new_vid if e["dst_vid"] == vid_id else e["dst_vid"]
                ne = self.conn.execute(
                    "INSERT INTO flow_edges(snapshot_id,src_vid,dst_vid,kind,callsite_path,"
                    "callsite_line,caller_symbol,callee_symbol,arg_index,param_name,return_to,"
                    "field_id,status,confidence,trust,provenance_id,evidence_id,version,"
                    "valid_from,valid_to,created_ts,meta_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,'{}')",
                    (e["snapshot_id"], src, dst, e["kind"], e["callsite_path"], e["callsite_line"],
                     e["caller_symbol"], e["callee_symbol"], e["arg_index"], e["param_name"],
                     e["return_to"], e["field_id"], e["status"], e["confidence"], e["trust"],
                     e["provenance_id"], e["evidence_id"], (e["version"] or 1) + 1, now, now))
                self.conn.execute("UPDATE flow_edges SET superseded_by=? WHERE id=?",
                                  (ne.lastrowid, e["id"]))
            # stale any materialized research chains that referenced the closed edges
            self.conn.execute(
                "UPDATE research_chains SET status='stale' WHERE id IN ("
                "SELECT DISTINCT chain_id FROM research_chain_steps WHERE flow_edge_id IN ("
                "SELECT id FROM flow_edges WHERE valid_to=?))", (now,))
            self.store.add_audit("reclassify_sink", "value_identities", vid_id, actor=self.actor,
                                 session=self.session, old_state=v["sink_type"] or "",
                                 new_state=new_sink_type, rationale=reason)
        return new_vid

    # ---- cross-revision staleness --------------------------------------- #
    def evidence_for(self, snapshot_id: int, include_historical: bool = False) -> dict:
        """Current evidence for a snapshot. Evidence from OTHER revisions is never
        returned as current: with include_historical=True it is returned in a
        separate list, each row labelled stale + revision_mismatch."""
        self._require_snapshot(snapshot_id)
        cur = [dict(r) for r in self.conn.execute(
            "SELECT * FROM evidence WHERE snapshot_id=? AND valid_to IS NULL ORDER BY id",
            (snapshot_id,)).fetchall()]
        for e in cur:
            e["stale"], e["revision_mismatch"] = False, False
        result = {"current": cur, "historical": []}
        if include_historical:
            hist = [dict(r) for r in self.conn.execute(
                "SELECT * FROM evidence WHERE (snapshot_id IS NULL OR snapshot_id!=?) ORDER BY id",
                (snapshot_id,)).fetchall()]
            for e in hist:
                e["stale"], e["revision_mismatch"] = True, True
                e["stale_reason"] = e.get("stale_reason") or "recorded against a different revision"
            result["historical"] = hist
        return result

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
