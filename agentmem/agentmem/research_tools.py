"""
agentmem.research_tools — the transport-independent contract layer for the
Firefox research MCP.

This is deliberately separate from both storage (ResearchMemory) and MCP
transport (research_mcp). Every operation returns a structured envelope with a
STABLE error code, validates its inputs, bounds its results, and supports an
idempotency key so a duplicate call cannot create duplicate evidence. The MCP
server is a thin adapter over these methods; tests exercise this layer directly.

Envelope:
    {"ok": true,  "data": {...}}
    {"ok": false, "error": {"code": "<CODE>", "message": "..."}}
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .research import ResearchMemory

# stable error codes (part of the contract)
INVALID_ARGUMENT = "INVALID_ARGUMENT"
NOT_FOUND = "NOT_FOUND"
REVISION_MISMATCH = "REVISION_MISMATCH"
STALE_EVIDENCE = "STALE_EVIDENCE"
CONFLICT = "CONFLICT"
BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
RESOURCE_LIMIT = "RESOURCE_LIMIT"

CODES = {INVALID_ARGUMENT, NOT_FOUND, REVISION_MISMATCH, STALE_EVIDENCE,
         CONFLICT, BACKEND_UNAVAILABLE, RESOURCE_LIMIT}

MAX_LIMIT = 200


def _ok(data) -> dict:
    return {"ok": True, "data": data}


def _err(code: str, message: str) -> dict:
    return {"ok": False, "error": {"code": code, "message": message}}


def _classify(exc: ValueError) -> str:
    """Map a ResearchMemory ValueError to a stable error code by its message."""
    msg = str(exc).lower()
    if "single snapshot" in msg or "revision" in msg or "cross-snapshot" in msg:
        return REVISION_MISMATCH
    if "unknown" in msg or "nonexistent" in msg or "not the current version" in msg:
        return NOT_FOUND
    return INVALID_ARGUMENT


class ResearchTools:
    def __init__(self, mem: ResearchMemory):
        self.m = mem
        self.conn = mem.conn

    # ---- idempotency ----------------------------------------------------- #
    @staticmethod
    def _payload_hash(payload) -> str:
        import hashlib
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def _idem_lookup(self, key: str, op: str, payload=None):
        """Replay only when the SAME key is reused for the SAME op AND the SAME
        arguments. A key reused for a different op, or the same op with different
        arguments, is a CONFLICT — not a silent replay of the first result."""
        if not key:
            return None
        row = self.conn.execute(
            "SELECT op,result_kind,result_id,payload_hash FROM idempotency_keys WHERE key=?",
            (key,)).fetchone()
        if row is None:
            return None
        if row["op"] != op:
            return _err(CONFLICT, f"idempotency key already used for a different op ({row['op']})")
        ph = self._payload_hash(payload) if payload is not None else None
        if ph is not None and row["payload_hash"] not in (None, ph):
            return _err(CONFLICT, "idempotency key reused with different arguments")
        return _ok({row["result_kind"]: row["result_id"], "idempotent_replay": True})

    def _idem_store(self, key: str, op: str, result_kind: str, result_id: int,
                    payload=None) -> None:
        if not key:
            return
        ph = self._payload_hash(payload) if payload is not None else None
        self.conn.execute(
            "INSERT OR IGNORE INTO idempotency_keys(key,op,result_kind,result_id,payload_hash,"
            "created_ts) VALUES(?,?,?,?,?,?)", (key, op, result_kind, result_id, ph, time.time()))

    # ---- snapshots / source -------------------------------------------- #
    def register_repository_snapshot(self, repo_id: str = "", commit_id: str = "",
                                     dirty: bool = False, patch_digest: str = "",
                                     scope: str = "", idempotency_key: str = "") -> dict:
        if not repo_id or not commit_id:
            return _err(INVALID_ARGUMENT, "repo_id and commit_id are required")
        payload = {k: v for k, v in locals().items() if k not in ("self", "idempotency_key")}
        replay = self._idem_lookup(idempotency_key, "register_repository_snapshot", payload)
        if replay is not None:
            return replay
        try:
            sid = self.m.register_snapshot(repo_id, commit_id, dirty, patch_digest, scope)
        except ValueError as e:
            return _err(_classify(e), str(e))
        self._idem_store(idempotency_key, "register_repository_snapshot", "snapshot_id", sid, payload)
        return _ok({"snapshot_id": sid})

    def record_source_reference(self, snapshot_id: int = 0, path: str = "", start_line: int = 0,
                                end_line: int = 0, symbol_id: str = "", language: str = "",
                                excerpt: Optional[str] = None, idempotency_key: str = "") -> dict:
        if not path:
            return _err(INVALID_ARGUMENT, "path is required")
        if start_line and end_line and end_line < start_line:
            return _err(INVALID_ARGUMENT, "end_line precedes start_line")
        replay = self._idem_lookup(idempotency_key, "record_source_reference")
        if replay is not None:
            return replay
        try:
            rid = self.m.add_source_ref(snapshot_id, path, start_line=start_line, end_line=end_line,
                                        symbol_id=symbol_id, language=language, excerpt=excerpt)
        except ValueError as e:
            return _err(_classify(e), str(e))
        self._idem_store(idempotency_key, "record_source_reference", "source_ref_id", rid)
        return _ok({"source_ref_id": rid})

    def record_value_identity(self, snapshot_id: int = 0, path: str = "", value_name: str = "",
                              role: str = "value", symbol_id: str = "", start_line: int = 0,
                              end_line: int = 0, sink_type: str = "", language: str = "",
                              idempotency_key: str = "") -> dict:
        if not path or not value_name:
            return _err(INVALID_ARGUMENT, "path and value_name are required")
        replay = self._idem_lookup(idempotency_key, "record_value_identity")
        if replay is not None:
            return replay
        try:
            vid = self.m.add_value_identity(snapshot_id, path, value_name, role=role,
                                            symbol_id=symbol_id, start_line=start_line,
                                            end_line=end_line, sink_type=sink_type, language=language)
        except ValueError as e:
            return _err(_classify(e), str(e))
        self._idem_store(idempotency_key, "record_value_identity", "value_identity_id", vid)
        return _ok({"value_identity_id": vid})

    # ---- evidence / hypotheses / flow ---------------------------------- #
    def record_analysis_evidence(self, snapshot_id: int = 0, kind: str = "static_analysis",
                                 raw: Optional[str] = None, projection: Optional[str] = None,
                                 status: str = "observed", trust: str = "agent_asserted",
                                 tool: str = "", query_id: str = "", tool_version: str = "",
                                 value_identity_id: Optional[int] = None,
                                 idempotency_key: str = "") -> dict:
        if raw is None and projection is None:
            return _err(INVALID_ARGUMENT, "evidence needs raw or projection")
        replay = self._idem_lookup(idempotency_key, "record_analysis_evidence")
        if replay is not None:
            return replay
        try:
            prov = self.m.add_provenance(snapshot_id, tool=tool, tool_version=tool_version,
                                         query_id=query_id, actor=tool or self.m.actor,
                                         actor_kind="tool" if tool else "agent", trust=trust)
            eid = self.m.add_evidence(snapshot_id, kind, raw=raw, projection=projection,
                                      status=status, trust=trust, provenance_id=prov,
                                      value_identity_id=value_identity_id)
        except ValueError as e:
            return _err(_classify(e), str(e))
        self._idem_store(idempotency_key, "record_analysis_evidence", "evidence_id", eid)
        stored = self.m.get_evidence(eid)
        return _ok({"evidence_id": eid, "stored_status": stored["status"]})

    def record_hypothesis(self, snapshot_id: Optional[int] = None, statement: str = "",
                          invariant: str = "", scope: str = "", next_action: str = "",
                          idempotency_key: str = "") -> dict:
        if not statement:
            return _err(INVALID_ARGUMENT, "statement is required")
        payload = {k: v for k, v in locals().items() if k not in ("self", "idempotency_key")}
        replay = self._idem_lookup(idempotency_key, "record_hypothesis", payload)
        if replay is not None:
            return replay
        try:
            hid = self.m.add_hypothesis(snapshot_id, statement, invariant=invariant,
                                        scope=scope, next_action=next_action)
        except ValueError as e:
            return _err(_classify(e), str(e))
        self._idem_store(idempotency_key, "record_hypothesis", "hypothesis_id", hid, payload)
        return _ok({"hypothesis_id": hid})

    def record_counter_evidence(self, hypothesis_id: int = 0, evidence_id: Optional[int] = None,
                                flow_edge_id: Optional[int] = None, rationale: str = "") -> dict:
        try:
            lid = self.m.link_evidence(hypothesis_id, "contradicts", evidence_id=evidence_id,
                                       flow_edge_id=flow_edge_id, rationale=rationale)
        except ValueError as e:
            return _err(_classify(e), str(e))
        return _ok({"link_id": lid})

    def link_flow_transition(self, snapshot_id: int = 0, src_vid: int = 0, dst_vid: int = 0,
                             kind: str = "interprocedural", status: str = "hypothesis",
                             trust: str = "agent_asserted", evidence_id: Optional[int] = None,
                             caller_symbol: str = "", callee_symbol: str = "",
                             arg_index: Optional[int] = None, param_name: str = "",
                             idempotency_key: str = "") -> dict:
        replay = self._idem_lookup(idempotency_key, "link_flow_transition")
        if replay is not None:
            return replay
        try:
            eid = self.m.add_flow_edge(snapshot_id, src_vid, dst_vid, kind=kind, status=status,
                                       trust=trust, evidence_id=evidence_id,
                                       caller_symbol=caller_symbol, callee_symbol=callee_symbol,
                                       arg_index=arg_index, param_name=param_name)
        except ValueError as e:
            return _err(_classify(e), str(e))
        self._idem_store(idempotency_key, "link_flow_transition", "flow_edge_id", eid)
        return _ok({"flow_edge_id": eid})

    def record_validation_run(self, snapshot_id: Optional[int] = None, kind: str = "test",
                              status: str = "not_run", hypothesis_id: Optional[int] = None,
                              logs: Optional[str] = None, repeat_summary: str = "",
                              idempotency_key: str = "") -> dict:
        replay = self._idem_lookup(idempotency_key, "record_validation_run")
        if replay is not None:
            return replay
        try:
            vid = self.m.add_validation_run(snapshot_id, kind=kind, status=status,
                                            hypothesis_id=hypothesis_id, logs=logs,
                                            repeat_summary=repeat_summary)
        except ValueError as e:
            return _err(_classify(e), str(e))
        self._idem_store(idempotency_key, "record_validation_run", "validation_run_id", vid)
        return _ok({"validation_run_id": vid})

    # ---- retrieval / review -------------------------------------------- #
    def query_history(self, snapshot_id: Optional[int] = None, text: str = "", kind: str = "",
                      status: str = "", path: str = "", symbol_id: str = "",
                      limit: int = 20, offset: int = 0) -> dict:
        if limit > MAX_LIMIT:
            return _err(RESOURCE_LIMIT, f"limit {limit} exceeds MAX_LIMIT {MAX_LIMIT}")
        try:
            hits = self.m.search_evidence(snapshot_id=snapshot_id, text=text or None,
                                          kind=kind or None, status=status or None,
                                          path=path or None, symbol_id=symbol_id or None,
                                          limit=limit, offset=offset)
        except ValueError as e:
            return _err(_classify(e), str(e))
        stale = [h for h in hits if h["stale"]]
        current = [h for h in hits if not h["stale"]]
        return _ok({"current": current, "historical": stale,
                    "text_backend": self.m.text_search_backend()})

    def review_chain(self, snapshot_id: int = 0, goal: str = "") -> dict:
        """Evaluate chains and report the EXACT missing/weak transitions (gaps). A
        chain is only 'demonstrated' when every required transition is demonstrated."""
        try:
            chains = self.m.chains(snapshot_id, goal=goal or None)
        except ValueError as e:
            return _err(_classify(e), str(e))
        reviewed = []
        for c in chains:
            gaps = [s for s in c["steps"] if s["status"] != "demonstrated" or s["guard_blocked"]]
            boundary_gaps = self.m.chain_boundary_gaps(snapshot_id, c["steps"])
            # a composed chain is 'demonstrated' only if EVERY transition is
            # demonstrated AND no unproven trust-boundary crossing remains.
            demonstrated = (c["status"] == "demonstrated" and not gaps and not boundary_gaps)
            reviewed.append({
                "goal": c["goal"], "status": c["status"], "severity": c["severity"],
                "impact_state": c["impact_state"], "narrative": c["narrative"],
                "demonstrated": demonstrated,
                "missing_transitions": [
                    {"flow_edge_id": g["flow_edge_id"], "status": g["status"],
                     "guard_blocked": g["guard_blocked"]} for g in gaps],
                "boundary_gaps": boundary_gaps,
            })
        return _ok({"chains": reviewed})

    def claim_coverage(self, hypothesis_id: int = 0) -> dict:
        try:
            return _ok(self.m.claim_coverage(hypothesis_id))
        except ValueError as e:
            return _err(_classify(e), str(e))

    def reclassify_sink(self, value_identity_id: int = 0, new_sink_type: str = "",
                        reason: str = "") -> dict:
        if not new_sink_type:
            return _err(INVALID_ARGUMENT, "new_sink_type is required")
        try:
            new_vid = self.m.reclassify_sink(value_identity_id, new_sink_type, reason=reason)
        except ValueError as e:
            return _err(_classify(e), str(e))
        return _ok({"new_value_identity_id": new_vid})

    def invalidate_changed_paths(self, snapshot_id: int = 0, changed_paths=None,
                                 reason: str = "source changed", new_snapshot_id: int = 0) -> dict:
        if not changed_paths:
            return _err(INVALID_ARGUMENT, "changed_paths is required")
        if isinstance(changed_paths, str):
            changed_paths = [p.strip() for p in changed_paths.split(",") if p.strip()]
        try:
            counts = self.m.invalidate_changed_paths(snapshot_id, changed_paths, reason,
                                                     new_snapshot_id or None)
        except ValueError as e:
            return _err(_classify(e), str(e))
        return _ok(counts)

    def export_evidence_bundle(self, snapshot_id: int = 0, limit: int = 100) -> dict:
        if limit > MAX_LIMIT:
            return _err(RESOURCE_LIMIT, f"limit {limit} exceeds MAX_LIMIT {MAX_LIMIT}")
        try:
            snap = self.m.get_snapshot(snapshot_id)
            if snap is None:
                return _err(NOT_FOUND, f"unknown snapshot {snapshot_id}")
            chains = self.m.chains(snapshot_id)
            evidence = self.m.search_evidence(snapshot_id=snapshot_id, limit=limit)
            findings = [dict(r) for r in self.conn.execute(
                "SELECT id,fingerprint,title,status,severity,impact_state FROM findings "
                "WHERE snapshot_id=? LIMIT ?", (snapshot_id, limit)).fetchall()]
        except ValueError as e:
            return _err(_classify(e), str(e))
        return _ok({"snapshot": {"id": snap["id"], "repo_id": snap["repo_id"],
                                 "commit_id": snap["commit_id"], "dirty": bool(snap["dirty"]),
                                 "scope": snap["scope"]},
                    "chains": chains, "evidence": evidence, "findings": findings})
