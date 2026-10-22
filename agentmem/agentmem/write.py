"""
agentmem.write — the write pipeline (spec §3.1).

observe -> sanitize -> persist episodic -> extract typed facts -> canonicalize/
resolve -> VERIFY (oracle gate) -> attach capabilities -> link-and-evolve ->
dual-record (raw + lesson) -> trigger chain detection.

Structured path only (no LLM): capabilities come from typed extractors + an
oracle, never from target text. This is what keeps memory poisoning-resistant —
a response that merely says "IDOR" cannot mint a confirmed finding.
"""
from __future__ import annotations

from typing import Optional

from . import canonical as C
from . import capabilities as caps
from .security import sanitize, may_seed_chain
from .store import Store


def observe(store: Store, request: str, response_meta: str = "",
            trust: str = "target_derived", source: str = "http") -> int:
    """Append a lossless observation (target text sanitized first)."""
    return store.add_observation(
        sanitize(request), sanitize(response_meta), trust, source)


def ensure_host(store: Store, host: str, attrs: Optional[dict] = None) -> int:
    host = C.norm_host(host)
    return store.upsert_node("host", C.host_key(host),
                             {"hostname": host, **(attrs or {})},
                             importance=5, confidence=0.9, trust="agent_asserted",
                             status="confirmed")


def ensure_endpoint(store: Store, host: str, path: str, method: str = "GET",
                    attrs: Optional[dict] = None) -> int:
    hid = ensure_host(store, host)
    eid = store.upsert_node(
        "endpoint", C.endpoint_key(method, host, path),
        {"host": C.norm_host(host), "path": C.norm_path(path),
         "method": (method or "GET").upper(), **(attrs or {})},
        importance=5, confidence=0.9, trust="agent_asserted", status="confirmed")
    store.add_edge(hid, eid, "HOSTS", confidence=0.9, trust="agent_asserted")
    return eid


def ensure_param(store: Store, host: str, path: str, name: str,
                 method: str = "GET", location: str = "query",
                 attrs: Optional[dict] = None) -> int:
    eid = ensure_endpoint(store, host, path, method)
    pid = store.upsert_node(
        "param", C.param_key(method, host, path, name, location),
        {"name": C.norm_param(name), "location": location,
         "host": C.norm_host(host), "path": C.norm_path(path), **(attrs or {})},
        importance=5, confidence=0.9, trust="agent_asserted", status="confirmed")
    store.add_edge(eid, pid, "ACCEPTS_PARAM", confidence=0.9, trust="agent_asserted")
    return pid


def add_fact(store: Store, kind: str, canonical_key: str, attrs: Optional[dict] = None,
             profile=None, node_type: str = "finding", confirmed: bool = False,
             oracle: str = "", trust: str = "agent_asserted", severity: int = 5) -> int:
    """Domain-agnostic fact ingest: upsert a node, attach the capability tokens the
    active profile derives for `kind`, apply the verification gate, pin if
    confirmed, and mark chains dirty. The web `add_finding` is sugar over this; a
    code-review profile uses it via add_taint_* helpers. Same engine, any domain."""
    attrs = dict(attrs or {})
    attrs["kind"] = kind
    if oracle:
        attrs["oracle"] = sanitize(oracle, 500)
    attrs = {k: (sanitize(v, 2000) if isinstance(v, str) else v) for k, v in attrs.items()}

    status = "confirmed" if (confirmed and oracle and may_seed_chain(trust)) else "suspected"
    confidence = 0.9 if status == "confirmed" else 0.35
    if not may_seed_chain(trust):
        confidence = min(confidence, 0.3)

    nid = store.upsert_node(node_type, canonical_key, attrs,
                            importance=max(5, severity), confidence=confidence,
                            trust=trust, status=status, allow_revive=(status == "confirmed"))
    prov, req = caps.capabilities_for(kind, attrs, profile)
    store.set_capabilities(nid, prov, req)
    if prov:
        store.add_lesson(nid, "forward", f"{kind} provides " + ", ".join(p[0] for p in prov))
    if status == "confirmed":
        store.pin(nid)
    store.mark_dirty()
    return nid


def add_finding(store: Store, vuln_class: str, host: str = "", path: str = "/",
                param: str = "", confirmed: bool = False, oracle: str = "",
                attrs: Optional[dict] = None, trust: str = "agent_asserted",
                obs_id: Optional[int] = None, severity: int = 5, profile=None) -> int:
    """Record a WEB finding, attach its capability tokens, link it structurally, and
    mark chains dirty. VERIFICATION GATE: status=confirmed only if an oracle is
    supplied AND the source is trusted; otherwise suspected (low confidence)."""
    attrs = dict(attrs or {})
    attrs.setdefault("host", C.norm_host(host))
    attrs.setdefault("path", C.norm_path(path) if path else "")
    if param:
        attrs.setdefault("param", C.norm_param(param))
    attrs["vuln_class"] = vuln_class
    if oracle:
        attrs["oracle"] = sanitize(oracle, 500)
    # attr values may be copied from target text — sanitize before storing, since
    # they surface into the working set / prompt context later.
    attrs = {k: (sanitize(v, 2000) if isinstance(v, str) else v) for k, v in attrs.items()}

    # VERIFICATION GATE: confirmed only with an oracle AND from a trusted source
    # (target-derived text can never promote a finding to confirmed).
    status = "confirmed" if (confirmed and oracle and may_seed_chain(trust)) else "suspected"
    confidence = 0.9 if status == "confirmed" else 0.35
    if not may_seed_chain(trust):
        confidence = min(confidence, 0.3)   # target-derived never seeds at full confidence

    fid = store.upsert_node(
        "finding", C.finding_key(vuln_class, host, path, param), attrs,
        importance=max(5, severity), confidence=confidence, trust=trust, status=status,
        allow_revive=(status == "confirmed"))   # a re-observation with an oracle can revive

    # structural links to endpoint/param (provenance)
    if host:
        eid = ensure_endpoint(store, host, path)
        store.add_edge(fid, eid, "VULNERABLE_TO", confidence=confidence, trust=trust)
        if param:
            pid = ensure_param(store, host, path, param)
            store.add_edge(pid, fid, "MENTIONS", confidence=confidence, trust=trust)

    # capability tokens from typed extractors (never from target text)
    prov, req = caps.capabilities_for(vuln_class, attrs, profile)
    store.set_capabilities(fid, prov, req)

    # dual record: forward lesson seeding chain hypotheses
    if prov:
        store.add_lesson(fid, "forward",
                         f"{vuln_class} provides " + ", ".join(p[0] for p in prov))

    # pin confirmed findings (never forgotten) and trigger detection
    if status == "confirmed":
        store.pin(fid)
    store.mark_dirty()   # lazy: detected on chains()/reflect()
    return fid


def add_technique_rule(store: Store, name: str, provides: list, requires: list,
                       confirmed: bool = True, attrs: Optional[dict] = None) -> int:
    """Add a reusable technique/rule node (e.g. the cloud-metadata step) that
    carries capabilities and participates in chains. Confirmed rules are pinned."""
    nid = store.upsert_node(
        "technique", C._key("technique", name),
        {"name": name, **(attrs or {})},
        importance=6, confidence=0.9 if confirmed else 0.4,
        trust="agent_asserted", status="confirmed" if confirmed else "suspected")
    store.set_capabilities(nid, provides, requires)
    if confirmed:
        store.pin(nid)
    return nid


def add_credential(store: Store, vault, kind: str, subject: str, value: str = "",
                   provides_tokens: Optional[list] = None,
                   obs_id: Optional[int] = None) -> tuple[int, str]:
    """Store a credential: value goes to the vault (by handle), the graph node
    holds the handle + provides tokens (e.g. session_token{subject}). Pinned."""
    handle = vault.put(value, kind=kind, subject=subject, acquired_obs=obs_id) if value else ""
    nid = store.upsert_node(
        "credential", C._key("credential", kind, subject, handle or value),
        {"kind": kind, "subject": subject, "handle": handle, "valid": True},
        importance=8, confidence=0.95, trust="tool_verified", status="confirmed")
    tokens = provides_tokens or [("session_token", {"subject": subject})]
    store.set_capabilities(nid, tokens, [])
    store.pin(nid)
    store.mark_dirty()   # lazy: detected on chains()/reflect()
    return nid, handle


def note_payload(store: Store, host: str, path: str, param: str, template: str,
                 value: str, outcome: str, success: bool, method: str = "GET",
                 obs_id: Optional[int] = None) -> int:
    """Record a payload attempt + outcome (incl. FAILURES = negative memory) and
    a Reflexion-style lesson so a dead payload is never retried after a restart."""
    eid = ensure_endpoint(store, host, path, method) if host else None
    pid = ensure_param(store, host, path, param, method) if (host and param) else None
    pay = store.add_payload(None, eid, pid, template, value, outcome, success, obs_id)
    if not success and pid:
        store.add_lesson(pid, "failure",
                         f"payload '{template}' failed on {param} ({outcome}); do not retry verbatim")
    return pay


def already_tried(store: Store, host: str, path: str, param: str,
                  template: str, method: str = "GET") -> bool:
    """Negative-memory check: has this payload template already been tried here?"""
    if not host:
        return False
    eid = store.find_node("endpoint", C.endpoint_key(method, host, path))
    if not eid:
        return False
    for p in store.payloads_for(eid["id"]):
        if p["template"] == template:
            return True
    return False
