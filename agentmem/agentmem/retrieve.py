"""
agentmem.retrieve — hybrid retrieval with composite reranking (spec §3.2).

Two retrievers (exact SQL + graph BFS) carry the core; an optional semantic
retriever plugs in when an embedding provider is configured. Results are fused
and reranked by the Generative-Agents composite score (relevance + importance +
recency-in-STEPS + confidence), with pinned nodes floored so verified assets are
never buried. Retrieval bumps `last_access_step` (reconsolidation).
"""
from __future__ import annotations

import json
import math
from typing import Optional

from . import config
from .store import Store


def _recency(store: Store, node) -> float:
    last = node["last_access_step"] if node["last_access_step"] is not None else node["created_step"] or 0
    return math.exp(-config.RECENCY_LAMBDA * max(0, store.step - last))


def composite_score(store: Store, node, relevance: float = 0.0) -> float:
    s = (config.W_RELEVANCE * relevance
         + config.W_IMPORTANCE * (node["importance"] / 10.0)
         + config.W_RECENCY * _recency(store, node)
         + config.W_CONFIDENCE * (node["confidence"] or 0.0))
    if node["pinned"]:
        s = max(s, config.PIN_FLOOR)
    return round(s, 4)


def exact(store: Store, type: Optional[str] = None, host: Optional[str] = None,
          vuln_class: Optional[str] = None) -> list:
    """Exact structured lookup by type/host/vuln_class (answers 'all params on
    host X', 'all confirmed findings', ...)."""
    q = "SELECT * FROM nodes WHERE status!='invalidated'"
    args: list = []
    if type:
        q += " AND type=?"; args.append(type)
    rows = store.conn.execute(q, args).fetchall()
    out = []
    for r in rows:
        a = json.loads(r["attrs_json"])
        if host and a.get("host") != host:
            continue
        if vuln_class and a.get("vuln_class") != vuln_class:
            continue
        out.append(r)
    return out


def graph_neighbors(store: Store, node_id: int, hops: int = 2,
                    rel_types: Optional[set] = None) -> list[int]:
    """BFS from a node over typed edges — the read-time 'pull everything
    reachable from what I just found' primitive (half of chain discovery)."""
    seen = {node_id}
    frontier = [node_id]
    order: list[int] = []
    for _ in range(hops):
        nxt = []
        for nid in frontier:
            for e in store.edges_from(nid):
                if rel_types and e["rel_type"] not in rel_types:
                    continue
                if e["dst_id"] not in seen:
                    seen.add(e["dst_id"]); nxt.append(e["dst_id"]); order.append(e["dst_id"])
        frontier = nxt
        if not frontier:
            break
    return order


def recall(store: Store, type: Optional[str] = None, host: Optional[str] = None,
           vuln_class: Optional[str] = None, limit: int = 20,
           seed_node: Optional[int] = None) -> list[dict]:
    """Hybrid recall: exact candidates (+ graph neighbors of a seed), reranked by
    the composite score. Returns [{node_id, type, score, attrs}]."""
    cand = {r["id"]: r for r in exact(store, type=type, host=host, vuln_class=vuln_class)}
    if seed_node is not None:
        for nid in graph_neighbors(store, seed_node):
            r = store.get_node(nid)
            if r and r["status"] != "invalidated":
                cand.setdefault(nid, r)
    scored = []
    for r in cand.values():
        store.touch(r["id"])
        scored.append({"node_id": r["id"], "type": r["type"],
                       "score": composite_score(store, r),
                       "status": r["status"], "pinned": bool(r["pinned"]),
                       "attrs": json.loads(r["attrs_json"])})
    scored.sort(key=lambda d: d["score"], reverse=True)
    return scored[:limit]
