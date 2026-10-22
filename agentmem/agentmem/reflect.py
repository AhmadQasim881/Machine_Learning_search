"""
agentmem.reflect — scheduled consolidation (spec §3.3).

Deterministic, LLM-free consolidation run from Memory.reflect():
  - materialize_hypotheses: persist the backward-chaining "next probe" queue as
    `hypothesis` nodes so it survives restarts (rehydrate step 4), and mark a
    hypothesis resolved once a live chain reaches its goal.
  - build_portraits: a per-host structured "portrait" summary (tech, endpoints,
    confirmed findings, chains) written to the summaries table — a compact index
    layer over the lossless graph (never ground truth).

(LLM-based summarization / ExpeL insight curation plug in on top of these.)
"""
from __future__ import annotations

import json

from . import canonical as C
from . import chains as chainmod
from . import config
from . import embeddings as emb
from .store import Store


def link_synonyms(store: Store, threshold: float = config.SAME_AS_THRESHOLD) -> int:
    """Advisory SAME_AS edges between same-type nodes with high embedding
    similarity. Conservative threshold; provenance kept; NEVER merges nodes and
    chains never traverse SAME_AS (scoping-critical — spec §4.2). Needs embeddings."""
    made = 0
    for ntype in ("endpoint", "param", "finding"):
        vecs = []
        for r in store.nodes_with_embeddings(type=ntype):
            try:
                vecs.append((r["id"], emb.from_blob(r["embedding"])))
            except Exception:   # noqa: BLE001
                continue
        for i in range(len(vecs)):
            for j in range(i + 1, len(vecs)):
                sim = emb.cosine(vecs[i][1], vecs[j][1])
                if sim >= threshold:
                    store.add_edge(vecs[i][0], vecs[j][0], "SAME_AS",
                                   attrs={"cosine": round(sim, 3)}, weight=sim,
                                   confidence=sim, trust="llm_inferred",
                                   provenance=[vecs[i][0], vecs[j][0]])
                    made += 1
    return made


def materialize_hypotheses(store: Store, profile=None) -> int:
    """Persist next-probe suggestions as hypothesis nodes; resolve any whose goal
    a live chain now reaches."""
    probes = chainmod.next_probes(store, profile)
    live_goals = {c["goal"] for c in store.chains() if c["status"] != "invalidated"}
    made = 0
    for p in probes:
        key = C._key("hyp", p["goal"], p["missing_capability"],
                     json.dumps(p["constraints"], sort_keys=True))
        store.upsert_node(
            "hypothesis", key,
            {"goal": p["goal"], "missing_capability": p["missing_capability"],
             "constraints": p["constraints"], "suggestion": p["suggestion"],
             "state": "open"},
            importance=p["severity"], confidence=0.5, status="suspected")
        made += 1
    for h in store.nodes_by_type("hypothesis"):
        a = store.node_attrs(h["id"])
        if a.get("state") == "open" and a.get("goal") in live_goals:
            store.update_node(h["id"], attrs={"state": "resolved"})
    return made


def build_portraits(store: Store, profile=None) -> int:
    """One structured per-host portrait summary. Deterministic (no LLM)."""
    # group findings/endpoints/params by host in a single pass each
    def by_host(node_type):
        out: dict[str, list] = {}
        for r in store.nodes_by_type(node_type):
            a = json.loads(r["attrs_json"])
            out.setdefault(a.get("host", ""), []).append((r, a))
        return out

    endpoints = by_host("endpoint")
    findings = by_host("finding")
    techs = {}
    for r in store.nodes_by_type("tech"):
        a = json.loads(r["attrs_json"])
        techs.setdefault(a.get("host", ""), []).append(a.get("name", "?"))

    chains = store.chains()
    n = 0
    for r in store.nodes_by_type("host"):
        a = json.loads(r["attrs_json"])
        hn = a.get("hostname", "")
        eps = endpoints.get(hn, [])
        fnd = findings.get(hn, [])
        confirmed = [fa for (fr, fa) in fnd if fr["status"] == "confirmed"]
        rel_chains = [c for c in chains if c["status"] != "invalidated"
                      and hn in (c["narrative"] or "")]
        lines = [f"Host {hn}"]
        if techs.get(hn):
            lines.append("  tech: " + ", ".join(sorted(set(techs[hn]))))
        lines.append(f"  endpoints: {len(eps)}  findings: {len(fnd)} "
                     f"({len(confirmed)} confirmed)")
        for fa in confirmed[:8]:
            lines.append(f"  - {fa.get('vuln_class', '?')} @ {fa.get('path', '')}")
        for c in rel_chains[:5]:
            lines.append(f"  * chain [sev {c['severity']}] {c['goal']}")
        store.set_summary("host", hn, 0, "\n".join(lines))
        n += 1
    return n
