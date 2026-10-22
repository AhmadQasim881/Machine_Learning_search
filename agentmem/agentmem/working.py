"""
agentmem.working — the persisted working set + rehydrate-on-restart (spec §5).

MemGPT-style tiering: a hot working set lives in RAM and is mirrored to the
`working_set` table so it survives process restarts. `rehydrate()` rebuilds it at
run start from durable state: the campaign clock, in-scope hosts/endpoints, all
pinned nodes (creds/confirmed findings/chains), open hypotheses with their
next-probe queue, the target portrait summary, and recent observations.
"""
from __future__ import annotations

import json
from typing import Any

from .store import Store


class WorkingMemory:
    def __init__(self, store: Store):
        self.store = store

    def set(self, key: str, value: Any) -> None:
        self.store.set_working(key, value)

    def get(self, key: str, default=None):
        return self.store.get_working(key, default)

    def rehydrate(self) -> dict:
        """Rebuild and return the working set from durable storage. Deterministic:
        the same campaign.db always rehydrates to the same working set."""
        s = self.store
        ws: dict = {"step": s.step}

        ws["targets"] = [dict(id=r["id"], **json.loads(r["attrs_json"]))
                         for r in s.nodes_by_type("target")]
        ws["hosts"] = [dict(id=r["id"], **json.loads(r["attrs_json"]))
                       for r in s.nodes_by_type("host")]

        ws["pinned"] = [{"id": r["id"], "type": r["type"], "status": r["status"],
                         "attrs": json.loads(r["attrs_json"])}
                        for r in s.pinned_nodes()]

        ws["chains"] = []
        for c in s.chains():
            steps = [cs["node_id"] for cs in s.chain_steps(c["id"])]
            ws["chains"].append({"id": c["id"], "goal": c["goal"], "score": c["score"],
                                 "severity": c["severity"], "status": c["status"],
                                 "narrative": c["narrative"], "steps": steps})

        ws["recent_observations"] = [
            {"id": r["id"], "step": r["step"], "request": r["request"]}
            for r in s.conn.execute(
                "SELECT id,step,request FROM observations ORDER BY id DESC LIMIT 20").fetchall()]

        # persist the rehydrated set so it is inspectable/restorable
        s.set_working("rehydrated", {"step": s.step, "n_pinned": len(ws["pinned"]),
                                     "n_chains": len(ws["chains"])})
        return ws
