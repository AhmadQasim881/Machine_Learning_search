"""
agentmem.memory — the Memory facade: the ONLY API the agent needs.

Wires together the store, secrets vault, write pipeline, retrieval, chain engine,
forgetting, and the persisted working set. A bug-bounty agent calls:

    m = Memory("campaign.db")
    m.observe(request, response)                       # log raw traffic (lossless)
    m.add_finding("open_redirect", host=..., param=..., confirmed=True, oracle="302")
    m.add_credential("session", subject="userB", value="...")
    chains = m.chains()                                # discovered exploit chains
    probes = m.next_probes()                           # what to try next to complete one
    hits   = m.recall(type="finding", host=...)        # ranked recall
    m.reflect(); m.close()                             # pin verified assets, persist

Everything persists to SQLite and reloads with rehydrate() after a restart.
"""
from __future__ import annotations

from typing import Optional

from . import chains as chainmod
from . import forget
from . import retrieve
from . import write
from .security import SecretsVault
from .store import Store
from .working import WorkingMemory


class Memory:
    def __init__(self, path: str = "campaign.db"):
        self.store = Store(path)
        self.vault = SecretsVault(self.store)
        self.working = WorkingMemory(self.store)

    # ---- lifecycle ------------------------------------------------------- #
    def tick(self) -> int:
        """Advance the campaign clock (one agent step)."""
        return self.store.tick()

    def rehydrate(self) -> dict:
        """Rebuild the working set after a restart."""
        return self.working.rehydrate()

    def close(self) -> None:
        self.store.close()

    def __enter__(self) -> "Memory":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- write ----------------------------------------------------------- #
    def observe(self, request: str, response: str = "",
                trust: str = "target_derived", source: str = "http") -> int:
        return write.observe(self.store, request, response, trust, source)

    def set_target(self, program: str, in_scope: list, out_scope: Optional[list] = None) -> int:
        from . import canonical as C
        return self.store.upsert_node(
            "target", C._key("target", program),
            {"program": program, "in_scope": in_scope, "out_scope": out_scope or []},
            importance=9, confidence=1.0, trust="agent_asserted", status="confirmed")

    def add_finding(self, vuln_class: str, host: str = "", path: str = "/",
                    param: str = "", confirmed: bool = False, oracle: str = "",
                    attrs: Optional[dict] = None, trust: str = "agent_asserted",
                    severity: int = 5) -> int:
        return write.add_finding(self.store, vuln_class, host, path, param,
                                 confirmed, oracle, attrs, trust, severity=severity)

    def add_technique_rule(self, name: str, provides: list, requires: list,
                           confirmed: bool = True, attrs: Optional[dict] = None) -> int:
        return write.add_technique_rule(self.store, name, provides, requires, confirmed, attrs)

    def add_credential(self, kind: str, subject: str, value: str = "",
                       provides_tokens: Optional[list] = None) -> tuple[int, str]:
        return write.add_credential(self.store, self.vault, kind, subject, value, provides_tokens)

    def note_payload(self, host: str, path: str, param: str, template: str,
                     value: str, outcome: str, success: bool, method: str = "GET") -> int:
        return write.note_payload(self.store, host, path, param, template, value,
                                  outcome, success, method)

    def already_tried(self, host: str, path: str, param: str, template: str,
                      method: str = "GET") -> bool:
        return write.already_tried(self.store, host, path, param, template, method)

    # ---- read ------------------------------------------------------------ #
    def recall(self, type: Optional[str] = None, host: Optional[str] = None,
               vuln_class: Optional[str] = None, limit: int = 20,
               seed_node: Optional[int] = None) -> list[dict]:
        return retrieve.recall(self.store, type=type, host=host, vuln_class=vuln_class,
                               limit=limit, seed_node=seed_node)

    def chains(self) -> list[dict]:
        """Discovered exploit chains, highest severity first, with cited steps."""
        chainmod.detect(self.store)
        out = []
        for c in self.store.chains():
            steps = []
            for cs in self.store.chain_steps(c["id"]):
                a = self.store.node_attrs(cs["node_id"])
                steps.append({"node_id": cs["node_id"],
                              "label": a.get("vuln_class") or a.get("name") or "node",
                              "host": a.get("host", ""), "path": a.get("path", "")})
            out.append({"id": c["id"], "goal": c["goal"], "severity": c["severity"],
                        "score": c["score"], "status": c["status"],
                        "narrative": c["narrative"], "steps": steps})
        return out

    def next_probes(self) -> list[dict]:
        """Goal-directed: the missing capabilities that would complete a chain."""
        return chainmod.next_probes(self.store)

    # ---- maintenance ----------------------------------------------------- #
    def pin(self, node_id: int) -> None:
        self.store.pin(node_id)

    def invalidate(self, node_id: int, reason: str = "") -> None:
        forget.soft_invalidate(self.store, node_id, reason)

    def reflect(self) -> dict:
        """Consolidation pass: pin verified assets (never-forget) + re-detect
        chains. (LLM summarization/insight curation plug in here when configured.)"""
        pinned = forget.auto_pin(self.store)
        chainmod.detect(self.store)
        return {"pinned": pinned, "chains": len(self.store.chains())}

    def export(self) -> dict:
        """Full inspectable snapshot of the memory (for debugging/reporting)."""
        s = self.store
        return {
            "step": s.step,
            "nodes": {t: len(s.nodes_by_type(t))
                      for t in ("target", "host", "endpoint", "param", "tech",
                                "finding", "credential", "technique")},
            "chains": self.chains(),
            "next_probes": self.next_probes(),
        }
