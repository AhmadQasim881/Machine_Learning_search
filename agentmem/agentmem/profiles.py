"""
agentmem.profiles — domain profiles over one engine.

The engine (store, chains, retrieve, forget, working, security) is domain-agnostic.
A `Profile` supplies the DOMAIN knowledge: the capability ontology (what facts
provide/require), the escalation rules + goal severities, how to label a node in a
chain narrative, and a canonical-key helper. Swapping the profile retargets the
whole memory to a new domain — same graph, same chain engine.

Shipped profiles:
  - WEB  — web bug-bounty (open-redirect/IDOR/SSRF/… -> token-theft/ATO/priv-esc).
  - CODEREVIEW — source-code taint analysis (source -> propagator -> sink -> rce/
    sqli/…). Proves domain-independence: a data-flow path is the SAME capability
    chain (source `provides tainted{var}`, sink `requires tainted{var}`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import canonical as C
from . import config


@dataclass
class Profile:
    name: str
    provides: dict          # kind -> (attrs) -> list[(token, attrs)]
    requires: dict          # kind -> (attrs) -> list[(token, attrs)]
    escalation_rules: list  # [{goal, need:[(token, attrs)]}]
    goal_severity: dict     # goal -> int
    label: Optional[Callable] = None   # (attrs, node_type) -> str

    def label_for(self, attrs: dict, node_type: str) -> str:
        if self.label:
            return self.label(attrs, node_type)
        return attrs.get("vuln_class") or attrs.get("name") or node_type


# --------------------------------------------------------------------------- #
# WEB profile — the current web bug-bounty ontology (backed by config.py)
# --------------------------------------------------------------------------- #
def _web_label(attrs: dict, node_type: str) -> str:
    return attrs.get("vuln_class") or attrs.get("name") or node_type


WEB = Profile(
    name="web",
    provides=config.PROVIDES,
    requires=config.REQUIRES,
    escalation_rules=config.ESCALATION_RULES,
    goal_severity=config.GOAL_SEVERITY,
    label=_web_label,
)


# --------------------------------------------------------------------------- #
# CODEREVIEW profile — taint analysis on the identical engine
# --------------------------------------------------------------------------- #
# A data-flow vulnerability IS a capability chain:
#   source   provides tainted{var=a}
#   propagator  requires tainted{var=a}, provides tainted{var=b}
#   sink     requires tainted{var=b}, provides a GOAL token (by sink kind)
# A sanitizer that cleans a var simply does not re-provide its taint (breaking
# the chain). Goals map from the sink kind (sql->full_db_read, exec->rce, ...).

_SINK_GOAL = {
    "sql": "full_db_read", "exec": "rce", "command": "rce", "eval": "rce",
    "deserialize": "rce", "ssrf": "ssrf_exec", "path": "file_read",
    "xss": "xss_exec", "ldap": "injection", "generic": "injection",
}

_CR_GOAL_SEVERITY = {
    "rce": 10, "full_db_read": 9, "ssrf_exec": 7, "file_read": 7,
    "xss_exec": 6, "injection": 6,
}


def _cr_provides_source(a):
    return [("tainted", {"var": a.get("var", "*")})]


def _cr_provides_prop(a):
    return [("tainted", {"var": a.get("var_out", a.get("var", "*"))})]


def _cr_provides_sink(a):
    goal = _SINK_GOAL.get(a.get("sink_type", "generic"), "injection")
    return [(goal, {"sink": a.get("sink_type", "generic")})]


def _cr_requires_prop(a):
    return [("tainted", {"var": a.get("var_in", "*")})]


def _cr_requires_sink(a):
    return [("tainted", {"var": a.get("var", "*")})]


# a trivial escalation per goal: the sink's own provided goal token IS the goal
_CR_ESCALATION = [{"goal": g, "need": [(g, {})]} for g in _CR_GOAL_SEVERITY]


def _cr_label(attrs: dict, node_type: str) -> str:
    kind = attrs.get("kind", node_type)
    loc = attrs.get("file", "")
    if attrs.get("line"):
        loc = f"{loc}:{attrs['line']}"
    sym = attrs.get("symbol") or attrs.get("var", "")
    return f"{kind}({sym})" + (f" @ {loc}" if loc else "")


CODEREVIEW = Profile(
    name="codereview",
    provides={
        "taint_source": _cr_provides_source,
        "taint_prop": _cr_provides_prop,
        "taint_sink": _cr_provides_sink,
    },
    requires={
        "taint_prop": _cr_requires_prop,
        "taint_sink": _cr_requires_sink,
    },
    escalation_rules=_CR_ESCALATION,
    goal_severity=_CR_GOAL_SEVERITY,
    label=_cr_label,
)


def cr_key(kind: str, file: str, symbol: str = "", var: str = "", line: int = 0) -> str:
    """Canonical key for a code-review fact (file + symbol/var + line)."""
    return C._key("cr", kind, (file or "").lower(), symbol or "", var or "", str(line or 0))


def get(name: str) -> Profile:
    return {"web": WEB, "codereview": CODEREVIEW}.get(name, WEB)
