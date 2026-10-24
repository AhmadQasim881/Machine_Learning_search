"""
agentmem — persistent, chain-finding memory for an autonomous web bug-bounty agent.

Synthesized from 28 agent-memory papers. The backbone is a typed knowledge graph
in SQLite; multi-step exploit chains are found by a deterministic capability
(precondition -> postcondition) planner — no LLM or embeddings required for the
core. See README.md and docs for the design and its provenance.

Quick start:
    from agentmem import Memory
    m = Memory("campaign.db")
    m.add_finding("open_redirect", host="app.target.com", path="/out",
                  param="url", confirmed=True, oracle="302",
                  attrs={"host": "app.target.com"})
    ...
    for ch in m.chains():
        print(ch["severity"], ch["narrative"])
"""
__version__ = "0.3.0"

from .memory import Memory  # noqa: F401
from .profiles import CODEREVIEW, WEB, Profile  # noqa: F401
from .research import ResearchMemory  # noqa: F401
from .store import Store    # noqa: F401
