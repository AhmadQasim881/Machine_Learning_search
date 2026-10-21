"""
web-bugbounty-harness — a scaffold for the triage "brain" of an AUTHORIZED
web bug-bounty testing pipeline.

Scope of THIS scaffold: schema + ingest + CWE-classifier stub + the confidence
gate + a SQLite store + a CLI. The detection ("hands") stages, real ML models,
CVSS scorer, exploit-likelihood, dedup/cluster and report generator are
explicitly stubs/gaps documented in README and the design guide.

Use only against targets you are authorized to test.
"""
__version__ = "0.1.0"

from .schema import (Authorization, CvssScore, CweAssignment, Exploit,  # noqa: F401
                     Finding, Status)
from .store import Store  # noqa: F401
