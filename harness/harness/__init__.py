"""
web-bugbounty-harness — the triage "brain" of an AUTHORIZED web bug-bounty
testing pipeline.

Implemented: a normalized multi-label-ready finding record, ingest adapters, a
keyword + trainable CWE classifier behind a confidence gate, an offline CVSS
v3.1 calculator (+ CWE->CVSS priors), EPSS/KEV/NVD enrichment, transparent
prioritization, temporal-split evaluation, and a DefectDojo exporter. The
detection ("hands") stages, a learned finding-level exploit-likelihood model,
near-duplicate clustering, and scope/ROE enforcement remain documented gaps.

Use only against targets you are authorized to test.
"""
__version__ = "0.2.0"

from .schema import (Authorization, CvssScore, CweAssignment, Exploit,  # noqa: F401
                     Finding, Status)
from .store import Store  # noqa: F401
