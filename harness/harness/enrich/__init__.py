"""
External enrichment feeds for Stage 7 prioritization (and Stage 6 for known CVEs).

These pull from the internet at runtime, so they are the one part of the harness
that needs outbound access when YOU run it:
  - EPSS  (api.first.org)            -> P(exploited in 30 days), per CVE
  - KEV   (cisa.gov)                 -> known-exploited boolean override
  - NVD   (services.nvd.nist.gov)    -> official CVSS vector + CWE for a CVE

All three cache to disk and fail soft (return empty / None) when offline, so the
rest of the pipeline still runs. `requests` is the only extra dependency.
"""
from .epss import EpssClient          # noqa: F401
from .kev import KevCatalog           # noqa: F401
from .nvd import NvdClient            # noqa: F401
