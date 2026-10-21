"""
harness.enrich.epss — EPSS (Exploit Prediction Scoring System) client.

EPSS gives a daily-updated probability (0..1) that a CVE will be exploited in the
next 30 days, plus a percentile. It is the CVE-level exploit-likelihood signal
the design says to ADOPT rather than reproduce (the model's training set is not
public). Your finding-level model (the real IP) fuses this with KEV + PoC
evidence; see harness.prioritize.

API: https://api.first.org/data/v1/epss?cve=CVE-xxed,CVE-yyyy  (batchable, no key)
"""
from __future__ import annotations

import json
import os
import time
from typing import Iterable, Optional

try:
    import requests
except ImportError:                      # requests is an optional dependency
    requests = None                      # type: ignore

_API = "https://api.first.org/data/v1/epss"
_BATCH = 100


class EpssClient:
    def __init__(self, cache_path: str = ".cache/epss.json", ttl_hours: float = 24,
                 timeout: float = 20):
        self.cache_path = cache_path
        self.ttl = ttl_hours * 3600
        self.timeout = timeout
        self._cache: dict[str, dict] = {}
        self._load()

    # ---- cache ----------------------------------------------------------- #
    def _load(self) -> None:
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path) as fh:
                    self._cache = json.load(fh)
            except (OSError, json.JSONDecodeError):
                self._cache = {}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        tmp = self.cache_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(self._cache, fh)
        os.replace(tmp, self.cache_path)

    def _fresh(self, cve: str, now: float) -> Optional[dict]:
        rec = self._cache.get(cve)
        if rec and (now - rec.get("_fetched", 0)) < self.ttl:
            return rec
        return None

    # ---- fetch ----------------------------------------------------------- #
    def scores(self, cves: Iterable[str], now: Optional[float] = None) -> dict[str, dict]:
        """Return {cve: {"epss": float, "percentile": float}} for the given CVEs.

        Serves from cache when fresh; fetches the rest in batches. On any network
        error (or if `requests` is missing) returns whatever is cached and logs
        nothing — callers treat a missing CVE as "no EPSS signal".
        """
        now = now if now is not None else time.time()
        want = {c.upper() for c in cves if c}
        out: dict[str, dict] = {}
        missing = []
        for c in want:
            fresh = self._fresh(c, now)
            if fresh:
                out[c] = {"epss": fresh["epss"], "percentile": fresh["percentile"]}
            else:
                missing.append(c)

        if missing and requests is not None:
            for i in range(0, len(missing), _BATCH):
                chunk = missing[i:i + _BATCH]
                try:
                    resp = requests.get(_API, params={"cve": ",".join(chunk)},
                                        timeout=self.timeout)
                    resp.raise_for_status()
                    for row in resp.json().get("data", []):
                        cve = row.get("cve", "").upper()
                        rec = {"epss": float(row.get("epss", 0.0)),
                               "percentile": float(row.get("percentile", 0.0)),
                               "_fetched": now}
                        self._cache[cve] = rec
                        out[cve] = {"epss": rec["epss"], "percentile": rec["percentile"]}
                except Exception:
                    break        # fail soft — keep whatever we have
            self._save()
        return out

    def score(self, cve: str) -> Optional[dict]:
        return self.scores([cve]).get(cve.upper())
