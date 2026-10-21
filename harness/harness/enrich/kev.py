"""
harness.enrich.kev — CISA Known Exploited Vulnerabilities catalog.

KEV is a hard, authoritative override: if a CVE is on it, it has been observed
exploited in the wild and remains on CISA's catalog. In prioritization this is a
boolean that trumps model scores (§7). The catalog is one JSON file, refreshed
roughly daily.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import json
import os
import logging
import time
from typing import Optional

try:
    import requests
except ImportError:
    requests = None                      # type: ignore

_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
         "known_exploited_vulnerabilities.json")
_log = logging.getLogger(__name__)


class KevCatalog:
    def __init__(self, cache_path: str = ".cache/kev.json", ttl_hours: float = 24,
                 timeout: float = 30):
        self.cache_path = cache_path
        self.ttl = ttl_hours * 3600
        self.timeout = timeout
        self._cves: set[str] = set()
        self._fetched: float = 0.0
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path) as fh:
                    blob = json.load(fh)
                self._cves = set(blob.get("cves", []))
                self._fetched = blob.get("_fetched", 0.0)
            except (OSError, json.JSONDecodeError):
                pass

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        tmp = self.cache_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"cves": sorted(self._cves), "_fetched": self._fetched}, fh)
        os.replace(tmp, self.cache_path)

    def refresh(self, now: Optional[float] = None, force: bool = False) -> bool:
        """Fetch the catalog if stale. Returns True if data is available."""
        now = now if now is not None else time.time()
        # back off within the TTL whether the last attempt succeeded OR failed,
        # so an empty/unreachable catalog isn't re-fetched on every call.
        if not force and (now - self._fetched) < self.ttl:
            return bool(self._cves)
        if requests is None:
            return bool(self._cves)
        self._fetched = now               # record the attempt (success or not)
        try:
            resp = requests.get(_FEED, timeout=self.timeout, allow_redirects=False)
            resp.raise_for_status()
            data = resp.json()
            self._cves = {v["cveID"].upper() for v in data.get("vulnerabilities", [])
                          if v.get("cveID")}
            self._save()
        except requests.RequestException as e:   # transport only — fail soft
            _log.warning("KEV fetch failed, using cache: %s", e)
        return bool(self._cves)

    def contains(self, cve: str) -> bool:
        # refresh() self-throttles via the TTL, so this won't hammer the network
        if not self._cves and (time.time() - self._fetched) >= self.ttl:
            self.refresh()
        return bool(cve) and cve.upper() in self._cves

    def __len__(self) -> int:
        return len(self._cves)

    # for tests / offline seeding
    def seed(self, cves: list[str], now: Optional[float] = None) -> None:
        self._cves = {c.upper() for c in cves}
        self._fetched = now if now is not None else time.time()
