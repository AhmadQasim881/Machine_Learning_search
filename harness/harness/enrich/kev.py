"""
harness.enrich.kev — CISA Known Exploited Vulnerabilities catalog.

KEV is a hard, authoritative override: if a CVE is on it, it is being exploited
in the wild NOW. In prioritization this is a boolean that trumps model scores
(§7). The catalog is one JSON file, refreshed roughly daily.

Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import json
import os
import time
from typing import Optional

try:
    import requests
except ImportError:
    requests = None                      # type: ignore

_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
         "known_exploited_vulnerabilities.json")


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
        if not force and self._cves and (now - self._fetched) < self.ttl:
            return True
        if requests is None:
            return bool(self._cves)
        try:
            resp = requests.get(_FEED, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            self._cves = {v["cveID"].upper() for v in data.get("vulnerabilities", [])
                          if v.get("cveID")}
            self._fetched = now
            self._save()
        except Exception:
            pass                          # fail soft — keep cached set
        return bool(self._cves)

    def contains(self, cve: str) -> bool:
        if not self._cves:
            self.refresh()
        return bool(cve) and cve.upper() in self._cves

    def __len__(self) -> int:
        return len(self._cves)

    # for tests / offline seeding
    def seed(self, cves: list[str], now: Optional[float] = None) -> None:
        self._cves = {c.upper() for c in cves}
        self._fetched = now if now is not None else time.time()
