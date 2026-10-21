"""
harness.enrich.nvd — minimal NVD 2.0 client for KNOWN-CVE findings.

When a finding already references a CVE (e.g. nuclei matched a known n-day), you
should NOT predict its CWE/CVSS — pull the official values from NVD (§5 build
plan: "for findings that match a known CVE, just pull the NVD vector"). This
client fetches the CVSS v3.1 vector and the mapped CWE(s) for a CVE id.

API: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-xxxx
An API key is optional but strongly raises the rate limit; pass it or set
NVD_API_KEY. Cached + fail-soft like the other feeds.
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

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdClient:
    def __init__(self, cache_path: str = ".cache/nvd.json", ttl_hours: float = 168,
                 api_key: Optional[str] = None, timeout: float = 30):
        self.cache_path = cache_path
        self.ttl = ttl_hours * 3600
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.timeout = timeout
        self._cache: dict[str, dict] = {}
        self._load()

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

    def lookup(self, cve: str, now: Optional[float] = None) -> Optional[dict]:
        """Return {"cvss_vector","cvss_score","severity","cwes":[...],"description"}
        for a CVE, or None if unavailable. Cached + fail-soft."""
        now = now if now is not None else time.time()
        cve = cve.upper()
        rec = self._cache.get(cve)
        if rec and (now - rec.get("_fetched", 0)) < self.ttl:
            return rec
        if requests is None:
            return rec
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            resp = requests.get(_API, params={"cveId": cve}, headers=headers,
                                timeout=self.timeout)
            resp.raise_for_status()
            parsed = self._parse(resp.json())
            if parsed is not None:
                parsed["_fetched"] = now
                self._cache[cve] = parsed
                self._save()
            return parsed
        except Exception:
            return rec

    @staticmethod
    def _parse(payload: dict) -> Optional[dict]:
        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            return None
        cve = vulns[0].get("cve", {})
        # description (English)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        # CVSS v3.1 (fall back to v3.0)
        metrics = cve.get("metrics", {})
        vector = score = severity = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if metrics.get(key):
                data = metrics[key][0].get("cvssData", {})
                vector = data.get("vectorString", "")
                score = data.get("baseScore")
                severity = data.get("baseSeverity", "").capitalize()
                break
        # CWEs
        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.upper().startswith("CWE-"):
                    cwes.append(val.upper())
        return {"cvss_vector": vector, "cvss_score": score, "severity": severity,
                "cwes": sorted(set(cwes)), "description": desc}
