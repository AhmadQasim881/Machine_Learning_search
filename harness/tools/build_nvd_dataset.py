#!/usr/bin/env python3
"""
build_nvd_dataset.py — build a real CVE->CWE training set from NVD.

The shipped samples/cwe_training_sample.jsonl is SYNTHETIC (templated) and will
score ~perfectly — it only exercises the code. For real results, build a dataset
from NVD with this script, then `harness train` / `harness evaluate` on it. On
real data expect ~70-80% and a visible temporal-split drop (the design's point).

Needs internet + `requests`. An NVD API key (env NVD_API_KEY) raises the rate
limit a lot; without one, NVD throttles to ~5 requests / 30s, so this paginates
slowly and politely. Run it on YOUR machine (this cloud session has no outbound
access to NVD).

    python tools/build_nvd_dataset.py --out nvd_cwe.jsonl --max 20000

Output: JSONL of {"text": <CVE description>, "cwe": "CWE-nn", "date": "YYYY-MM-DD"}
keeping only CVEs with a single concrete CWE (drops NVD-CWE-noinfo/Other and
multi-CWE rows for a clean single-label training set; adapt if you want multi).
"""
from __future__ import annotations

import argparse
import json
import sys
import time

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000  # NVD max resultsPerPage


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--max", type=int, default=20000, help="max CVEs to collect")
    ap.add_argument("--api-key", default=None, help="NVD API key (or env NVD_API_KEY)")
    args = ap.parse_args()

    try:
        import os
        import requests
    except ImportError:
        print("needs requests: pip install requests", file=sys.stderr)
        return 1

    key = args.api_key or os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    delay = 0.8 if key else 6.5  # politeness / rate limit

    kept = 0
    start = 0
    with open(args.out, "w", encoding="utf-8") as out:
        while kept < args.max:
            params = {"resultsPerPage": PAGE, "startIndex": start}
            try:
                r = requests.get(API, params=params, headers=headers, timeout=60)
                r.raise_for_status()
            except Exception as e:  # noqa: BLE001
                print(f"[!] fetch error at startIndex={start}: {e}", file=sys.stderr)
                time.sleep(delay * 2)
                continue
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            for v in vulns:
                cve = v.get("cve", {})
                desc = next((d["value"] for d in cve.get("descriptions", [])
                             if d.get("lang") == "en"), "")
                cwes = []
                for w in cve.get("weaknesses", []):
                    for d in w.get("description", []):
                        val = d.get("value", "")
                        if val.upper().startswith("CWE-") and val[4:].isdigit():
                            cwes.append(val.upper())
                cwes = sorted(set(cwes))
                date = (cve.get("published", "") or "")[:10]
                if desc and len(cwes) == 1:          # clean single-label row
                    out.write(json.dumps({"text": desc, "cwe": cwes[0], "date": date}) + "\n")
                    kept += 1
            total = data.get("totalResults", 0)
            start += PAGE
            print(f"  collected {kept} usable rows (scanned up to {start}/{total})",
                  file=sys.stderr)
            if start >= total:
                break
            time.sleep(delay)
    print(f"[+] wrote {kept} rows to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
