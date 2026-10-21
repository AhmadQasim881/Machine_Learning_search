# Bug-Bounty Harness: Build-vs-Adopt Recommendation

## 0. Honest framing first

No single project matches your full 0→8 pipeline, and you shouldn't want one to. The design is deliberately split into **hands** (recon/scan/fuzz/validate — commodity, mature, adopt) and a **brain** (classify/score/dedup/prioritize/report over finding text — your original IP). The right move is to adopt a mature datastore/triage backbone, feed it from mature recon/scan tools, and spend your effort only where the brain is genuinely uncovered. Two of your four stated "gaps" are already partly built by others — I call that out in §3 so you don't greenfield something that exists.

---

## 1. Single most-matching existing project

**OWASP DefectDojo** (`DefectDojo/django-DefectDojo`) — adopt as the backbone, do not reimplement.

It is the closest match to the *core* of your design: a normalized **Finding** object flowing through **one datastore**, with a configurable dedup/correlation engine and native CWE / CVSSv3-vector / severity / EPSS / SLA / risk-acceptance fields, status tracking across a product→engagement→test hierarchy, templated reporting, and a full REST API. It covers stages **4–8** out of the box and much of stage-2 ingest via its ~180-parser library.

**Why it wins over the alternatives:** Faraday (~6.8k stars) is the only comparable full backbone, but it's **GPL-3.0** (vs DefectDojo's **BSD-3**, which lets you build a proprietary brain on top cleanly) *and* it is pivoting into "AI autonomous pentesting" — i.e. it is becoming a competitor to the exact brain you want to own. reNgine/ArcherySec/Dradis are each thinner or staler on the triage datastore.

**Real caveats (be honest with yourself):**
- It is only half your pipeline — **no native stage 0/1/3** (authorization, recon, validate).
- **KEV and "business context" are not first-class** — you add them as custom fields / in your prioritization layer.
- Field names (hash_code dedup, EPSS percentile, etc.) are confirmed from docs/topics in the scouted data but were **not line-verified in source** this run — verify against the running schema before you couple to it.
- DefectDojo is the datastore and triage shell. **It is not the brain.** The ML enrichment is yours to build and bolt on via REST API + custom fields — never fork the data model.

---

## 2. Build-vs-adopt per stage

| Stage | Decision | Best repo | License | Notes / caveat |
|---|---|---|---|---|
| **0 Authorization (scope+ROE gate)** | **BUILD** (small, bespoke) | — (STUDY: CAI autonomy taxonomy, SSVC) | — | Nothing covers a scope+ROE gate; it must be yours and must gate everything. CAI's arXiv autonomy-level taxonomy is good framing — but CAI itself is **archived/read-only + partly proprietary**, so mine the paper, not the code. |
| **1 Recon** | **ADOPT** | **bbot** (backbone) | AGPL-3.0 ⚠ | Python-native, emits normalized JSON Events into a DB — the cleanest feed into a Python brain. **AGPL is strong copyleft** for a network-served product: run it as a **subprocess/separate service**, don't import it. reconFTW (MIT) is a lighter alt but dumps files, not records. STUDY reNgine's Postgres schema. |
| **2 Detect (scan/fuzz)** | **ADOPT** | **nuclei** (backbone) + **Strix** | MIT / Apache-2.0 | nuclei is the standard detection engine everyone wraps; reuse its JSON schema as your finding-record template, and its ~10k templates' `cwe-id/cvss/tags` as **weak-labeled training data** for stages 5/6. Strix adds AI web detect. |
| **3 Validate (PoC/oracle)** | **ADOPT / EXTEND** | **Strix**; STUDY **CVE-Genie** | Apache-2.0 / Apache-2.0 | See §3 — this is a "gap" that is **already partly built**. Strix validates web findings with real PoCs (but strongest claims are its *paid* cloud; benchmark the OSS CLI yourself). CVE-Genie's CTF-Verifier is the reference oracle (~51% reproduction, costs ~$2.77/CVE, research prototype). |
| **4 Dedup/cluster** | **ADOPT** | **DefectDojo** | BSD-3 | Its correlation engine is exactly this. Don't rebuild. |
| **5 CWE classify** | **ADOPT recipe + BUILD** | **CVE-LMTune** (recipe); datasets: xamxte 234k, UnifiedCVE-CWE | GPL-3.0 ⚠ | CVE-LMTune already does **multi-label CWE/CAPEC/ATT&CK, flat + hierarchical** — the only released repo that does. But it's **young (~11 stars), unbattle-tested, GPL-3.0**: retrain under its recipe rather than shipping its checkpoints. STUDY V2W-BERT (hierarchy idea; its 94–97% is inflated by random splits). |
| **6 CVSS score** | **BUILD** | adopt **Joana-Cabral/CVSS_Prediction** code+data, retrain | MIT | **No mature text→CVSS tool exists** — the whole category is <10-star research notebooks. Joana-Cabral is the only "code+dataset+permissive" option but research-grade, v3-only, stale (~2021 data). STUDY CVSS-BERT (no license — can't reuse), LLM-CVSS (no license), AutoCVSS (**v4.0 coverage + eval method, but noncommercial-only — do NOT ship its code**). |
| **7 Prioritize** | **ADOPT feeds + BUILD model** | **EPSS API** + **CISA KEV** (adopt); **cvss-bt** (train data); STUDY **SSVC**, **CVE_Prioritizer** | open / MIT / BSD-3 | Adopt EPSS (don't reproduce it — training set is proprietary) and KEV as a boolean override + clean positive labels. `cvss-bt` is a daily multi-source labeled corpus — your training data for the exploit-likelihood model. Adopt **SSVC** schemas for the business/mission dimension. CVE_Prioritizer is a 1-day threshold heuristic — study, don't depend. |
| **8 Report (CWE/CAPEC/ATT&CK)** | **ADOPT** | **DefectDojo** reporting + **CVE-LMTune** enrichment | BSD-3 / GPL-3.0 | DefectDojo templated reports; CVE-LMTune supplies CAPEC+ATT&CK labels. STUDY Dradis for client-ready templating if you need richer output. |

---

## 3. Where your original effort should actually go

Your brief names four gaps. Being blunt: **two are already partly built by others** — treat those as *extend/benchmark*, not greenfield.

- **Verified-PoC generation — ALREADY PARTLY EXISTS.** Strix (web, Apache-2.0) and CVE-Genie (Apache-2.0) both do verified-PoC generation today. Do **not** build this from scratch. Your genuine original work here is narrow: the **oracle/verifier harness that ties a PoC result back to the normalized finding record**, and emitting PoCs that compile down to **nuclei templates** so the hands stay interchangeable.
- **Multi-label CWE — ALREADY EXISTS (immature).** CVE-LMTune does flat+hierarchical multi-label CWE/CAPEC/ATT&CK. Your original effort is **domain multi-label fine-tuning + honest temporal-split evaluation** — every existing repo evaluates with random splits and inflates its numbers (V2W-BERT's 94–97%, xamxte's 87% is just *agreement with LLM-relabeled data*).
- **Exploit-likelihood model — REAL gap, but scope it.** EPSS already gives the CVE-level signal and you must not reproduce it. Your IP is a **finding-level** likelihood that fuses EPSS + KEV + "does a PoC exist for *this* finding" + your scan evidence — trained on `cvss-bt`'s labeled exploit-maturity corpus.
- **Brain evaluation — the truest uncovered gap and your strongest IP.** No tool does rigorous **temporal-split, ground-truth-aware** evaluation of classify/score/prioritize. This is where to invest: a per-stage eval harness (copy AutoCVSS's *methodology*, not its noncommercial code), temporal splits, and agreement-vs-ground-truth separation. This differentiates the product.

Net: concentrate on **(1) finding-level exploit-likelihood fusion** and **(2) the brain-evaluation harness**. Extend, don't rebuild, PoC-gen and multi-label CWE.

---

## 4. Recommended integration shape

```
         ┌─────────── Stage 0: BUILD (bespoke scope+ROE gate) ───────────┐
         │        gates every downstream call; borrow SSVC/CAI framing    │
         └───────────────────────────────┬───────────────────────────────┘
                                          ▼
   HANDS (adopt, run as separate services/subprocesses):
     bbot (recon, stage 1 — subprocess to contain AGPL)
     nuclei (detect, stage 2 — reuse JSON schema as finding template)
     Strix / CVE-Genie (detect+validate, stages 2–3; verified PoC)
                                          │  normalize → Findings
                                          ▼
   BACKBONE:  OWASP DefectDojo  (BSD-3)
     one datastore • dedup (stage 4) • CWE/CVSS/EPSS fields • triage • reports (8)
     ── do NOT fork the data model; integrate via REST API + custom fields ──
                                          ▲  read Findings / write enrichment
                                          │
   BRAIN (your IP, as a decoupled plugin/microservice — keeps licensing clean):
     • multi-label CWE   (CVE-LMTune recipe, retrained)         → stage 5
     • CVSS from text    (Joana-Cabral code, retrained on NVD)  → stage 6
     • exploit-likelihood (your model, trained on cvss-bt)      → stage 7
     • CAPEC/ATT&CK enrichment (CVE-LMTune)                     → stage 8
     • evaluation harness (temporal splits) ← your differentiator
                                          ▲
   EXTERNAL FEEDS (pull, don't rebuild):
     EPSS (FIRST API, no key) + CISA KEV (JSON) → prioritization features/overrides
```

**Key integration rules:**
1. **DefectDojo is the spine** for 4–8; everything else plugs into it over REST.
2. **Keep the brain a separate service** that reads/writes Findings via API. This isolates you from the copyleft hands (bbot AGPL, CVE-LMTune GPL) — you retrain CVE-LMTune under its recipe and run bbot as a subprocess so no copyleft reaches your product code.
3. **Reuse nuclei's JSON schema** as the canonical in-flight finding shape so hands are swappable.
4. **Feeds are HTTP GETs**, not dependencies — EPSS and KEV are a few lines each.

---

## Licensing / maturity ledger (honest)

- **Safe to build on (permissive):** DefectDojo (BSD-3), nuclei (MIT), reconFTW (MIT), Osmedeus (MIT), Nettacker (Apache-2.0), Strix (Apache-2.0), CVE-Genie (Apache-2.0), project-kb/Prospector (Apache-2.0), Joana-Cabral (MIT), cvss-bt (MIT), CVE_Prioritizer (BSD-3), EPSS/KEV (open/public domain).
- **Copyleft — contain or retrain:** bbot (AGPL-3.0 → subprocess), Faraday (GPL-3.0), reNgine (GPL-3.0), CVE-LMTune (GPL-3.0 → retrain), vulnhuntr (AGPL-3.0).
- **Do NOT ship the code:** CVSS-BERT (no license = all-rights-reserved), LLM-CVSS (no license), **AutoCVSS (noncommercial-only — unusable in a paid harness; copy methodology only)**, Jackhammer (unresolved license + abandoned).

**Flagged as unverified / do-not-trust-as-stated:**
- No public repo exists for **ThreatZoom**, **SemFuzz**, **CommitShield**, or **nuclei-ai-prompt** — paper/concept only; nothing to adopt.
- Licenses/stats **unconfirmed** for: xamxte (HF unreachable; also single-author non-peer-reviewed, labels LLM-generated), CIRCL VLAI (weak: 66% acc, coarse-parent-only), V2W-BERT, UnifiedCVE-CWE-Dataset (maintainer/quality/18-class-only all unknown).
- **PentAGI** star count irreconcilable (~12.5k vs ~31.7k reported) and architecturally far from your design — low weight.
- DefectDojo's exact dedup/CWE/CVSS/EPSS field names were not line-verified in source this run.

**Bottom line:** the architecture is sound and the adopt/build split is right. The one correction to your plan: you listed verified-PoC generation and multi-label CWE as gaps to *build* — both already exist (Strix/CVE-Genie; CVE-LMTune), just immaturely. Redirect that effort into finding-level exploit-likelihood fusion and a rigorous temporal-split brain-evaluation harness, which nothing mature covers and which is your real differentiator.