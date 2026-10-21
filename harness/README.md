# web-bugbounty-harness (scaffold)

A starting skeleton for the **triage "brain"** of an **authorized** web
bug-bounty testing pipeline. It implements the spine the research design calls
for — a normalized finding record, an ingest layer, a confidence-gated CWE
classifier, and a datastore — and leaves the heavier stages as clearly-marked
stubs with an upgrade path.

> ⚠️ **Authorized testing only.** Use this only against targets you have written
> permission to test, within the program's scope **and** rules of engagement.
> See `SCOPE_AND_ROE.md`. This scaffold *records* authorization; it does not yet
> *enforce* scope — that enforcement engine is a deliberate BUILD gap.

> This is the **brain** (classify / score / dedup / prioritize / report over
> finding *text*). It does **not** find bugs — discovery is your conventional
> tooling (the "hands"). The design explains that split in full.

---

## Why this exists / what's intentionally NOT here

Built from an 18-paper + 44-link research review (`CVE-ML-papers_to_bug-bounty-harness.md`).
The honest headline from that review: the research is strong on the *brain* and
weak on the *hands*, and **mature open-source tools already own the datastore /
dedup / report backbone** (see *Build vs adopt* below). So this scaffold is a
**learning-grade, swappable skeleton** — useful to understand the pipeline and
to prototype the ML enrichment, not a reinvention of a vuln-management platform.

---

## Quickstart (no dependencies)

```bash
cd web-bugbounty-harness
python -m unittest discover -s tests        # 8 tests, stdlib only

python -m harness --db demo.db init
python -m harness --db demo.db ingest --tool nuclei --file samples/nuclei_sample.jsonl \
    --program acme --in-scope --roe-ok --authorized-by you
python -m harness --db demo.db classify
python -m harness --db demo.db list
python -m harness --db demo.db show --id <id-prefix-shown-by-list>
```

Expected: 5 findings ingested; the keyword stub auto-triages the ones it is
confident about and sends the rest to `needs_review` — exactly what a *baseline*
should do (it is not a real model; see Stage 5 below).

---

## How it maps to the design stages

| Stage | In this scaffold | Status | Upgrade path |
|---|---|---|---|
| **0. Authorization** | `Authorization` block on every finding; CLI flags; `SCOPE_AND_ROE.md` template | **recorded, not enforced** | Build a scope/ROE engine: match URLs to the allow-list + per-request rate/technique checks |
| **1. Recon** | — | **gap** | Feed from bbot / amass / httpx / katana (external) |
| **2. Detect** | — | **gap** | Feed from nuclei / Burp / sqlmap etc. — ingest their output |
| **3. Validate** | `Exploit` fields (`poc_path`, `poc_verified`) | **fields only** | Non-destructive PoC store; CVE-GENIE-style verified repro (sandbox) |
| **4. Dedup/cluster** | exact-duplicate collapse (`store.add_deduped`) | **exact only** | Embed + UMAP/HDBSCAN for near-duplicates (design §Group E) |
| **5. CWE classify** | `KeywordCweClassifier` + confidence gate | **baseline stub** | Swap in Aota BoW+RF, Simonetto two-step, or RoBERTa-125M |
| **6. CVSS score** | `CvssScore` schema; nuclei pre-seed | **schema only** | Per-metric model (Marchiori/Costa) → official `cvss` equations |
| **7. Prioritize** | `priority_score` field; `exploit_likelihood` field | **field only** | EPSS + CISA-KEV feeds + FastEmbed-style P(exploit) model |
| **8. Report** | — | **gap** | Sun templates + GuardLink/VWC-MAP (ATT&CK/CAPEC enrichment) |

Fully working today: **schema, store, ingest (nuclei + generic), CWE baseline,
the confidence gate, dedup, CLI, tests.**

---

## Architecture

```
harness/
  schema.py            Finding + CweAssignment/CvssScore/Exploit/Authorization  (the spine)
  store.py             SQLite datastore + exact-duplicate key
  ingest/
    base.py            Adapter contract + registry + authorization stamping
    nuclei.py          nuclei -jsonl  -> Finding   (pre-seeds tool CWE/CVSS)
    generic.py         config-mapped JSON/JSONL -> Finding
  classify/
    base.py            CweClassifier interface + apply_gate (Aota C>0.8)
    keyword_stub.py    baseline keyword matcher  (REPLACE with a real model)
    ../data/cwe_keywords.json   web-focused CWE keyword table
  cli.py / __main__.py the command line
tests/                 stdlib unittest
samples/               example nuclei output
SCOPE_AND_ROE.md       Stage-0 authorization template
```

**Swap-a-stub rule:** every stub is behind an interface. To use a real CWE model,
subclass `CweClassifier`, implement `.predict(text) -> [CweAssignment]`, and
return it from `classify.default_classifier()` (or add `--classifier`). Nothing
else changes — the gate, store, and CLI are model-agnostic.

---

## Build vs adopt

From a survey of 40+ existing projects (full writeup: `repo_recommendation.md`).
**No single repo matches the whole 0→8 pipeline — and you shouldn't want one.**
Adopt mature tools for the commodity parts; spend your effort only where the
"brain" is genuinely uncovered.

| Stage | Decision | Adopt | License* |
|---|---|---|---|
| 0 Authorization | **BUILD** (bespoke; study SSVC framing) | — | — |
| 1 Recon | ADOPT | **bbot** (run as subprocess) / reconFTW | AGPL-3.0 / MIT |
| 2 Detect | ADOPT | **nuclei** (+ reuse its JSON schema) | MIT |
| 3 Validate | ADOPT/EXTEND | **CVE-Genie** (oracle), Strix | Apache-2.0 |
| 4 Dedup | ADOPT | **DefectDojo** correlation engine | BSD-3 |
| 5 CWE classify | ADOPT recipe + retrain | **CVE-LMTune** (multi-label) | GPL-3.0 |
| 6 CVSS score | BUILD (retrain) | Joana-Cabral/CVSS_Prediction code+data | MIT |
| 7 Prioritize | ADOPT feeds + BUILD model | **EPSS** API + **CISA KEV**; train on `cvss-bt` | open / MIT |
| 8 Report | ADOPT | **DefectDojo** reports + CVE-LMTune enrichment | BSD-3 |

**The backbone: OWASP DefectDojo (BSD-3).** It already is the normalized-Finding
datastore + dedup + CWE/CVSS/EPSS fields + triage + templated reports + ~180
ingest parsers + REST API (stages 4–8). *Adopt it; do not rebuild the data
model.* This scaffold's `store.py`/`schema.py` are a learning-grade stand-in and
a clean place to prototype the brain before you wire it to DefectDojo over REST.

**Integration shape:** `bbot/nuclei → (normalize) → DefectDojo ← your ML "brain"
as a decoupled microservice over REST`, with EPSS/KEV pulled as HTTP feeds. Keep
the brain a separate service so copyleft tools (bbot AGPL, CVE-LMTune GPL) never
touch your code — subprocess bbot, retrain CVE-LMTune under its recipe.

**Where YOUR original effort goes** (nothing mature covers these):
1. **Finding-level exploit-likelihood** — fuse EPSS + KEV + "does a PoC exist for
   *this* finding" + scan evidence (EPSS is only CVE-level). Train on `cvss-bt`.
2. **A rigorous brain-evaluation harness** — temporal splits + ground-truth-aware
   scoring. Every existing classifier inflates its numbers with random splits.
   This is your real differentiator.

*\*License/star figures are agent-reported and only partly verified — confirm
each repo's LICENSE and current state yourself before depending on it. Two of
your stated "gaps" (verified-PoC gen, multi-label CWE) already exist immaturely
(Strix/CVE-Genie; CVE-LMTune) — extend/benchmark them, don't greenfield.*

---

## Design provenance

This scaffold follows `CVE-ML-papers_to_bug-bounty-harness.md` (the full research
guide). Key principles baked in: multi-label CWE (not single-label); confidence-
gate every model output; predict CVSS vectors then compute the score; treat NVD
labels as noisy; keep a human in the loop; and keep Stage 0 authorization and
non-destructive validation as hard boundaries.

## License
MIT (scaffold code). The research papers and any third-party models/datasets you
plug in keep their own licenses — check each before use.
