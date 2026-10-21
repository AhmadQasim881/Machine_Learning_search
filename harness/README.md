# web-bugbounty-harness

The triage **"brain"** of an **authorized** web bug-bounty testing pipeline:
ingest findings → classify (CWE) → score (CVSS) → enrich (EPSS/KEV/NVD) →
prioritize → export to a backbone. Built from the research review in `docs/`.

**v0.2 — now a working brain, not just a skeleton.** Real trainable CWE
classifier, a correct offline CVSS v3.1 calculator, EPSS/KEV/NVD enrichment,
transparent prioritization, a temporal-split evaluation harness, and a
DefectDojo exporter. 40 tests pass.

> ⚠️ **Authorized testing only.** Use this only against targets you have written
> permission to test, within the program's scope **and** rules of engagement.
> See `SCOPE_AND_ROE.md`. This scaffold *records* authorization; it does not yet
> *enforce* scope — that enforcement engine is a deliberate BUILD gap.

> This is the **brain** (classify / score / dedup / prioritize / report over
> finding *text*). It does **not** find bugs — discovery is your conventional
> tooling (the "hands"). The design explains that split in full.

---

## Why this exists / what's intentionally NOT here

Built from an 18-paper + 44-link research review (`../docs/ANALYSIS_cve-ml-to-harness.md`).
The honest headline from that review: the research is strong on the *brain* and
weak on the *hands*, and **mature open-source tools already own the datastore /
dedup / report backbone** (see *Build vs adopt* below). So this scaffold is a
**learning-grade, swappable skeleton** — useful to understand the pipeline and
to prototype the ML enrichment, not a reinvention of a vuln-management platform.

---

## Quickstart

```bash
cd harness
python -m unittest discover -s tests        # 40 tests (stdlib; sklearn tests skip if absent)

# --- core pipeline (no installs needed) ---
python -m harness --db demo.db init
python -m harness --db demo.db ingest --tool nuclei --file samples/nuclei_sample.jsonl \
    --program acme --in-scope --roe-ok --authorized-by you
python -m harness --db demo.db classify            # keyword baseline (no deps)
python -m harness --db demo.db score               # CVSS vector -> base score
python -m harness --db demo.db prioritize --no-kev # fuse CVSS+EPSS+PoC
python -m harness --db demo.db list --sort priority
python -m harness --db demo.db export --out dd.json # -> DefectDojo generic import
```

```bash
# --- the real ML brain (needs: pip install -r requirements.txt) ---
# train a CWE model (the shipped sample is SYNTHETIC — see note), then use it:
python -m harness train    --data samples/cwe_training_sample.jsonl --model model.pkl
python -m harness evaluate  --data samples/cwe_training_sample.jsonl   # temporal split
python -m harness --db demo.db classify --classifier model.pkl

# --- enrichment (needs internet on YOUR machine; keys off CVE ids) ---
python -m harness --db demo.db enrich --nvd         # EPSS + CISA KEV + NVD
python -m harness --db demo.db predict-exploit      # finding-level P(exploit) — heuristic
python -m harness --db demo.db prioritize           # now KEV/EPSS/likelihood-aware

# --- finding-level exploit-likelihood MODEL (the original piece) ---
# build a real training set from cvss-bt (needs internet), then train + use it:
python tools/build_exploit_dataset.py --out exploit_train.jsonl
python -m harness train-exploit --data exploit_train.jsonl --model expl.pkl
python -m harness --db demo.db predict-exploit --model expl.pkl
```

> **Finding-level exploit-likelihood** is the one piece the research flags as
> genuinely original: EPSS/KEV are CVE-level, but a bug-bounty finding is
> finding-level and often has *no CVE*. `predict-exploit` fuses EPSS + KEV +
> verified-PoC + CVSS + CWE into one P(exploit), with a transparent heuristic by
> default and a model (trained on cvss-bt) when you have one. The shipped
> `samples/exploit_training_sample.jsonl` is SYNTHETIC — use cvss-bt for real numbers.

> ⚠️ **The shipped `samples/cwe_training_sample.jsonl` is SYNTHETIC** (templated)
> and will score ~100% — it only proves the code runs. Build a real set with
> `python tools/build_nvd_dataset.py --out nvd_cwe.jsonl` (needs internet), then
> train/evaluate on that. On real NVD data expect **~70–80% and a visible drop on
> the temporal split** — that honest gap is the whole point of the eval harness.

---

## How it maps to the design stages

| Stage | In this harness | Status | Next upgrade |
|---|---|---|---|
| **0. Authorization** | `Authorization` block + CLI flags + `SCOPE_AND_ROE.md` | **recorded, not enforced** | Build a scope/ROE engine (URL allow-list + rate/technique checks) |
| **1. Recon** | — | **gap (external)** | Feed from bbot / amass / httpx / katana |
| **2. Detect** | nuclei + generic ingest adapters | **ingest works** | More adapters (Burp/ZAP/sqlmap); detection itself stays external |
| **3. Validate** | `Exploit` fields (`poc_path`, `poc_verified`) | **fields + prioritization hook** | Non-destructive PoC store; CVE-GENIE-style verified repro (sandbox) |
| **4. Dedup/cluster** | exact-duplicate collapse (`store.add_deduped`) | **exact only** | Embed + UMAP/HDBSCAN for near-duplicates |
| **5. CWE classify** | keyword baseline **+ real TF-IDF/LogReg model** (`train`/`classify --classifier`) + gate | **working** | Simonetto two-step / RoBERTa-125M; multi-label |
| **6. CVSS score** | **offline v3.1 calculator** (`score`) + NVD vector pull (`enrich --nvd`) | **working (v3.1 base)** | Per-metric text→vector model (Marchiori/Costa); v4.0 |
| **7. Prioritize** | EPSS + KEV enrichment, **finding-level exploit-likelihood model** (`predict-exploit`, heuristic or trained on cvss-bt), transparent fusion (`prioritize`) | **working** | Richer features; calibration on real data |
| **8. Report** | **DefectDojo generic-import export** (`export`) | **export works** | ATT&CK/CAPEC enrichment (GuardLink/VWC-MAP); Sun templates |

Working today: schema, store, ingest, keyword + trained CWE classifier, the gate,
CVSS v3.1 scoring, EPSS/KEV/NVD enrichment, transparent prioritization, temporal
evaluation, DefectDojo export, exploit-likelihood, CLI, 40 tests. Enrichment needs internet; the
trained classifier needs scikit-learn.

---

## Architecture

```
harness/
  schema.py            Finding + CweAssignment/CvssScore/Exploit/Authorization  (the spine)
  store.py             SQLite datastore + exact-duplicate key
  ingest/              nuclei + generic adapters (contract + registry)
  classify/
    base.py            CweClassifier interface + apply_gate (Aota C>0.8)
    keyword_stub.py    zero-dep baseline keyword matcher
    sklearn_model.py   REAL trainable TF-IDF + LogReg classifier (train/save/load)
    ../data/cwe_keywords.json   web-focused CWE keyword table
  score/cvss31.py      offline, correct CVSS v3.1 base-score calculator
  score/priors.py      CWE -> CVSS v3.1 vector priors (Miyamoto-style seed)
  score/exploit_likelihood.py  finding-level P(exploit): heuristic + trainable model
  enrich/              EPSS + CISA KEV + NVD clients (cached, fail-soft)
  prioritize.py        transparent CVSS+likelihood+KEV+PoC fusion (Stage 7)
  evaluate.py          temporal-split evaluation of the CWE classifier
  export/defectdojo.py Finding -> DefectDojo generic-import JSON
  cli.py / __main__.py the command line
tools/build_nvd_dataset.py       build a real CVE->CWE training set from NVD
tools/build_exploit_dataset.py   build an exploit-likelihood training set from cvss-bt
tests/                 stdlib unittest (40 tests)
samples/               example nuclei output + synthetic CWE training data
SCOPE_AND_ROE.md       Stage-0 authorization template
```

**Pipeline order:** `ingest → classify → score → enrich → predict-exploit → prioritize → export`.
Each stage reads/writes the one `Finding` record; every ML output is a
confidence-gated suggestion, never an authority.

**Swap-a-stub rule:** every stub is behind an interface. To use a real CWE model,
subclass `CweClassifier`, implement `.predict(text) -> [CweAssignment]`, and
return it from `classify.default_classifier()` (or add `--classifier`). Nothing
else changes — the gate, store, and CLI are model-agnostic.

---

## Build vs adopt

From a survey of 40+ existing projects (full writeup: `../docs/BUILD_VS_ADOPT.md`).
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

This harness follows `../docs/ANALYSIS_cve-ml-to-harness.md` (the full research
guide). Key principles baked in: the finding record is **multi-label-ready** for
CWE (the shipped classifiers are single-label — true multi-label is a future
upgrade); confidence-gate every model output; predict CVSS vectors then compute
the score with the official equations; treat NVD CWE labels as noisy (NVD CWEs
enter below the gate, not as authority); keep a human in the loop; and keep
Stage 0 authorization and non-destructive validation as hard boundaries.

## License
MIT — see `LICENSE`. The research papers and any third-party models/datasets you
plug in keep their own licenses — check each before use.
