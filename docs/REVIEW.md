# Implementation Review — web-bugbounty-harness

An adversarial, multi-dimension review of the `harness/` implementation against
the research design (`ANALYSIS_cve-ml-to-harness.md`) and professional software
standards. Six reviewers (design fidelity, correctness, SWE quality, security,
claims-honesty, completeness-vs-adopt) raised findings; each was verified against
the actual code to remove false positives and gold-plating before being acted on.

## Verdict

**Entering review: B+ — a disciplined, honest prototype faithful to the research,
held back by two first-principle violations, a security footgun, and a cluster of
boundary bugs.** All verified findings were then fixed (see `harness/` history).

## What the review confirmed is good

- **CVSS v3.1 base math is correct** — implemented from the official FIRST
  equations (scope-changed impact, 3.1 roundup, 1.08 multiplier) and validated
  against canonical vectors (Log4Shell = 10.0).
- **Evaluation is genuinely temporal** (train on past, test on future), not a
  random split — the design's flagged differentiator.
- **Clean, swappable architecture** — every stub sits behind a real interface.
- **Build-vs-adopt honored** — the SQLite store is a documented, swappable
  learning-grade stand-in; DefectDojo is the intended backbone (export exists).
- **Honest docs** — "it does not find bugs", "authorization recorded not
  enforced", synthetic-data caveats all match the code.

## The load-bearing fixes applied

| Severity | Issue | Fix |
|---|---|---|
| HIGH (design) | NVD CWEs injected at 0.99 "official mapping" — inverts the design's "NVD labels are noisy" thesis | NVD CWEs now enter at 0.5 as unverified suggestions (route to review); placeholder/pillar CWEs dropped |
| HIGH (security) | `pickle.load` of a model = arbitrary code execution, with a false "trusted" comment | `.sha256` integrity sidecar written on save + verified on load; loud warning; tampered files refused |
| MEDIUM (security) | Out-of-scope findings exported as actionable | Unauthorized findings export `active:false` + `UNAUTHORIZED` tag + "DO NOT ACTION", and sink in the priority sort |
| MEDIUM | nuclei adapter crashes (bad port, null CVSS vector, one bad record aborting the batch) | Per-record isolation + safe parsing; real CVSS-version detection (v2/v3/v4) replaces a dead ternary |
| MEDIUM | dedup key omitted the URL path (distinct endpoints collapsed) | path added to the dedup basis |
| MEDIUM | `except Exception` across enrichment hid real bugs as "offline" | narrowed to `RequestException` + logging; `allow_redirects=False` on all feeds |
| MEDIUM | Python-3.9 import crash (`str | None` without `from __future__`) | future-import added |
| MEDIUM | Stage-6 could not score a novel finding | CWE→CVSS prior table seeds a vector (low confidence on PR/C/I/A → human review) |
| LOW/NIT | version drift, dead doc refs, missing LICENSE, multi-label overclaim, re-gate selector, EPSS negative-cache, KEV backoff, random_state, … | all applied |

## Deliberate non-fixes (prototype scope / adopt-don't-build)

- **CVSS v4 / v2→v3 conversion** — v3.1-base only by design; v4 is a named gap.
- **Full per-metric text→CVSS predictor** — intentional BUILD gap (prior-seed only).
- **Near-duplicate clustering (Stage 4)** — intentional stub; only exact-dup fixed.
- **Replacing the SQLite store** — deliberately a thin, swappable stand-in; the
  real datastore/dedup/report backbone is DefectDojo (export is the seam).

## Honest standing limitations

This is the triage **brain**, not a bug finder. It does **not** find live bugs
(that is conventional tooling), does **not** enforce scope (authorization is
recorded, not enforced — a documented gap), and its shipped sample datasets are
synthetic. Real numbers require NVD / cvss-bt data. Use only for authorized testing.
