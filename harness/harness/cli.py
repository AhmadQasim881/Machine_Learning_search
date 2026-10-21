"""
harness.cli — the command line over the harness.

    python -m harness --db harness.db init
    python -m harness --db harness.db ingest  --tool nuclei --file out.jsonl --program acme --in-scope --roe-ok
    python -m harness --db harness.db classify [--classifier model.pkl] [--all]
    python -m harness --db harness.db score                  # CVSS vector/prior -> base score
    python -m harness --db harness.db enrich   [--no-epss] [--no-kev] [--nvd]
    python -m harness --db harness.db predict-exploit [--model expl.pkl]  # finding-level P(exploit)
    python -m harness --db harness.db prioritize             # fuse CVSS+likelihood+KEV+PoC
    python -m harness --db harness.db list     [--status needs_review] [--sort priority]
    python -m harness --db harness.db show     --id <id>
    python -m harness --db harness.db export   --out findings_dd.json   # DefectDojo
    python -m harness train          --data cwe.jsonl --model model.pkl
    python -m harness evaluate       --data cwe.jsonl [--train-frac 0.8]
    python -m harness train-exploit  --data exploit.jsonl --model expl.pkl
    python -m harness adapters

Stdlib argparse only. The CLI wires the stages together; the real work lives in
the modules so it stays swappable. ML/enrichment commands need their optional
deps (scikit-learn / requests) — they print a clear message if missing.
"""
from __future__ import annotations

import argparse
import json
import sys

from .classify import apply_gate, load_classifier
from .ingest import apply_authorization, available_adapters, get_adapter
from .schema import Authorization, CvssScore, ConfidenceSource, Status
from .store import Store


def _cmd_init(args) -> int:
    with Store(args.db):
        pass
    print(f"[+] initialized datastore at {args.db}")
    return 0


def _cmd_adapters(args) -> int:
    print("available ingest adapters:")
    for a in available_adapters():
        print(f"  - {a}")
    return 0


def _cmd_ingest(args) -> int:
    adapter = get_adapter(args.tool)
    findings = adapter.parse_file(args.file)
    auth = Authorization(program=args.program or "", in_scope=bool(args.in_scope),
                         roe_ok=bool(args.roe_ok), authorized_by=args.authorized_by or "")
    apply_authorization(findings, auth)
    new = dup = 0
    with Store(args.db) as store:
        for f in findings:
            _, is_new = store.add_deduped(f)
            new += int(is_new)
            dup += int(not is_new)
    print(f"[+] ingested {len(findings)} record(s) via '{args.tool}': {new} new, {dup} exact-duplicate")
    if findings and not auth.actionable:
        print("[!] authorization NOT fully set (in-scope/ROE) — findings recorded "
              "but not-actionable until you confirm scope and rules of engagement.",
              file=sys.stderr)
    return 0


def _cmd_classify(args) -> int:
    try:
        clf = load_classifier(args.classifier)
    except Exception as e:  # noqa: BLE001
        print(f"[-] could not load classifier: {e}", file=sys.stderr)
        return 1
    # default: only NEW findings; --all re-classifies all machine-set states
    # (NEW/NEEDS_REVIEW/TRIAGED) so a model swap takes effect without clobbering
    # human decisions; --status targets one state.
    if args.status:
        selected = [Status(args.status)]
    elif args.all:
        selected = [Status.NEW, Status.NEEDS_REVIEW, Status.TRIAGED]
    else:
        selected = [Status.NEW]
    triaged = reviewed = 0
    todo = []
    with Store(args.db) as store:
        for st in selected:
            todo.extend(store.iter_findings(status=st))
        for f in todo:
            clf.classify(f)
            apply_gate(f, threshold=args.gate)
            store.upsert(f)
            triaged += int(f.status == Status.TRIAGED)
            reviewed += int(f.status == Status.NEEDS_REVIEW)
    print(f"[+] classified {len(todo)} finding(s) with '{clf.name}' "
          f"(gate={args.gate}): {triaged} auto-triaged, {reviewed} -> needs_review")
    return 0


def _cmd_score(args) -> int:
    from .score import (low_confidence_for_subjective, prior_vector, score_vector)
    from .schema import ConfidenceSource, CvssScore
    scored = seeded = skipped = 0
    with Store(args.db) as store:
        for f in store.iter_findings():
            # seed a vector from the CWE prior when none exists (and not opted out)
            if (not (f.cvss and f.cvss.vector)) and not args.no_prior:
                top = f.top_cwe()
                pv = prior_vector(top.cwe_id) if top else None
                if pv:
                    f.cvss = CvssScore(version="3.1", vector=pv,
                                       source=ConfidenceSource.PRIOR,
                                       per_metric_confidence=low_confidence_for_subjective())
                    seeded += 1
            if not (f.cvss and f.cvss.vector):
                skipped += 1
                continue
            # don't overwrite an authoritative NVD-sourced score (source=PRIOR with a
            # base_score already set); prior-SEEDED vectors have no score yet, so they
            # still get computed below.
            if f.cvss.source == ConfidenceSource.PRIOR and f.cvss.base_score is not None:
                continue
            try:
                base, sev = score_vector(f.cvss.vector)
            except ValueError:
                skipped += 1
                continue
            f.cvss.base_score = base
            f.cvss.severity = sev
            f.severity = sev
            store.upsert(f)
            scored += 1
    print(f"[+] CVSS: computed base score for {scored} finding(s)"
          + (f" ({seeded} seeded from CWE priors — PR/C/I/A need human review)" if seeded else "")
          + f"; {skipped} still lack a usable vector.")
    return 0


def _cmd_enrich(args) -> int:
    try:
        import requests  # noqa: F401
    except ImportError:
        print("[-] enrichment needs 'requests' (pip install requests)", file=sys.stderr)
        return 1
    from .enrich import EpssClient, KevCatalog, NvdClient

    epss_client = None if args.no_epss else EpssClient()
    kev = None if args.no_kev else KevCatalog()
    nvd = NvdClient() if args.nvd else None
    if kev:
        kev.refresh()

    # collect CVE ids from findings (source_ref or tags like CVE-xxxx)
    def cve_of(f):
        for cand in [f.source_ref] + list(f.tags):
            if cand and cand.upper().startswith("CVE-"):
                return cand.upper()
        return None

    n_epss = n_kev = n_nvd = 0
    with Store(args.db) as store:
        findings = list(store.iter_findings())
        cves = {cve_of(f) for f in findings} - {None}
        epss_map = epss_client.scores(cves) if (epss_client and cves) else {}
        for f in findings:
            cve = cve_of(f)
            changed = False
            if cve and cve in epss_map:
                f.exploit.exploit_likelihood = epss_map[cve]["epss"]
                f.exploit.likelihood_source = "epss"
                n_epss += 1
                changed = True
            if kev and cve and kev.contains(cve):
                if "kev" not in [t.lower() for t in f.tags]:
                    f.tags.append("kev")
                n_kev += 1
                changed = True
            if nvd and cve:
                info = nvd.lookup(cve)
                if info and info.get("cvss_vector"):
                    f.cvss = CvssScore(vector=info["cvss_vector"],
                                       base_score=info.get("cvss_score"),
                                       severity=(info.get("severity") or ""),
                                       source=ConfidenceSource.PRIOR)
                    for c in info.get("cwes", []):
                        if c not in [x.cwe_id for x in f.cwes]:
                            from .schema import CweAssignment
                            # NVD CWE labels are noisy (design §1: ~55% invalid), so
                            # this is a SUGGESTION below the gate, not an authority —
                            # it routes to NEEDS_REVIEW rather than auto-accepting.
                            f.cwes.append(CweAssignment(
                                c, 0.5, ConfidenceSource.PRIOR,
                                "NVD-suggested (unverified; NVD CWE labels are noisy)"))
                    n_nvd += 1
                    changed = True
            if changed:
                store.upsert(f)
    print(f"[+] enrichment: EPSS on {n_epss}, KEV on {n_kev}, NVD on {n_nvd} finding(s). "
          f"({len(cves)} CVE id(s) seen)" + ("" if cves else
          "  [note: no CVE ids on findings — EPSS/KEV/NVD key on CVE]"))
    return 0


def _cmd_prioritize(args) -> int:
    from .enrich import KevCatalog
    from . import prioritize as prio

    kev = None
    if not args.no_kev:
        try:
            kev = KevCatalog()
            kev.refresh()        # fetch once up front, not per-finding
        except Exception:  # noqa: BLE001
            kev = None

    def cve_of(f):
        for cand in [f.source_ref] + list(f.tags):
            if cand and cand.upper().startswith("CVE-"):
                return cand.upper()
        return None

    n = 0
    with Store(args.db) as store:
        for f in store.iter_findings():
            cve = cve_of(f)
            in_kev = bool(kev and cve and kev.contains(cve)) or ("kev" in [t.lower() for t in f.tags])
            prio.apply(f, epss=f.exploit.exploit_likelihood, in_kev=in_kev)
            store.upsert(f)
            n += 1
    print(f"[+] scored priority for {n} finding(s). Use 'list --sort priority'.")
    return 0


def _cmd_predict_exploit(args) -> int:
    """Finding-level exploit-likelihood: writes exploit.exploit_likelihood for
    every finding, using a trained model if given, else the transparent heuristic."""
    from .score import ExploitLikelihoodModel, heuristic_likelihood
    from .enrich import KevCatalog

    model = None
    if args.model:
        try:
            model = ExploitLikelihoodModel.load(args.model)
        except Exception as e:  # noqa: BLE001
            print(f"[-] could not load exploit model: {e}", file=sys.stderr)
            return 1

    kev = None
    if not args.no_kev:
        try:
            kev = KevCatalog(); kev.refresh()
        except Exception:  # noqa: BLE001
            kev = None

    def cve_of(f):
        for cand in [f.source_ref] + list(f.tags):
            if cand and cand.upper().startswith("CVE-"):
                return cand.upper()
        return None

    src = f"model:{model.name}" if model else "heuristic"
    n = 0
    with Store(args.db) as store:
        for f in store.iter_findings():
            cve = cve_of(f)
            in_kev = bool(kev and cve and kev.contains(cve)) or ("kev" in [t.lower() for t in f.tags])
            # read EPSS from the finding's own enrichment before we overwrite
            epss = f.exploit.exploit_likelihood if f.exploit.likelihood_source == "epss" else None
            if model:
                p = model.predict_for_finding(f, epss=epss, in_kev=in_kev)
            else:
                p = heuristic_likelihood(f, epss=epss, in_kev=in_kev)
            f.exploit.exploit_likelihood = p
            f.exploit.likelihood_source = src
            store.upsert(f)
            n += 1
    print(f"[+] predicted finding-level exploit-likelihood for {n} finding(s) "
          f"using '{src}'. Run 'prioritize' next.")
    if model:
        print("    top model features:", ", ".join(f"{k}={w}" for k, w in model.top_weights(6)))
    return 0


def _cmd_train_exploit(args) -> int:
    try:
        from .score import ExploitLikelihoodModel
    except ImportError:
        print("[-] training needs scikit-learn (pip install scikit-learn)", file=sys.stderr)
        return 1
    rows = _load_rows(args.data)
    if not rows:
        print("[-] no training rows", file=sys.stderr)
        return 1
    model = ExploitLikelihoodModel.train(rows)
    model.save(args.model)
    pos = sum(int(r.get("exploited", 0)) for r in rows)
    print(f"[+] trained exploit-likelihood model on {len(rows)} rows "
          f"({pos} exploited / {len(rows) - pos} not) -> {args.model}")
    print("    top features:", ", ".join(f"{k}={w}" for k, w in model.top_weights(8)))
    return 0


def _cmd_list(args) -> int:
    status = Status(args.status) if args.status else None
    with Store(args.db) as store:
        counts = store.count_by_status()
        rows = list(store.iter_findings(status=status))
    if args.sort == "priority":
        # actionable (authorized) findings first, then by priority desc; unauthorized
        # rows sink to the bottom regardless of score (do not action them).
        rows.sort(key=lambda f: (
            1 if f.authorization.actionable else 0,
            f.priority_score if f.priority_score is not None else -1,
        ), reverse=True)
    if not args.status:
        print("status counts:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "(empty)")
    for f in rows:
        top = f.top_cwe()
        cwe = f"{top.cwe_id}@{top.confidence:.2f}" if top else "-"
        auth = "OK" if f.authorization.actionable else "UNAUTH"
        pri = f"{f.priority_score:5.1f}" if f.priority_score is not None else "   - "
        epss = f"{f.exploit.exploit_likelihood:.0%}" if f.exploit.exploit_likelihood is not None else "-"
        print(f"  P{pri} {f.id[:8]} [{f.status.value:12}] {auth:6} {f.severity or '-':8} "
              f"EPSS:{epss:>4} {cwe:16} {(f.title or f.vuln_type)[:40]}  {f.host}")
    return 0


def _cmd_show(args) -> int:
    with Store(args.db) as store:
        f = store.get(args.id)
    if not f:
        print(f"[-] no finding {args.id}", file=sys.stderr)
        return 1
    print(json.dumps(f.to_dict(), indent=2))
    return 0


def _cmd_export(args) -> int:
    from .export import write_defectdojo_generic
    with Store(args.db) as store:
        findings = list(store.iter_findings())
    n = write_defectdojo_generic(findings, args.out)
    print(f"[+] wrote {n} finding(s) to {args.out} (DefectDojo generic-import format). "
          f"Upload via DefectDojo UI/API.")
    return 0


def _load_rows(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    try:
        data = json.loads(text)
        rows = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        rows = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    return [r for r in rows if isinstance(r, dict)]


def _cmd_train(args) -> int:
    try:
        from .classify.sklearn_model import SklearnCweClassifier
    except ImportError:
        print("[-] training needs scikit-learn (pip install scikit-learn)", file=sys.stderr)
        return 1
    rows = _load_rows(args.data)
    texts = [r["text"] for r in rows]
    labels = [r["cwe"] for r in rows]
    clf = SklearnCweClassifier.train(texts, labels)
    clf.save(args.model)
    print(f"[+] trained on {len(rows)} rows, {len(set(labels))} CWE classes -> {args.model}")
    return 0


def _cmd_evaluate(args) -> int:
    try:
        from .evaluate import evaluate
    except ImportError:
        print("[-] evaluation needs scikit-learn (pip install scikit-learn)", file=sys.stderr)
        return 1
    rows = _load_rows(args.data)
    result = evaluate(rows, train_frac=args.train_frac, gate=args.gate)
    print(json.dumps(result, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="harness",
                                description="Authorized web bug-bounty triage harness")
    p.add_argument("--db", default="harness.db", help="SQLite datastore path")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the datastore").set_defaults(func=_cmd_init)
    sub.add_parser("adapters", help="list ingest adapters").set_defaults(func=_cmd_adapters)

    sp = sub.add_parser("ingest", help="parse a tool output into findings")
    sp.add_argument("--tool", required=True)
    sp.add_argument("--file", required=True)
    sp.add_argument("--program")
    sp.add_argument("--in-scope", action="store_true")
    sp.add_argument("--roe-ok", action="store_true")
    sp.add_argument("--authorized-by")
    sp.set_defaults(func=_cmd_ingest)

    sp = sub.add_parser("classify", help="run the CWE classifier + gate over findings")
    sp.add_argument("--classifier", help="path to a trained model.pkl (else keyword baseline)")
    sp.add_argument("--gate", type=float, default=0.80)
    sp.add_argument("--all", action="store_true",
                    help="re-classify all machine-set states (NEW/NEEDS_REVIEW/TRIAGED), "
                         "e.g. after a model swap; human decisions are preserved")
    sp.add_argument("--status", help="classify only this status (default: NEW)")
    sp.set_defaults(func=_cmd_classify)

    sp = sub.add_parser("score", help="compute CVSS base score (seeds from CWE priors if needed)")
    sp.add_argument("--no-prior", action="store_true",
                    help="do not seed a vector from the CWE->CVSS prior table")
    sp.set_defaults(func=_cmd_score)

    sp = sub.add_parser("enrich", help="pull EPSS / KEV / NVD for findings with a CVE id")
    sp.add_argument("--no-epss", action="store_true")
    sp.add_argument("--no-kev", action="store_true")
    sp.add_argument("--nvd", action="store_true", help="also pull official CVSS/CWE from NVD")
    sp.set_defaults(func=_cmd_enrich)

    sp = sub.add_parser("prioritize", help="fuse CVSS + EPSS + KEV + PoC into a priority score")
    sp.add_argument("--no-kev", action="store_true")
    sp.set_defaults(func=_cmd_prioritize)

    sp = sub.add_parser("predict-exploit",
                        help="finding-level exploit-likelihood (trained model or heuristic)")
    sp.add_argument("--model", help="trained exploit model (.pkl); omit to use the heuristic")
    sp.add_argument("--no-kev", action="store_true")
    sp.set_defaults(func=_cmd_predict_exploit)

    sp = sub.add_parser("list", help="list findings")
    sp.add_argument("--status")
    sp.add_argument("--sort", choices=["priority", "updated"], default="updated")
    sp.set_defaults(func=_cmd_list)

    sp = sub.add_parser("show", help="dump one finding as JSON")
    sp.add_argument("--id", required=True)
    sp.set_defaults(func=_cmd_show)

    sp = sub.add_parser("export", help="export findings to DefectDojo generic-import JSON")
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=_cmd_export)

    sp = sub.add_parser("train", help="train the sklearn CWE classifier")
    sp.add_argument("--data", required=True, help="JSONL/JSON of {text,cwe[,date]}")
    sp.add_argument("--model", required=True, help="output model path (.pkl)")
    sp.set_defaults(func=_cmd_train)

    sp = sub.add_parser("evaluate", help="temporal-split evaluation of the CWE classifier")
    sp.add_argument("--data", required=True, help="JSONL/JSON of {text,cwe,date}")
    sp.add_argument("--train-frac", type=float, default=0.8)
    sp.add_argument("--gate", type=float, default=0.80)
    sp.set_defaults(func=_cmd_evaluate)

    sp = sub.add_parser("train-exploit", help="train the finding-level exploit-likelihood model")
    sp.add_argument("--data", required=True, help="JSONL/JSON of feature rows + 'exploited' 0/1")
    sp.add_argument("--model", required=True, help="output model path (.pkl)")
    sp.set_defaults(func=_cmd_train_exploit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
