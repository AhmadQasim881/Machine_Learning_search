"""
harness.cli — a thin command line over the scaffold.

    python -m harness init         --db harness.db
    python -m harness ingest       --tool nuclei --file out.jsonl --program acme --in-scope --roe-ok
    python -m harness classify     --db harness.db
    python -m harness list         --db harness.db [--status needs_review]
    python -m harness show         --db harness.db --id <finding-id>
    python -m harness adapters

Stdlib argparse only. The CLI wires the stages together; the real work lives in
the modules so it stays swappable.
"""
from __future__ import annotations

import argparse
import sys

from .classify import apply_gate, default_classifier
from .ingest import apply_authorization, available_adapters, get_adapter
from .schema import Authorization, Status
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
    auth = Authorization(
        program=args.program or "",
        in_scope=bool(args.in_scope),
        roe_ok=bool(args.roe_ok),
        authorized_by=args.authorized_by or "",
    )
    apply_authorization(findings, auth)

    new, dup = 0, 0
    with Store(args.db) as store:
        for f in findings:
            _, is_new = store.add_deduped(f)
            new += int(is_new)
            dup += int(not is_new)
    print(f"[+] ingested {len(findings)} record(s) via '{args.tool}': "
          f"{new} new, {dup} exact-duplicate")
    if findings and not (args.in_scope and args.roe_ok):
        print("[!] authorization NOT fully set (in-scope/ROE). These findings "
              "are recorded but marked not-actionable until you confirm scope "
              "and rules of engagement.", file=sys.stderr)
    return 0


def _cmd_classify(args) -> int:
    clf = default_classifier()
    gate = args.gate
    triaged = reviewed = 0
    with Store(args.db) as store:
        todo = list(store.iter_findings(status=Status.NEW))
        for f in todo:
            clf.classify(f)
            apply_gate(f, threshold=gate)
            store.upsert(f)
            if f.status == Status.TRIAGED:
                triaged += 1
            elif f.status == Status.NEEDS_REVIEW:
                reviewed += 1
    print(f"[+] classified {len(todo)} new finding(s) with '{clf.name}' "
          f"(gate={gate}): {triaged} auto-triaged, {reviewed} -> needs_review")
    return 0


def _cmd_list(args) -> int:
    status = Status(args.status) if args.status else None
    with Store(args.db) as store:
        counts = store.count_by_status()
        rows = list(store.iter_findings(status=status))
    if not args.status:
        print("status counts:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "(empty)")
    for f in rows:
        top = f.top_cwe()
        cwe = f"{top.cwe_id}@{top.confidence:.2f}" if top else "-"
        auth = "OK" if f.authorization.actionable else "UNAUTH"
        print(f"  {f.id[:8]} [{f.status.value:12}] {auth:6} {f.severity or '-':8} "
              f"{cwe:16} {(f.title or f.vuln_type)[:48]}  {f.host}")
    return 0


def _cmd_show(args) -> int:
    with Store(args.db) as store:
        f = store.get(args.id)
    if not f:
        print(f"[-] no finding {args.id}", file=sys.stderr)
        return 1
    print(f.to_json())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="harness",
                                description="Authorized web bug-bounty triage harness (scaffold)")
    p.add_argument("--db", default="harness.db", help="SQLite datastore path")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="create the datastore")
    sp.set_defaults(func=_cmd_init)

    sp = sub.add_parser("adapters", help="list ingest adapters")
    sp.set_defaults(func=_cmd_adapters)

    sp = sub.add_parser("ingest", help="parse a tool output into findings")
    sp.add_argument("--tool", required=True, help="adapter name (see 'adapters')")
    sp.add_argument("--file", required=True, help="tool output file")
    sp.add_argument("--program", help="bug-bounty program name")
    sp.add_argument("--in-scope", action="store_true", help="assets are on the program allow-list")
    sp.add_argument("--roe-ok", action="store_true", help="tool/rate/technique permitted by ROE")
    sp.add_argument("--authorized-by", help="who confirmed authorization")
    sp.set_defaults(func=_cmd_ingest)

    sp = sub.add_parser("classify", help="run the CWE classifier + gate over NEW findings")
    sp.add_argument("--gate", type=float, default=0.80, help="auto-accept confidence threshold")
    sp.set_defaults(func=_cmd_classify)

    sp = sub.add_parser("list", help="list findings")
    sp.add_argument("--status", help="filter by status")
    sp.set_defaults(func=_cmd_list)

    sp = sub.add_parser("show", help="dump one finding as JSON")
    sp.add_argument("--id", required=True)
    sp.set_defaults(func=_cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
