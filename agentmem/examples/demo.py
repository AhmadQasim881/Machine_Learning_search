#!/usr/bin/env python3
"""
agentmem demo — runs the three worked exploit-chain examples (spec §4.4) and
prints the chains the memory discovers by capability unification. No deps.

    python examples/demo.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agentmem import Memory  # noqa: E402


def main() -> int:
    db = os.path.join(tempfile.mkdtemp(), "demo.db")
    m = Memory(db)

    # A) open-redirect + OAuth -> token theft
    m.add_finding("open_redirect", host="app.target.com", path="/out", param="url",
                  confirmed=True, oracle="302 Location reflects url",
                  attrs={"host": "app.target.com"})
    m.add_finding("oauth_redirect", host="app.target.com", path="/oauth/authorize",
                  param="redirect_uri", confirmed=True, oracle="code delivered to redirect_uri",
                  attrs={"allow": "*.target.com"})

    # B) IDOR + info-leak -> account takeover
    m.add_finding("idor", host="api.target.com", path="/api/user/5", param="id",
                  confirmed=True, oracle="returned another user's record",
                  attrs={"object": "user_record", "scope": "any_user"})
    m.add_finding("info_leak", host="api.target.com", path="/api/user/5",
                  confirmed=True, oracle="password-reset token present in body",
                  attrs={"object": "user_record", "secret_type": "reset_token"})

    # C) SSRF + cloud metadata -> cloud creds -> privilege escalation
    m.add_finding("ssrf", host="api.target.com", path="/fetch", param="imageUrl",
                  confirmed=True, oracle="internal host fetched", attrs={"egress": "internal"})
    m.add_technique_rule("aws_metadata",
                         provides=[("cloud_credentials", {"provider": "aws"})],
                         requires=[("ssrf", {"egress": "in:internal*"})])

    print("=== discovered exploit chains (by capability unification) ===\n")
    for ch in m.chains():
        print(f"  [severity {ch['severity']}]  {ch['goal'].upper()}  "
              f"(score {ch['score']}, {ch['status']})")
        print(f"      {ch['narrative']}\n")

    snap = m.export()
    print("nodes:", snap["nodes"])
    print("\nnext probes (backward chaining — what would complete a chain):")
    for p in m.next_probes()[:5]:
        print(f"  -> toward {p['goal']}: obtain '{p['missing_capability']}' {p['constraints']}")
    m.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
