# Stage 0 — Authorization (scope + rules of engagement)

**This harness is for authorized testing only.** A finding is actionable only
when BOTH conditions hold. A host being in scope is **not** permission to attack
it however you like.

Fill one of these per program before you run anything, and feed it to the
scaffold via `--program/--in-scope/--roe-ok/--authorized-by`. The scaffold
*records* this; it does **not yet enforce** it — a real scope/ROE enforcement
engine (URL-to-allowlist matching + per-request rate/technique checks) is a
BUILD gap (see README).

---

## Program: `<name>`

- **Platform / URL:** <HackerOne/Bugcrowd/self-hosted + policy link>
- **Authorization confirmed:** <date> by <who> (you, reading the policy)
- **Written policy snapshot saved at:** <path> *(keep a dated copy — policies change)*

### In scope (assets)
```
# exact domains / wildcards / CIDRs / apps that ARE in scope
*.example.com
api.example.com
```

### Out of scope (never touch)
```
# explicitly excluded assets, third-party SaaS, prod payment paths, etc.
blog.example.com         # WordPress, hosted by third party
*.vendor-crm.com
```

### Rules of engagement (behavior, not just hosts)
- [ ] **Automated scanning allowed?**  yes / no / rate-limited
- [ ] **Max request rate:** <e.g. 5 req/s, 1 thread>
- [ ] **Prohibited tools/techniques:** <e.g. no sqlmap, no ffuf brute force, no automated fuzzing>
- [ ] **Account/test-data rules:** <use only your test accounts; no other users' data>
- [ ] **No destructive actions:** confirmed — **validate with a non-destructive
      PoC only**; never exfiltrate real data, modify/delete records, upload
      shells, or cause DoS on a live target.
- [ ] **PII / data handling:** stop on real PII; report immediately; do not store.
- [ ] **Disclosure:** <program's disclosure terms>

### Validation boundary (important)
The CVE-Bench-style impact oracle (DB-checksum, planted secret table, sentinel
file, forced admin login) is **destructive and sandbox-only**. Use it against an
authorized staging replica you control — **never** against a live program target.
On live targets, proof = a benign, reversible demonstration + screenshots.
