"""
agentmem.config — tunables + the capability ontology that drives chain detection.

Everything the memory's behavior depends on lives here so it is auditable and
easy to extend: scoring weights (Generative Agents), decay (MemoryBank), trust
ranks + the capability ontology, per-vuln-class provides/requires extractors,
and the escalation rules that terminate a chain at a high-value goal.

Design source: the 28-paper synthesis spec, §0/§3/§4/§6.
"""
from __future__ import annotations

# --- retrieval scoring (Generative Agents composite; recency in STEPS) ------ #
W_RELEVANCE = 1.0
W_IMPORTANCE = 1.0
W_RECENCY = 0.5
W_CONFIDENCE = 0.8
RECENCY_LAMBDA = 0.02          # exp(-lambda * delta_step); steps, not wall-clock

# --- forgetting (MemoryBank Ebbinghaus) — RANKING ONLY, never deletes ------- #
DECAY_S0 = 20.0                # base memory strength; R = exp(-delta_step / S)
PIN_FLOOR = 1.0               # pinned nodes get this retrieval floor

# --- chain search caps (keep it bounded / deterministic) ------------------- #
CHAIN_MAX_DEPTH = 6
CHAIN_MAX_WIDTH = 64           # frontier cap per expansion
CHAIN_MIN_CONFIDENCE = 0.05    # prune paths whose running product drops below

# --- consensus promotion (N corroborating observations confirm a finding) --- #
CONSENSUS_N = 2               # distinct observations needed to confirm without an oracle
CONSENSUS_CONFIDENCE = 0.7    # weaker than an oracle's 0.9

# --- embeddings / semantic recall (optional; stdlib hashing fallback) ------- #
EMBED_DIM = 256
SAME_AS_THRESHOLD = 0.86      # conservative — advisory synonym edge only, never merge
RRF_K = 60                    # reciprocal-rank-fusion constant

# --- trust levels (AI-Meets-Brain): higher seeds chains at full confidence -- #
TRUST_RANK = {
    "tool_verified": 3,
    "agent_asserted": 2,
    "llm_inferred": 1,
    "target_derived": 0,       # target response text — data, never instruction
}
DEFAULT_TRUST = "agent_asserted"
# only findings at/above this trust may seed a chain at full confidence
CHAIN_SEED_MIN_TRUST = "agent_asserted"

# --- severity of goal capabilities (chain terminals) ----------------------- #
GOAL_SEVERITY = {
    "rce": 10,
    "full_db_read": 9,
    "account_takeover": 9,
    "privilege_escalation": 8,
    "token_theft": 8,
    "pii_exfil": 7,
}
GOALS = set(GOAL_SEVERITY)

# --- per-vuln_class capability extractors ---------------------------------- #
# For a Finding of vuln_class C, PROVIDES[C](attrs) and REQUIRES[C](attrs) build
# the capability tokens. attrs come from the finding (host, param, object, ...).
# A token is (name, {attr: value}); a REQUIRES attr value may be "*", a concrete
# value, or "in:<glob>" (membership constraint). See capabilities.unify().

def _g(attrs, key, default="*"):
    v = attrs.get(key)
    return v if v not in (None, "") else default


PROVIDES = {
    "open_redirect":   lambda a: [("controlled_redirect", {"host": _g(a, "host"), "param": _g(a, "param")})],
    "oauth_redirect":  lambda a: [("oauth_code_delivery", {"to": _g(a, "redirect_param", "redirect_uri")})],
    "xss":             lambda a: [("reflected_input", {"context": _g(a, "context", "html"), "param": _g(a, "param")})],
    "idor":            lambda a: [("arbitrary_read", {"object": _g(a, "object", "record"), "scope": _g(a, "scope", "any_user")})],
    "idor_write":      lambda a: [("arbitrary_write", {"object": _g(a, "object", "record"), "scope": _g(a, "scope", "any_user")})],
    "info_leak":       lambda a: [("leaked_secret", {"type": _g(a, "secret_type", "sensitive"), "subject": _g(a, "subject", "any_user")})],
    "ssrf":            lambda a: [("ssrf", {"egress": _g(a, "egress", "internal")})],
    "cors":            lambda a: [("open_cors", {"origin": _g(a, "origin")})],
    "csrf":            lambda a: [("csrf", {"action": _g(a, "action")})],
    "sqli":            lambda a: [("sqli", {"dbms": _g(a, "dbms", "unknown")})],
    "auth_bypass":     lambda a: [("auth_bypass", {"scope": _g(a, "scope", "user")})],
    "cloud_metadata":  lambda a: [("cloud_credentials", {"provider": _g(a, "provider", "aws")})],
}

REQUIRES = {
    # OAuth code delivery is only useful if the attacker controls a redirect the
    # allowlist accepts. `allow` is a glob of accepted hosts (e.g. "*.target.com").
    "oauth_redirect":  lambda a: [("controlled_redirect", {"host": "in:" + _g(a, "allow", "*")})],
    # exfiltrating a secret from a record first needs read access to that record
    "info_leak":       lambda a: [("arbitrary_read", {"object": _g(a, "object", "*")})],
    # the cloud-metadata step needs server-side request forgery to reach it
    "cloud_metadata":  lambda a: [("ssrf", {"egress": "in:internal*"})],
}

# --- escalation rules: a path reaches a GOAL when its accumulated provides --- #
# satisfy ALL `need` tokens of a rule. Each need is a (name, attr-constraints).
ESCALATION_RULES = [
    {"goal": "token_theft",
     "need": [("oauth_code_delivery", {}), ("controlled_redirect", {})]},
    {"goal": "account_takeover",
     "need": [("leaked_secret", {"type": "in:*token*"})]},
    {"goal": "account_takeover",
     "need": [("leaked_secret", {"type": "in:*reset*"})]},
    {"goal": "account_takeover",
     "need": [("arbitrary_write", {"scope": "in:*admin*"})]},
    {"goal": "account_takeover",
     "need": [("auth_bypass", {"scope": "in:*admin*"})]},
    {"goal": "privilege_escalation",
     "need": [("cloud_credentials", {})]},
    {"goal": "full_db_read",
     "need": [("sqli", {})]},
    {"goal": "pii_exfil",
     "need": [("arbitrary_read", {"scope": "in:*any*"})]},
]

# --- prompt-injection markers to strip from target-derived text (security) -- #
INJECTION_MARKERS = [
    "ignore previous", "ignore all previous", "disregard previous",
    "system prompt", "you are now", "new instructions", "assistant:",
    "<|im_start|>", "<|im_end|>", "###instruction", "[/inst]", "[inst]",
]
