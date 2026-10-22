"""
agentmem.canonical — normalization + dedup keys + entity resolution (spec §4.2).

Canonicalization-first (not embedding-merge) because scoping is safety-critical:
an agent that names `id` / `user_id` / `uid` differently across restarts, or hits
`/api/user/1` then `/api/user/2`, must map to ONE node. We normalize hosts, paths
(numeric/uuid segments -> `{id}`), and param names, and build a stable
`canonical_key`. Distinct endpoints are NEVER auto-merged on similarity.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

_NUM = re.compile(r"^\d+$")
_HEX = re.compile(r"^[0-9a-f]{8,}$", re.I)
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_DEFAULT_PORTS = {"http": "80", "https": "443"}


def norm_host(host: str) -> str:
    """Lowercase, strip default ports and a trailing dot."""
    if not host:
        return ""
    h = host.strip().lower().rstrip(".")
    if ":" in h:
        name, _, port = h.partition(":")
        # keep non-default ports as part of identity
        if port in ("80", "443", ""):
            h = name
    return h


def norm_path(path: str) -> str:
    """Collapse //, resolve . and .., and replace id-like segments with {id}."""
    if not path:
        return "/"
    # resolve . / .. and collapse slashes
    parts: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        if _NUM.match(seg) or _UUID.match(seg) or _HEX.match(seg):
            parts.append("{id}")
        else:
            # keep segment case: /Admin and /admin are distinct on case-sensitive
            # origins, and merging them would lose a finding (spec §4.2).
            parts.append(seg)
    return "/" + "/".join(parts)


def norm_param(name: str) -> str:
    return (name or "").strip().lower()


def _key(*parts: str) -> str:
    basis = "|".join(p for p in parts)
    return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:20]


def host_key(host: str) -> str:
    return _key("host", norm_host(host))


def endpoint_key(method: str, host: str, path: str) -> str:
    return _key("endpoint", (method or "GET").upper(), norm_host(host), norm_path(path))


def param_key(method: str, host: str, path: str, name: str, location: str = "query") -> str:
    return _key("param", (method or "GET").upper(), norm_host(host),
                norm_path(path), norm_param(name), location)


def tech_key(name: str, version: str = "") -> str:
    return _key("tech", (name or "").strip().lower(), (version or "").strip().lower())


def finding_key(vuln_class: str, host: str, path: str, param: str = "") -> str:
    return _key("finding", (vuln_class or "").lower(), norm_host(host),
                norm_path(path), norm_param(param))


def split_url(url: str) -> tuple[str, str]:
    """Return (host, path) from a URL or host/path string."""
    u = url if "://" in url else "//" + url
    parts = urlsplit(u)
    host = parts.hostname or ""
    if parts.port and str(parts.port) not in _DEFAULT_PORTS.values():
        host = f"{host}:{parts.port}"
    return host, parts.path or "/"
