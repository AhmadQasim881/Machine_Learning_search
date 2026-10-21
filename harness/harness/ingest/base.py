"""
harness.ingest.base — the adapter contract.

Every scanner/tool gets a small adapter that turns its native output into a
list of normalized `Finding` records (the Sun 9-aspect spine). The rest of the
harness never sees tool-specific formats.

A registry lets the CLI pick an adapter by name. Adding a tool = write one
`Adapter` subclass and register it. This is intentionally the same shape mature
platforms (DefectDojo's "parsers") use, so adapters port over if you later
adopt one — see README.
"""
from __future__ import annotations

import abc
from typing import Callable, Optional

from ..schema import Authorization, Finding


class Adapter(abc.ABC):
    """Turn one tool's raw output (a file's text) into Finding records."""

    name: str = "base"

    @abc.abstractmethod
    def parse(self, raw_text: str) -> list[Finding]:
        ...

    def parse_file(self, path: str) -> list[Finding]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return self.parse(fh.read())


_REGISTRY: dict[str, Callable[[], Adapter]] = {}


def register(name: str) -> Callable[[type[Adapter]], type[Adapter]]:
    def deco(cls: type[Adapter]) -> type[Adapter]:
        cls.name = name
        _REGISTRY[name] = cls
        return cls
    return deco


def get_adapter(name: str) -> Adapter:
    if name not in _REGISTRY:
        raise KeyError(
            f"no ingest adapter '{name}'. available: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]()


def available_adapters() -> list[str]:
    return sorted(_REGISTRY)


def apply_authorization(findings: list[Finding], auth: Optional[Authorization]) -> None:
    """Stamp a program's Stage-0 authorization onto freshly parsed findings.

    NOTE: this records the *claimed* authorization passed on the CLI; it does
    not itself verify scope. A real scope/ROE enforcement engine (matching URLs
    to the program allow-list and rules) is a BUILD gap flagged in the design.
    """
    if auth is None:
        return
    for f in findings:
        f.authorization = auth
