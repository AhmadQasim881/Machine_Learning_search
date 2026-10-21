"""Ingest adapters. Importing this package registers the built-in adapters."""
from .base import (Adapter, apply_authorization, available_adapters,  # noqa: F401
                   get_adapter, register)
from . import nuclei  # noqa: F401  (registers "nuclei")
from . import generic  # noqa: F401  (registers "generic")
