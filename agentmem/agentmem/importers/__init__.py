"""agentmem.importers — adapters that turn EXTERNAL analyzer output into research
evidence (value identities, explicit flow edges, evidence). The memory layer
records what these produce; it does not run the analyzers."""
from .sarif import import_sarif  # noqa: F401
