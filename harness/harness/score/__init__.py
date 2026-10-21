"""CVSS scoring: compute the score from a vector with the official equations."""
from .cvss31 import (CVSS31_METRICS, base_score, parse_vector,  # noqa: F401
                     score_vector, severity_of)
