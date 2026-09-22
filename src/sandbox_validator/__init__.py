"""Milestone 5 sandbox validation for explicitly supported controls.

The package is intentionally local-only.  It does not discover targets, connect to
remote systems, execute CIS prose, or prove that the local machine is disposable.
"""

from .models import ValidationDecision, ValidationReport

__all__ = ["ValidationDecision", "ValidationReport"]
