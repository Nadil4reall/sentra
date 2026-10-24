"""Local, non-secret sandbox operator policy loaded by systemd."""

from __future__ import annotations

import os


SANDBOX_OPERATOR_ACK_ENVIRONMENT_KEY = "SENTRA_SANDBOX_OPERATOR_ACKNOWLEDGED"


def local_sandbox_operator_acknowledged() -> bool:
    """Read only the fixed local setting supplied by the fixed EnvironmentFile."""

    return os.environ.get(SANDBOX_OPERATOR_ACK_ENVIRONMENT_KEY) == "true"
