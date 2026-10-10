"""Run exactly one fixed 7.1.1 sandbox M5 validation session."""

from __future__ import annotations

import sys

from src.sandbox_m5_protocol.models import SandboxM5SessionResult

from .config import local_sandbox_operator_acknowledged
from .receiver import _diagnostic_failure
from .session_channel import open_fixed_validation_channel_and_run_session


EXIT_ACCEPTED = 0
EXIT_CONTEXT_REJECTED = 2
EXIT_SESSION_FAILURE = 3
EXIT_RECEIVER_FAILURE = EXIT_SESSION_FAILURE


def main() -> int:
    """Run the fixed local-authorized session with non-sensitive exit status."""

    if len(sys.argv) != 1:
        return EXIT_CONTEXT_REJECTED

    try:
        sandbox_operator_acknowledged = local_sandbox_operator_acknowledged()
        result = open_fixed_validation_channel_and_run_session(
            sandbox_operator_acknowledged=sandbox_operator_acknowledged,
        )
    except Exception as error:
        # Only the exception class is recorded; never log exception text or inputs.
        _diagnostic_failure(error)
        return EXIT_SESSION_FAILURE

    if type(result) is SandboxM5SessionResult:
        return EXIT_ACCEPTED
    return EXIT_SESSION_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
