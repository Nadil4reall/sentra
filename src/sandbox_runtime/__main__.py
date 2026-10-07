"""Run exactly one fixed sandbox-context receive operation."""

from __future__ import annotations

import sys

from .receiver import open_fixed_validation_channel_and_receive


EXIT_ACCEPTED = 0
EXIT_CONTEXT_REJECTED = 2
EXIT_RECEIVER_FAILURE = 3


def main() -> int:
    """Receive one context and return a fixed, non-sensitive status code."""

    if len(sys.argv) != 1:
        return EXIT_CONTEXT_REJECTED

    try:
        result = open_fixed_validation_channel_and_receive()
    except Exception:
        # Keep receiver and unexpected runtime diagnostics out of appliance logs.
        return EXIT_RECEIVER_FAILURE

    if result.manifest is not None and result.acknowledgement.status == "accepted":
        return EXIT_ACCEPTED
    return EXIT_CONTEXT_REJECTED


if __name__ == "__main__":
    raise SystemExit(main())
