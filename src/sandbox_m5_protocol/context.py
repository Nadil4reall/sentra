"""Canonical context binding for the post-ACK M5 session."""

from __future__ import annotations

import hashlib

from src.sandbox_protocol import SandboxContextManifest, encode_sandbox_context_frame


def sandbox_context_sha256(manifest: SandboxContextManifest) -> str:
    """Hash only the canonical framed context bytes used in the first phase."""

    if type(manifest) is not SandboxContextManifest:
        raise TypeError("context fingerprint requires a SandboxContextManifest")
    canonical_frame = encode_sandbox_context_frame(manifest)
    return hashlib.sha256(canonical_frame).hexdigest()
