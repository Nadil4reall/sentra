"""Credential generation and verification for the M6 controller boundary.

Only salted, one-way PBKDF2 representations are intended for persistence.
Protocol credentials remain ``SecretStr`` values so normal representations do
not reveal plaintext tokens.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from pydantic import SecretStr


_ALGORITHM = "pbkdf2_sha256"
_HASH_NAME = "sha256"
_DEFAULT_ITERATIONS = 600_000
_MINIMUM_ITERATIONS = 100_000
_MAXIMUM_ITERATIONS = 10_000_000
_SALT_BYTES = 16
_TOKEN_BYTES = 32
_DIGEST_BYTES = 32


def _plaintext(credential: SecretStr | str) -> str:
    value = (
        credential.get_secret_value()
        if isinstance(credential, SecretStr)
        else credential
    )
    if not isinstance(value, str) or not value:
        raise ValueError("credential must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class CredentialHash:
    """Serializable salted credential verifier, never a plaintext credential."""

    iterations: int
    salt: bytes
    digest: bytes

    def __post_init__(self) -> None:
        if not _MINIMUM_ITERATIONS <= self.iterations <= _MAXIMUM_ITERATIONS:
            raise ValueError("credential hash iteration count is outside safe bounds")
        if len(self.salt) < _SALT_BYTES:
            raise ValueError("credential hash salt is too short")
        if len(self.digest) != _DIGEST_BYTES:
            raise ValueError("credential hash digest has an invalid length")

    def to_storage(self) -> str:
        """Return a versioned, database-safe encoding."""

        return "$".join(
            (_ALGORITHM, str(self.iterations), self.salt.hex(), self.digest.hex())
        )

    @classmethod
    def from_storage(cls, encoded: str) -> "CredentialHash":
        """Parse and validate a stored credential representation."""

        if not isinstance(encoded, str):
            raise ValueError("stored credential hash must be a string")
        try:
            algorithm, iteration_text, salt_hex, digest_hex = encoded.split("$")
            if algorithm != _ALGORITHM:
                raise ValueError("unsupported credential hash algorithm")
            iterations = int(iteration_text)
            salt = bytes.fromhex(salt_hex)
            digest = bytes.fromhex(digest_hex)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid stored credential hash") from exc
        return cls(iterations=iterations, salt=salt, digest=digest)

    def __repr__(self) -> str:
        return f"CredentialHash(iterations={self.iterations}, value=<redacted>)"


def generate_credential(*, token_bytes: int = _TOKEN_BYTES) -> SecretStr:
    """Generate a cryptographically strong opaque bearer credential."""

    if token_bytes < _TOKEN_BYTES:
        raise ValueError("credential entropy must be at least 256 bits")
    return SecretStr(secrets.token_urlsafe(token_bytes))


def hash_credential(
    credential: SecretStr | str,
    *,
    iterations: int = _DEFAULT_ITERATIONS,
) -> CredentialHash:
    """Create a new independently salted verifier for a credential."""

    plaintext = _plaintext(credential)
    if not _MINIMUM_ITERATIONS <= iterations <= _MAXIMUM_ITERATIONS:
        raise ValueError("credential hash iteration count is outside safe bounds")
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        _HASH_NAME,
        plaintext.encode("utf-8"),
        salt,
        iterations,
        dklen=_DIGEST_BYTES,
    )
    return CredentialHash(iterations=iterations, salt=salt, digest=digest)


def verify_credential(
    credential: SecretStr | str,
    expected: CredentialHash | str,
) -> bool:
    """Verify a credential with a constant-time digest comparison.

    Malformed stored values are authentication failures rather than a source
    of parsing details at the authentication boundary.
    """

    try:
        plaintext = _plaintext(credential)
        credential_hash = (
            CredentialHash.from_storage(expected)
            if isinstance(expected, str)
            else expected
        )
        if not isinstance(credential_hash, CredentialHash):
            return False
        candidate = hashlib.pbkdf2_hmac(
            _HASH_NAME,
            plaintext.encode("utf-8"),
            credential_hash.salt,
            credential_hash.iterations,
            dklen=_DIGEST_BYTES,
        )
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(candidate, credential_hash.digest)


class CredentialVerifier:
    """Purpose-specific verifier facade that retains no plaintext secret."""

    __slots__ = ("_expected",)

    def __init__(self, expected: CredentialHash | str) -> None:
        self._expected = (
            CredentialHash.from_storage(expected)
            if isinstance(expected, str)
            else expected
        )
        if not isinstance(self._expected, CredentialHash):
            raise TypeError("expected must be a CredentialHash or its encoding")

    def verify(self, supplied: SecretStr | str) -> bool:
        return verify_credential(supplied, self._expected)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(credential=<redacted>)"


class BootstrapCredentialVerifier(CredentialVerifier):
    """Verifier for the one-time enrollment boundary."""


class AdminCredentialVerifier(CredentialVerifier):
    """Verifier for controller-administrator requests."""


__all__ = [
    "AdminCredentialVerifier",
    "BootstrapCredentialVerifier",
    "CredentialHash",
    "CredentialVerifier",
    "generate_credential",
    "hash_credential",
    "verify_credential",
]
