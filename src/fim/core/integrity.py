"""HMAC-SHA256 baseline authentication, key management, and cryptographic sealing."""

import hashlib
import hmac
import secrets
from pathlib import Path

from fim.config.settings import settings


class IntegrityError(Exception):
    """Raised when cryptographic key or signature validation fails."""


def generate_key(key_bytes: int | None = None) -> bytes:
    """Generate cryptographically secure 256-bit random key.

    Args:
        key_bytes: Number of random bytes. Defaults to settings.HMAC_KEY_BYTES.

    Returns:
        Raw CSPRNG byte sequence.
    """
    length = key_bytes or settings.HMAC_KEY_BYTES
    return secrets.token_bytes(length)


def save_key(key: bytes, key_path: Path) -> None:
    """Persist HMAC secret key with restricted POSIX permissions (0600).

    Args:
        key: Raw key bytes to store.
        key_path: Path where key should be saved.

    Raises:
        IntegrityError: If key is too weak or destination cannot be secured.
    """
    if len(key) < 32:
        raise IntegrityError("HMAC authentication key must be at least 32 bytes (256 bits).")

    try:
        # Create or overwrite file with owner read/write permissions only
        key_path.write_bytes(key)
        key_path.chmod(0o600)
    except OSError as exc:
        raise IntegrityError(f"Failed to persist secure key to '{key_path}': {exc}") from exc


def load_key(key_path: Path) -> bytes:
    """Load HMAC secret key from file and validate sufficient entropy length.

    Args:
        key_path: Path to existing secret key file.

    Returns:
        Raw secret key bytes.

    Raises:
        IntegrityError: If file is missing, inaccessible, or shorter than 32 bytes.
    """
    if not key_path.exists():
        raise IntegrityError(f"Authentication key file '{key_path}' does not exist.")

    try:
        key = key_path.read_bytes()
    except OSError as exc:
        raise IntegrityError(f"Unable to read key from '{key_path}': {exc}") from exc

    if len(key) < 32:
        raise IntegrityError(
            f"Key in '{key_path}' is insufficiently secure (length {len(key)} < 32 bytes)."
        )

    return key


def sign_payload(payload: bytes, key: bytes) -> str:
    """Compute HMAC-SHA256 authentication digest for arbitrary payload bytes.

    Args:
        payload: Binary data to sign.
        key: Cryptographic HMAC key.

    Returns:
        Hex-encoded HMAC digest string.
    """
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_payload(payload: bytes, expected_signature: str, key: bytes) -> bool:
    """Verify payload integrity against expected signature in constant time.

    Args:
        payload: Binary data to verify.
        expected_signature: Hex-encoded signature string.
        key: Cryptographic HMAC key.

    Returns:
        True if signature matches in constant time, False otherwise.
    """
    computed = sign_payload(payload, key)
    return hmac.compare_digest(computed.lower(), expected_signature.strip().lower())
