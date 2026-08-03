"""Authenticated symmetric encryption: AES-256-GCM.

README §1 fixes AES-256-GCM as the symmetric primitive for the whole
benchmark. Ref[35] specifies only an abstract "symmetric encryption SE"
(Ref[35].txt:1535), so it uses this same primitive — which is the point of a
shared layer: the SE cost is identical across schemes and cannot explain a
latency difference between them.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .rng import secure_random_bytes

KEY_BYTES = 32   # AES-256
NONCE_BYTES = 12  # 96-bit nonce, SP 800-38D recommended size
TAG_BYTES = 16   # 128-bit authentication tag


class DecryptionError(RuntimeError):
    """Raised when authenticated decryption fails (wrong key or tampering)."""


@dataclass(frozen=True)
class Ciphertext:
    """AES-GCM output. ``tag`` is appended to ``body`` by the AESGCM API."""

    nonce: bytes
    body: bytes  # ciphertext || tag

    def to_bytes(self) -> bytes:
        """Wire format: nonce || ciphertext || tag."""
        return self.nonce + self.body

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Ciphertext":
        if len(raw) < NONCE_BYTES + TAG_BYTES:
            raise DecryptionError(
                f"ciphertext too short: {len(raw)} bytes, need at least "
                f"{NONCE_BYTES + TAG_BYTES}"
            )
        return cls(nonce=raw[:NONCE_BYTES], body=raw[NONCE_BYTES:])

    @property
    def size_bytes(self) -> int:
        """Total on-the-wire size — reported as a secondary metric."""
        return len(self.nonce) + len(self.body)


def generate_key() -> bytes:
    """Fresh AES-256 key from OS entropy."""
    return secure_random_bytes(KEY_BYTES)


def encrypt(key: bytes, plaintext: bytes, *, associated_data: bytes = b"") -> Ciphertext:
    """Encrypt under AES-256-GCM with a fresh random nonce.

    A fresh nonce per call is mandatory: GCM catastrophically loses both
    confidentiality and authenticity if a (key, nonce) pair repeats. Random
    96-bit nonces are safe here because no single benchmark key encrypts
    anywhere near 2^32 messages.
    """
    _check_key(key)
    nonce = secure_random_bytes(NONCE_BYTES)
    body = AESGCM(key).encrypt(nonce, plaintext, associated_data or None)
    return Ciphertext(nonce=nonce, body=body)


def decrypt(key: bytes, ciphertext: Ciphertext, *, associated_data: bytes = b"") -> bytes:
    """Decrypt and verify. Raises ``DecryptionError`` on any failure."""
    _check_key(key)
    try:
        return AESGCM(key).decrypt(
            ciphertext.nonce, ciphertext.body, associated_data or None
        )
    except Exception as exc:  # cryptography raises InvalidTag
        raise DecryptionError("AES-GCM authentication failed") from exc


def _check_key(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise ValueError(
            f"AES-256 requires a {KEY_BYTES}-byte key, got {len(key)}"
        )


def ciphertext_overhead() -> int:
    """Bytes added on top of the plaintext length.

    Exp. 1 reports trapdoor size and Exp. 4 reports proof size; both need the
    overhead stated rather than measured off one sample.
    """
    return NONCE_BYTES + TAG_BYTES
