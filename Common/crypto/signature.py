"""ML-DSA-65 (FIPS 204) digital signatures — the "Dilithium3" of Ref[54].

Ref[54] signs twice: the edge device signs each record at Phase 2
(``sigma_edge``), and the fog tier threshold-signs the aggregated index root at
Phase 3. Both are named Dilithium3, which is the pre-standardisation name for
what FIPS 204 standardised as ML-DSA-65 — the NIST Category 3 parameter set,
matching that paper's stated ``lambda = 192``.

WHY THIS IS A SHARED PRIMITIVE
------------------------------
Same reason as ``kem.py``: ``run_meta.json`` has to record which
implementation produced a number, and a signature that silently changed backend
between runs would make two figures incomparable without anything saying so.
``available_backends`` is what gets recorded.

WHY BACKENDS ARE PROBED RATHER THAN IMPORTED
--------------------------------------------
``kem.py`` learned this the hard way: its ``cryptography`` backend was written
against ``mlkem.MLKEMParameterSet``, an API that no release ever shipped, so
the primary backend failed on every host and the error only surfaced as a
missing-backend message. Each backend here therefore resolves the exact classes
it needs in ``__init__``, so a version that does not have them raises during
probing and the next backend is tried.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

# FIPS 204 fixed sizes for the ML-DSA-65 parameter set.
VERIFYING_KEY_BYTES = 1952
SIGNATURE_BYTES = 3309


class SignatureUnavailableError(RuntimeError):
    """Raised when no ML-DSA-65 implementation can be found."""


class SignatureError(RuntimeError):
    """Raised when a signature does not verify."""


@dataclass(frozen=True)
class SigningKeyPair:
    verifying_key: bytes   # public
    signing_key: bytes     # secret (seed form on the cryptography backend)


class MLDSA65:
    """ML-DSA-65 with automatic backend selection."""

    def __init__(self, backend: Optional[str] = None) -> None:
        self._impl, self.backend = _select_backend(backend)

    def keygen(self) -> SigningKeyPair:
        return self._impl.keygen()

    def sign(self, signing_key: bytes, message: bytes) -> bytes:
        return self._impl.sign(signing_key, message)

    def verify(self, verifying_key: bytes, message: bytes, signature: bytes) -> bool:
        return self._impl.verify(verifying_key, message, signature)

    def self_test(self) -> bool:
        kp = self.keygen()
        sig = self.sign(kp.signing_key, b"self-test")
        return (
            self.verify(kp.verifying_key, b"self-test", sig)
            and not self.verify(kp.verifying_key, b"tampered", sig)
            and len(sig) == SIGNATURE_BYTES
        )


class _CryptographyBackend:
    """``cryptography``'s native ML-DSA API (46+).

    The signing key is the FIPS 204 seed, which is what ``private_bytes_raw``
    exposes and ``from_seed_bytes`` reconstructs from — the same representation
    difference documented for ML-KEM in ``kem.py``.
    """

    name = "cryptography"

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # type: ignore

        self._private = mldsa.MLDSA65PrivateKey  # type: ignore[attr-defined]
        self._public = mldsa.MLDSA65PublicKey  # type: ignore[attr-defined]

    def keygen(self) -> SigningKeyPair:
        private = self._private.generate()
        return SigningKeyPair(
            verifying_key=private.public_key().public_bytes_raw(),
            signing_key=private.private_bytes_raw(),
        )

    def sign(self, signing_key: bytes, message: bytes) -> bytes:
        return self._private.from_seed_bytes(signing_key).sign(message)

    def verify(self, verifying_key: bytes, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            self._public.from_public_bytes(verifying_key).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True


class _LiboqsBackend:
    """Open Quantum Safe (``oqs``)."""

    name = "liboqs"
    _ALG = "ML-DSA-65"

    def __init__(self) -> None:
        import oqs  # type: ignore

        self._oqs = oqs
        if self._ALG not in oqs.get_enabled_sig_mechanisms():
            raise ImportError(f"liboqs lacks {self._ALG}")

    def keygen(self) -> SigningKeyPair:
        with self._oqs.Signature(self._ALG) as sig:
            public = sig.generate_keypair()
            return SigningKeyPair(
                verifying_key=public, signing_key=sig.export_secret_key()
            )

    def sign(self, signing_key: bytes, message: bytes) -> bytes:
        with self._oqs.Signature(self._ALG, signing_key) as sig:
            return sig.sign(message)

    def verify(self, verifying_key: bytes, message: bytes, signature: bytes) -> bool:
        with self._oqs.Signature(self._ALG) as sig:
            return bool(sig.verify(message, signature, verifying_key))


_BACKEND_ORDER: List[Tuple[str, Callable[[], object]]] = [
    (_CryptographyBackend.name, _CryptographyBackend),
    (_LiboqsBackend.name, _LiboqsBackend),
]


def _select_backend(requested: Optional[str]) -> Tuple[object, str]:
    tried: List[str] = []
    for name, factory in _BACKEND_ORDER:
        if requested and name != requested:
            continue
        try:
            return factory(), name
        except Exception as exc:
            tried.append(f"{name} ({type(exc).__name__}: {exc})")

    raise SignatureUnavailableError(
        f"no ML-DSA-65 backend available (requested: {requested or 'any'}).\n"
        f"Tried: {'; '.join(tried) if tried else 'none'}\n"
        f"Install one of:\n"
        f"  pip install 'cryptography>=46'\n"
        f"  pip install liboqs-python"
    )


def available_backends() -> dict[str, bool]:
    """Which ML-DSA backends import here — recorded in ``run_meta.json``."""
    status: dict[str, bool] = {}
    for name, factory in _BACKEND_ORDER:
        try:
            factory()
            status[name] = True
        except Exception:
            status[name] = False
    return status


__all__ = [
    "SIGNATURE_BYTES",
    "VERIFYING_KEY_BYTES",
    "MLDSA65",
    "SignatureError",
    "SignatureUnavailableError",
    "SigningKeyPair",
    "available_backends",
]
