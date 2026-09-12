"""ML-KEM-768 (FIPS 203) key encapsulation.

Used by the proposed scheme for post-quantum session key establishment
(skill.md). Provided in the shared layer because ``run_meta.json`` must
record which ML-KEM implementation produced a number, and because Exp. 1's
measurement rule depends on encapsulation being separable:

    skill.md, Exp. 1: "ML-KEM-768 encapsulation runs once at session
    establishment and is EXCLUDED; report it separately as a one-time setup
    cost in the text, not inside the per-query curve."

``encapsulate`` is therefore never called from a trapdoor-generation path.
``measure_setup_cost`` exists to produce that separately-reported number.

BACKEND DETECTION
-----------------
requirements.txt attributes ML-KEM-768 to ``cryptography>=43.0.0``. That
attribution is UNVERIFIED — ML-KEM landed in ``cryptography`` well after
43.0, so a host that satisfies requirements.txt may still have no ML-KEM.
Rather than hardcode one import path, this module probes several known
providers and reports which one is live. Confirm the active backend on the
experiment host before reportable runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

# FIPS 203 fixed sizes for the ML-KEM-768 parameter set.
ENCAPSULATION_KEY_BYTES = 1184
DECAPSULATION_KEY_BYTES = 2400   # expanded dk (liboqs, kyber_py)
DECAPSULATION_SEED_BYTES = 64    # (d, z) seed form — FIPS 203 §7.1 (cryptography)
CIPHERTEXT_BYTES = 1088
SHARED_SECRET_BYTES = 32


class KEMUnavailableError(RuntimeError):
    """Raised when no ML-KEM-768 implementation can be found."""


@dataclass(frozen=True)
class KeyPair:
    encapsulation_key: bytes  # public
    decapsulation_key: bytes  # secret


@dataclass(frozen=True)
class Encapsulation:
    ciphertext: bytes
    shared_secret: bytes


class MLKEM768:
    """ML-KEM-768 with automatic backend selection."""

    def __init__(self, backend: Optional[str] = None) -> None:
        self._impl, self.backend = _select_backend(backend)

    @property
    def decapsulation_key_bytes(self) -> int:
        """Size of the dk this backend emits — 2400 expanded, or 64 as a seed."""
        return self._impl.decapsulation_key_bytes

    def keygen(self) -> KeyPair:
        return self._impl.keygen()

    def encapsulate(self, encapsulation_key: bytes) -> Encapsulation:
        """Session establishment. EXCLUDED from the Exp. 1 trapdoor curve."""
        return self._impl.encapsulate(encapsulation_key)

    def decapsulate(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        return self._impl.decapsulate(decapsulation_key, ciphertext)

    def self_test(self) -> bool:
        """Round-trip check: both parties must derive the same secret."""
        kp = self.keygen()
        enc = self.encapsulate(kp.encapsulation_key)
        recovered = self.decapsulate(kp.decapsulation_key, enc.ciphertext)
        from .hashes import constant_time_equal

        return (
            constant_time_equal(recovered, enc.shared_secret)
            and len(enc.shared_secret) == SHARED_SECRET_BYTES
        )


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
class _CryptographyBackend:
    """``cryptography``'s native ML-KEM API (``MLKEM768PrivateKey``, 46+).

    THE DECAPSULATION KEY IS THE 64-BYTE SEED, NOT THE 2400-BYTE EXPANDED KEY.
    ``cryptography`` exposes ``private_bytes_raw()`` as the FIPS 203 ``(d, z)``
    seed and reconstructs from it with ``from_seed_bytes``. FIPS 203 §7.1 names
    that an equivalent representation of ``dk`` — the expanded key is derived
    from it deterministically — so this is a storage-format difference, not a
    weaker key. ``decapsulation_key_bytes`` reports which representation the
    live backend produces so a size assertion checks the active backend rather
    than one hardcoded number (``liboqs`` and ``kyber_py`` both give 2400).
    """

    name = "cryptography"
    decapsulation_key_bytes = DECAPSULATION_SEED_BYTES

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import mlkem  # type: ignore

        # Probed rather than assumed: the module exists on versions that predate
        # the ML-KEM-768 classes, and an AttributeError here is what tells
        # _select_backend to move on to the next backend.
        self._private = mlkem.MLKEM768PrivateKey  # type: ignore[attr-defined]
        self._public = mlkem.MLKEM768PublicKey  # type: ignore[attr-defined]

    def keygen(self) -> KeyPair:
        private = self._private.generate()
        return KeyPair(
            encapsulation_key=private.public_key().public_bytes_raw(),
            decapsulation_key=private.private_bytes_raw(),
        )

    def encapsulate(self, encapsulation_key: bytes) -> Encapsulation:
        public = self._public.from_public_bytes(encapsulation_key)
        shared, ct = public.encapsulate()
        return Encapsulation(ciphertext=ct, shared_secret=shared)

    def decapsulate(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        private = self._private.from_seed_bytes(decapsulation_key)
        return private.decapsulate(ciphertext)


class _LiboqsBackend:
    """Open Quantum Safe (``oqs``) — the usual choice in PQC research code."""

    name = "liboqs"
    _ALG = "ML-KEM-768"
    decapsulation_key_bytes = DECAPSULATION_KEY_BYTES

    def __init__(self) -> None:
        import oqs  # type: ignore

        self._oqs = oqs
        if self._ALG not in oqs.get_enabled_kem_mechanisms():
            raise ImportError(f"liboqs lacks {self._ALG}")

    def keygen(self) -> KeyPair:
        with self._oqs.KeyEncapsulation(self._ALG) as kem:
            public = kem.generate_keypair()
            return KeyPair(
                encapsulation_key=public,
                decapsulation_key=kem.export_secret_key(),
            )

    def encapsulate(self, encapsulation_key: bytes) -> Encapsulation:
        with self._oqs.KeyEncapsulation(self._ALG) as kem:
            ct, shared = kem.encap_secret(encapsulation_key)
            return Encapsulation(ciphertext=ct, shared_secret=shared)

    def decapsulate(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        with self._oqs.KeyEncapsulation(self._ALG, decapsulation_key) as kem:
            return kem.decap_secret(ciphertext)


class _KyberPyBackend:
    """Pure-Python ``kyber-py``. Correct but SLOW — development only.

    A pure-Python KEM is orders of magnitude slower than a C implementation.
    Since Exp. 1 excludes encapsulation from its curve this does not corrupt
    the trapdoor figures, but the separately-reported setup cost would be
    meaningless. Do not report a setup cost measured on this backend.
    """

    name = "kyber_py"
    decapsulation_key_bytes = DECAPSULATION_KEY_BYTES

    def __init__(self) -> None:
        from kyber_py.ml_kem import ML_KEM_768  # type: ignore

        self._kem = ML_KEM_768

    def keygen(self) -> KeyPair:
        ek, dk = self._kem.keygen()
        return KeyPair(encapsulation_key=ek, decapsulation_key=dk)

    def encapsulate(self, encapsulation_key: bytes) -> Encapsulation:
        shared, ct = self._kem.encaps(encapsulation_key)
        return Encapsulation(ciphertext=ct, shared_secret=shared)

    def decapsulate(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        return self._kem.decaps(decapsulation_key, ciphertext)


_BACKEND_ORDER: List[Tuple[str, Callable[[], object]]] = [
    (_CryptographyBackend.name, _CryptographyBackend),
    (_LiboqsBackend.name, _LiboqsBackend),
    (_KyberPyBackend.name, _KyberPyBackend),
]


def _select_backend(requested: Optional[str]) -> Tuple[object, str]:
    tried: List[str] = []
    for name, factory in _BACKEND_ORDER:
        if requested and name != requested:
            continue
        try:
            return factory(), name
        except Exception as exc:  # ImportError, AttributeError on old versions
            tried.append(f"{name} ({type(exc).__name__}: {exc})")

    target = requested or "any"
    raise KEMUnavailableError(
        f"no ML-KEM-768 backend available (requested: {target}).\n"
        f"Tried: {'; '.join(tried) if tried else 'none'}\n"
        f"Install one of:\n"
        f"  pip install 'cryptography>=46'   # if its mlkem module is present\n"
        f"  pip install liboqs-python        # Open Quantum Safe\n"
        f"  pip install kyber-py             # pure Python, development only"
    )


def available_backends() -> dict[str, bool]:
    """Which ML-KEM backends import here — recorded in ``run_meta.json``."""
    status: dict[str, bool] = {}
    for name, factory in _BACKEND_ORDER:
        try:
            factory()
            status[name] = True
        except Exception:
            status[name] = False
    return status


def measure_setup_cost(repetitions: int = 30) -> dict[str, object]:
    """Time keygen/encapsulate/decapsulate for the separately-reported figure.

    skill.md keeps this OUT of the Exp. 1 curve and asks for it in the text
    as a one-time session-establishment cost. Timings are in milliseconds;
    the ``backend`` key names the implementation that produced them, because
    a number from the pure-Python backend must not be reported.
    """
    import time

    kem = MLKEM768()
    timings = {"keygen_ms": 0.0, "encapsulate_ms": 0.0, "decapsulate_ms": 0.0}

    for _ in range(5):  # warm-up, discarded (skill.md)
        kp = kem.keygen()
        enc = kem.encapsulate(kp.encapsulation_key)
        kem.decapsulate(kp.decapsulation_key, enc.ciphertext)

    for _ in range(repetitions):
        start = time.perf_counter_ns()
        kp = kem.keygen()
        mid = time.perf_counter_ns()
        enc = kem.encapsulate(kp.encapsulation_key)
        after_encap = time.perf_counter_ns()
        kem.decapsulate(kp.decapsulation_key, enc.ciphertext)
        end = time.perf_counter_ns()

        timings["keygen_ms"] += (mid - start) / 1e6
        timings["encapsulate_ms"] += (after_encap - mid) / 1e6
        timings["decapsulate_ms"] += (end - after_encap) / 1e6

    result: dict[str, object] = {k: v / repetitions for k, v in timings.items()}
    result["backend"] = kem.backend
    result["repetitions"] = repetitions
    return result
