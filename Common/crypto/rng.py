"""Random number generation.

Two generators live here and they must never be confused:

``secure_random_bytes`` / ``SecureRandom``
    OS entropy, for anything that is key material, a nonce, or a salt.

``DeterministicRNG``
    Seeded and reproducible, for EXPERIMENT ARTEFACTS ONLY — corpus content,
    workload arrival traces, which keywords a synthetic query asks for. Using
    it for key material would make every "encrypted" record in the benchmark
    trivially recoverable, so it refuses to produce anything key-shaped.
"""

from __future__ import annotations

import os
import secrets
from typing import Iterator, Sequence, TypeVar

import numpy as np

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Cryptographic randomness
# ---------------------------------------------------------------------------
def secure_random_bytes(length: int) -> bytes:
    """Return ``length`` cryptographically secure random bytes."""
    if length < 0:
        raise ValueError(f"length must be non-negative, got {length}")
    return os.urandom(length)


def secure_random_int(upper_exclusive: int) -> int:
    """Uniform integer in ``[0, upper_exclusive)`` without modulo bias."""
    if upper_exclusive <= 0:
        raise ValueError("upper_exclusive must be positive")
    return secrets.randbelow(upper_exclusive)


class SecureRandom:
    """Namespace wrapper, so call sites read as ``SecureRandom.bytes(32)``."""

    bytes = staticmethod(secure_random_bytes)
    below = staticmethod(secure_random_int)


# ---------------------------------------------------------------------------
# Reproducible, NON-cryptographic randomness
# ---------------------------------------------------------------------------
class DeterministicRNG:
    """Seeded PRNG for reproducible experiment artefacts.

    NOT CRYPTOGRAPHICALLY SECURE. This wraps numpy's PCG64 so that a corpus or
    a workload trace regenerates byte-identically on any machine — which is
    what lets all four scheduler variants in Exp. 7-8 see "byte-identical
    workloads".
    """

    def __init__(self, seed: int) -> None:
        self.seed = int(seed)
        self._rng = np.random.default_rng(self.seed)

    @property
    def numpy(self) -> np.random.Generator:
        """The underlying numpy Generator, for vectorised sampling."""
        return self._rng

    def integers(self, low: int, high: int, size: int | None = None):
        """Uniform integers in ``[low, high)``."""
        return self._rng.integers(low, high, size=size)

    def zipf(self, exponent: float, size: int):
        """Zipf-distributed integers >= 1 (heavy-tailed keyword frequency)."""
        return self._rng.zipf(exponent, size=size)

    def lognormal(self, mean: float, sigma: float, size: int):
        return self._rng.lognormal(mean=mean, sigma=sigma, size=size)

    def choice(self, population: Sequence[T], size: int, *, replace: bool = False,
               p=None):
        idx = self._rng.choice(len(population), size=size, replace=replace, p=p)
        return [population[int(i)] for i in np.atleast_1d(idx)]

    def shuffled(self, items: Sequence[T]) -> list[T]:
        out = list(items)
        self._rng.shuffle(out)
        return out

    def spawn(self, label: str) -> "DeterministicRNG":
        """Derive an independent child stream from a string label.

        Lets each stage draw from its own stream, so adding a stage does not
        shift every later stage's values and silently change the corpus.
        """
        mixed = (self.seed * 0x9E3779B97F4A7C15 + _label_to_int(label)) % (2**63)
        return DeterministicRNG(mixed)

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return f"DeterministicRNG(seed={self.seed})"


def _label_to_int(label: str) -> int:
    """Stable, platform-independent integer from a label.

    Deliberately not ``hash()``: CPython randomises string hashing per process
    unless PYTHONHASHSEED is pinned, which would break reproducibility in a
    way that is very hard to notice.
    """
    import hashlib

    return int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest()[:8], "big")


def chunked(items: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    """Yield ``items`` in consecutive chunks of at most ``size``."""
    for start in range(0, len(items), size):
        yield items[start : start + size]
