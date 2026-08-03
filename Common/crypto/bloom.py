"""Bloom filter BF(l, k).

Ref[52] uses a Bloom filter for membership tests over attribute/keyword sets
(Ref[52].txt:163-165: "By utilizing an l-bit array and k hash functions,
denoted as BF(l,k)"), with the published parameters at Ref[52].txt:734-735.

A NOTE ON REF[52]'s PARAMETER NAMES: Table III labels the row "h  Total number
of hash functions  3" and "k  Length of bloom filter array  32", which swaps
the l/k roles used in its own Definition. This module follows the WORDS, not
the letters: a 32-bit array with 3 hash functions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

import mmh3


@dataclass
class BloomFilter:
    """Classic Bloom filter over an ``array_bits``-bit array.

    Backed by a Python ``int`` used as a bit vector. At the sizes this
    benchmark uses (Ref[52] publishes 32 bits) that is both faster and
    smaller than a list or a bitarray, and makes the serialised form exact.
    """

    array_bits: int
    num_hashes: int
    bits: int = 0
    _count: int = 0

    def __post_init__(self) -> None:
        if self.array_bits <= 0:
            raise ValueError(f"array_bits must be positive, got {self.array_bits}")
        if self.num_hashes <= 0:
            raise ValueError(f"num_hashes must be positive, got {self.num_hashes}")

    # -- core ---------------------------------------------------------------
    def _positions(self, item: bytes) -> List[int]:
        """k independent bit positions via Kirsch-Mitzenmacher double hashing.

        Two 64-bit MurmurHash3 halves generate all k indices as
        ``h1 + i*h2``, which is proven to preserve the false-positive rate of
        k independent hashes while costing one hash call instead of k.
        """
        h1, h2 = mmh3.hash64(item, signed=False)
        if h2 % self.array_bits == 0:
            # A step of 0 would make every index identical, collapsing k to 1.
            h2 += 1
        return [(h1 + i * h2) % self.array_bits for i in range(self.num_hashes)]

    def add(self, item: bytes) -> None:
        for pos in self._positions(item):
            self.bits |= 1 << pos
        self._count += 1

    def add_all(self, items: Iterable[bytes]) -> None:
        for item in items:
            self.add(item)

    def __contains__(self, item: bytes) -> bool:
        return all((self.bits >> pos) & 1 for pos in self._positions(item))

    def contains(self, item: bytes) -> bool:
        """Membership test. May return a false positive, never a false negative."""
        return self.__contains__(item)

    # -- reporting ----------------------------------------------------------
    @property
    def inserted(self) -> int:
        return self._count

    @property
    def bits_set(self) -> int:
        return bin(self.bits).count("1")

    @property
    def size_bytes(self) -> int:
        """Serialised size of the bit array."""
        return (self.array_bits + 7) // 8

    def to_bytes(self) -> bytes:
        return self.bits.to_bytes(self.size_bytes, "big")

    @classmethod
    def from_bytes(cls, raw: bytes, *, array_bits: int, num_hashes: int) -> "BloomFilter":
        obj = cls(array_bits=array_bits, num_hashes=num_hashes)
        obj.bits = int.from_bytes(raw, "big")
        return obj

    def false_positive_rate(self) -> float:
        """Observed FP rate estimate from the current fill.

        ``(bits_set / array_bits) ** num_hashes`` uses the ACTUAL fill rather
        than the textbook formula's expected fill, so it stays honest when the
        filter is heavily loaded — which BF(32, 3) becomes quickly.
        """
        return (self.bits_set / self.array_bits) ** self.num_hashes

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return (
            f"BloomFilter(l={self.array_bits}, k={self.num_hashes}, "
            f"set={self.bits_set}/{self.array_bits}, n={self._count})"
        )


def optimal_num_hashes(array_bits: int, expected_items: int) -> int:
    """The k minimising false positives for a given load: ``(l/n) * ln 2``.

    Provided for sizing OUR scheme's filters. Ref[52]'s k is published and
    must not be re-derived from this — README §14 forbids tuning a baseline
    away from its published construction.
    """
    if expected_items <= 0:
        raise ValueError("expected_items must be positive")
    import math

    return max(1, round((array_bits / expected_items) * math.log(2)))
