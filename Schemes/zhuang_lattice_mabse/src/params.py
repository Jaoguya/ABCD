"""Scheme parameters for Ref[52] — loaded from ``crypto.yaml``.

Every value here traces to a published parameter in Table III
(Ref[52] lines 722–735) or to a benchmark-choice recorded in crypto.yaml.
No hardcoded constants — README §7 requires config-hash provenance.

Table III published parameters
------------------------------
    n = 284           security parameter
    m = 13,812        basis dimension
    q = 2^24          modulus
    l = 10            size of attribute set U_C
    u = 50            total number of users
    w = 5             total number of keywords in CT
    h = 3             total number of hash functions (Bloom)
    k = 32            length of bloom filter array

NOTE on the paper's parameter naming: Table III labels "h" for hashes
and "k" for bloom array length, which swaps the l/k roles used in the
Bloom filter definition (§II.C says BF(l,k) = l-bit array, k hashes).
This module follows the WORDS, matching ``bloom.py``'s convention.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

import numpy as np

from Common.crypto.config import get as cfg_get
from Common.crypto.lattice import LatticeParams


@dataclass(frozen=True)
class SchemeParams:
    """All Ref[52] parameters, loaded from crypto.yaml."""

    lattice: LatticeParams

    # Bloom filter BF(l, k) — §II.C
    bloom_array_bits: int      # l = 32 (published as "k" in Table III)
    bloom_num_hashes: int      # k = 3  (published as "h" in Table III)

    # Attribute / user / keyword counts
    num_attributes: int        # |U_C| = 10
    num_users: int             # u = 50
    keywords_per_ct: int       # w = 5

    @classmethod
    def from_config(cls) -> "SchemeParams":
        """Load from ``Experiment Configuration/crypto.yaml``."""
        block = cfg_get("zhuang_lattice_mabse")
        lp_block = block["lattice"]
        bf_block = block["bloom_filter"]
        attr_block = block["attributes"]
        return cls(
            lattice=LatticeParams(
                n=int(lp_block["n"]),
                m=int(lp_block["m"]),
                log_q=int(lp_block["log_q"]),
                sigma=float(lp_block["gaussian_sigma"]),
            ),
            bloom_array_bits=int(bf_block["array_bits"]),
            bloom_num_hashes=int(bf_block["num_hashes"]),
            num_attributes=int(attr_block["l"]),
            num_users=int(block.get("users_total", 50)),
            keywords_per_ct=int(block["keywords_per_ciphertext"]),
        )


# ---------------------------------------------------------------------------
# Hash functions required by the construction
# ---------------------------------------------------------------------------
def H0(category_bit: int, n: int, m: int, q: int) -> np.ndarray:
    """H_0 : {0,1}* → Z_q^{n×m}  — Ref[52] line 235–238.

    Maps a keyword-category bit k_0 ∈ {0,1} to a deterministic n×m matrix
    over Z_q.  Since k_0 takes only two values, the two possible outputs
    can be cached after the first call.

    Implementation: SHA-256(k_0) → 256-bit seed → numpy PRNG → n*m uniform
    values in [0, q).  This is a standard random-oracle instantiation.
    """
    seed_bytes = hashlib.sha256(
        b"zhuang_ref52/H0/" + category_bit.to_bytes(1, "big")
    ).digest()
    seed = int.from_bytes(seed_bytes[:8], "big")
    rng = np.random.default_rng(seed)
    return rng.integers(0, q, size=(n, m), dtype=np.int64)


# Cache the two possible H_0 outputs (they never change for fixed params).
_H0_CACHE: dict[tuple[int, int, int, int], np.ndarray] = {}


def H0_cached(category_bit: int, params: LatticeParams) -> np.ndarray:
    """Cached version of H_0 — avoids recomputing per-query."""
    key = (category_bit, params.n, params.m, params.q)
    if key not in _H0_CACHE:
        _H0_CACHE[key] = H0(category_bit, params.n, params.m, params.q)
    return _H0_CACHE[key]


def Hi_hash(keyword: bytes, index: int, q: int) -> int:
    """H_i : {0,1}* → Z_q  for 1 ≤ i ≤ k — Ref[52] lines 239–241.

    Used by the Bloom filter to determine bit positions.  Each hash function
    H_i is independent, keyed by the index ``i``.
    """
    digest = hashlib.sha256(
        b"zhuang_ref52/Hi/" + index.to_bytes(4, "big") + keyword
    ).digest()
    # q = 2^24 is a power of two, so masking gives exact uniformity.
    return int.from_bytes(digest[:3], "big") % q
