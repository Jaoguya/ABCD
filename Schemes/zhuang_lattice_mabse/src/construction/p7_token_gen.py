"""Phase 7 — Token Generation: (w', {k^ID_{d,i}}) ← TokenGen(GP, k'_0, W', {PK_d}, SK_ID)

Ref[52] §III.G, lines 508–581.

The data user generates a search token independently (offline KGC).  The
token consists of:
    • w' — Bloom filter binary vector encoding the search keywords
    • {k^ID_{d,i}} — one 2m-vector per held attribute, from SampleLeft

"Since the DU can independently generate tokens, the scheme achieves an
offline KGC architecture." — §III.G note.

This is the TIMED operation for Experiment 1 (trapdoor generation latency).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from Common.crypto.bloom import BloomFilter
from Common.crypto.lattice import mod_q, sample_left

from ..params import H0_cached
from .p1_setup import GlobalParams
from .p3_enroll import AttrKey, UserPrivateKey, UserPublicInfo


@dataclass
class SearchToken:
    """Search token sent from user to cloud server."""

    bloom_vector: np.ndarray   # w' — binary vector (length bloom_array_bits)
    token_vectors: Dict[AttrKey, np.ndarray] = field(
        default_factory=dict
    )  # (auth, attr) → k^ID_{d,i} ∈ Z_q^{2m}

    @property
    def size_bytes(self) -> int:
        """Total serialised token size — Exp. 1 secondary metric."""
        size = self.bloom_vector.nbytes
        for v in self.token_vectors.values():
            size += v.nbytes
        return size


def token_gen(
    gp: GlobalParams,
    category_bit: int,
    keywords: List[bytes],
    user_pub: UserPublicInfo,
    user_prv: UserPrivateKey,
    *,
    rng: Optional[np.random.Generator] = None,
) -> SearchToken:
    """Generate a search token for keyword set ``keywords``.

    Steps (Ref[52] §III.G):
        1. K' = H_0(k'_0)
        2. Select keyword set W' — already provided
        3. Compute Bloom filter binary vector w' for W'
        4. For each attribute a_i ∈ U^ID:
           SampleLeft(B^ID_{d,i}, K', T_{B^ID_{d,i}}, u, σ) → k^ID_{d,i}
           where [B | K'] @ k = u
        5. Send (w', {k^ID_{d,i}}) to CS

    Args:
        gp: Global parameters.
        category_bit: k'_0 ∈ {0, 1}.
        keywords: W' = {k'_1, ..., k'_j} as raw bytes.
        user_pub: User's published B matrices.
        user_prv: User's private key (trapdoors).
        rng: Random number generator.

    Returns:
        SearchToken — (w', {k^ID_{d,i}}).
    """
    rng = rng or np.random.default_rng()
    sp = gp.params
    lp = sp.lattice

    # Step 1: K' = H_0(k'_0)
    K_prime = H0_cached(category_bit, lp)

    # Step 3: Bloom filter of search keywords
    bf = BloomFilter(
        array_bits=sp.bloom_array_bits,
        num_hashes=sp.bloom_num_hashes,
    )
    bf.add_all(keywords)
    w_prime = np.array(
        [(bf.bits >> i) & 1 for i in range(sp.bloom_array_bits)],
        dtype=np.int64,
    )

    # Step 4: SampleLeft for each held attribute
    token = SearchToken(bloom_vector=w_prime)

    for attr_key, T_B in user_prv.trapdoors.items():
        B = user_pub.B_matrices[attr_key]

        # SampleLeft(B, K', T_B, u, σ) → k ∈ Z_q^{2m}
        # where [B | K'] @ k = u (mod q)
        k_vec = sample_left(
            B, K_prime, T_B, gp.u_vector,
            s=lp.sigma, rng=rng,
        )
        token.token_vectors[attr_key] = k_vec

    return token
