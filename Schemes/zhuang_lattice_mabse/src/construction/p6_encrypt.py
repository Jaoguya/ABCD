"""Phase 6 — Encryption: CT ← Encrypt(GP, b, k_0, W, τ, {PK_d})

Ref[52] §III.F, lines 412–504.

Encrypts one bit ``b`` under access tree ``τ`` and embeds a keyword search
index using a Bloom filter of keyword set ``W``.

Equations:
    (1) C       = u^T s1 · r  + b⌊q/2⌋ + x
    (2) C^ID_i  = (B^ID_i)^T s1 · r_i + x_{1,i}
    (3) I_{1,θ} = u^T s2 · r  + w_θ⌊q/2⌋ + x_l
    (4) I^ID_i  = [B^ID_i | K]^T s2 · r_i + x_{2,i}

Complexity: O(l · u) matrix–vector products — Table VI reports ~4741 ms
for l=10, u=50 at the published parameters.

"Each ID has independent keys, ensuring collusion resistance.  Both messages
and keywords are encrypted, so user attributes are verified during
decryption and search." — §III.F note.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from Common.crypto.bloom import BloomFilter
from Common.crypto.lattice import mod_q, sample_discrete_gaussian, sample_uniform_zq

from ..access_tree import TreeNode, assign_shares, get_leaf_shares
from ..params import H0_cached
from .p1_setup import GlobalParams
from .p3_enroll import AttrKey, UserPublicInfo


@dataclass
class Ciphertext:
    """CT = {C, {C^ID_{d,i}}}  — the encrypted message."""

    C: int                                              # scalar ∈ Z_q
    C_components: Dict[Tuple[str, AttrKey], np.ndarray] = field(
        default_factory=dict
    )  # (user_id, (auth, attr)) → m-vector


@dataclass
class EncryptedIndex:
    """I^ID = {{I_{1,θ}}, {I^ID_{d,i}}}  — the keyword search index."""

    bloom_scalars: np.ndarray                           # I_{1,θ} for θ=1..l_bloom
    index_vectors: Dict[Tuple[str, AttrKey], np.ndarray] = field(
        default_factory=dict
    )  # (user_id, (auth, attr)) → 2m-vector
    bloom_vector: np.ndarray = field(
        default_factory=lambda: np.array([], dtype=np.int64)
    )  # w — the Bloom bit-vector (for search verification)


def _build_bloom(
    keywords: List[bytes],
    array_bits: int,
    num_hashes: int,
) -> Tuple[BloomFilter, np.ndarray]:
    """Build Bloom filter and extract the binary vector w."""
    bf = BloomFilter(array_bits=array_bits, num_hashes=num_hashes)
    bf.add_all(keywords)
    # Extract binary vector w = (w_1, ..., w_l) from the Bloom filter bits
    w = np.array(
        [(bf.bits >> i) & 1 for i in range(array_bits)],
        dtype=np.int64,
    )
    return bf, w


def encrypt(
    gp: GlobalParams,
    bit: int,
    category_bit: int,
    keywords: List[bytes],
    access_tree: TreeNode,
    user_pub_list: List[UserPublicInfo],
    *,
    rng: Optional[np.random.Generator] = None,
) -> Tuple[Ciphertext, EncryptedIndex]:
    """Encrypt one bit with keyword index under an access policy.

    Args:
        gp: Global parameters from Setup.
        bit: The message bit b ∈ {0, 1}.
        category_bit: k_0 ∈ {0, 1} — keyword category.
        keywords: W = {k_1, ..., k_j} — keyword set as raw bytes.
        access_tree: τ — the access policy tree.
        user_pub_list: Published B matrices for each enrolled user.
        rng: Random number generator.

    Returns:
        (CT, Index) — the ciphertext and search index.
    """
    rng = rng or np.random.default_rng()
    sp = gp.params
    lp = sp.lattice
    q = lp.q
    n, m = lp.n, lp.m
    sigma = lp.sigma

    # ── Step 1: noise scalar ──
    x = int(sample_discrete_gaussian(1, sigma, rng=rng)[0])

    # ── Step 2: attributes from access tree ──
    # (tree already has the right attributes)

    # ── Step 4: random values and message encryption ──
    r = int(rng.integers(0, q))
    s1 = sample_uniform_zq((n,), q, rng=rng)

    # Eq. (1): C = u^T s1 · r + b⌊q/2⌋ + x
    u_dot_s1 = int(np.sum(gp.u_vector * s1) % q)
    half_q = q // 2
    C_val = (u_dot_s1 * r + bit * half_q + x) % q

    # ── Step 5: assign shares through the access tree ──
    assign_shares(access_tree, r, q, rng=rng)
    leaf_shares = get_leaf_shares(access_tree)

    # ── Step 6: per-user, per-attribute partial ciphertexts ──
    ct = Ciphertext(C=C_val)

    for user_pub in user_pub_list:
        for (auth_id, attr_id), B in user_pub.B_matrices.items():
            if attr_id not in leaf_shares:
                continue
            r_i = leaf_shares[attr_id]

            # Noise vector x_{1,d,i} ∈ χ^m
            x1 = sample_discrete_gaussian(m, sigma, rng=rng)

            # Eq. (2): C^ID_{d,i} = B^T s1 · r_i + x_{1,d,i}
            # B^T is m×n, s1 is n-vector → B^T @ s1 is m-vector
            Bt_s1 = mod_q(B.T @ s1, q)
            c_comp = mod_q(Bt_s1 * r_i + x1, q)

            ct.C_components[(user_pub.user_id, (auth_id, attr_id))] = c_comp

    # ── Steps 7–9: keyword index (Bloom filter) ──
    K = H0_cached(category_bit, lp)
    _bf, w = _build_bloom(keywords, sp.bloom_array_bits, sp.bloom_num_hashes)

    # ── Step 10: index encryption ──
    x_l = int(sample_discrete_gaussian(1, sigma, rng=rng)[0])
    s2 = sample_uniform_zq((n,), q, rng=rng)
    u_dot_s2 = int(np.sum(gp.u_vector * s2) % q)

    # Eq. (3): I_{1,θ} = u^T s2 · r + w_θ ⌊q/2⌋ + x_l   for θ = 1..l_bloom
    bloom_scalars = mod_q(
        np.full(sp.bloom_array_bits, u_dot_s2 * r, dtype=np.int64)
        + w * half_q
        + x_l,
        q,
    )

    # ── Step 11: per-user, per-attribute index vectors ──
    idx = EncryptedIndex(
        bloom_scalars=bloom_scalars,
        bloom_vector=w.copy(),
    )

    for user_pub in user_pub_list:
        for (auth_id, attr_id), B in user_pub.B_matrices.items():
            if attr_id not in leaf_shares:
                continue
            r_i = leaf_shares[attr_id]

            # Noise vector x_{2,d,i} ∈ χ^{2m}
            x2 = sample_discrete_gaussian(2 * m, sigma, rng=rng)

            # Eq. (4): I^ID_{d,i} = [B | K]^T s2 · r_i + x_{2,d,i}
            # [B | K] is n × 2m, so [B|K]^T is 2m × n
            BK_t_s2 = mod_q(
                np.concatenate([B.T @ s2, K.T @ s2]) * r_i,
                q,
            )
            idx_vec = mod_q(BK_t_s2 + x2, q)

            idx.index_vectors[(user_pub.user_id, (auth_id, attr_id))] = idx_vec

    return ct, idx
