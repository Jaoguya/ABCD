"""Phase 8 — Search: CT/⊥ ← Search(w', {k^ID_{d,i}}, {I^ID}, τ)

Ref[52] §III.H, lines 582–643.

The cloud server receives a search token from the user and checks each
stored ciphertext's keyword index for a match.

For AND-gate access trees the server:
    1. Computes S = Σ_{a_i ∈ U_C} (k^ID_{d,i})^T I^ID_{d,i}   (once)
    2. For each Bloom bit θ: w'_θ = I_{1,θ} − S
    3. Recovers bit: |w'_θ − ⌊q/2⌋| < ⌊q/4⌋  →  1, else 0
    4. Checks Bloom containment: search ⊆ ciphertext

The sum S is independent of θ, so the l dot-products of 2m-vectors dominate
the cost.  Table VI: search ≈ l · Tmul8 ≈ 0.18 ms per record.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import numpy as np

from Common.crypto.lattice import mod_q

from ..access_tree import GateType, TreeNode
from .p1_setup import GlobalParams
from .p3_enroll import AttrKey
from .p6_encrypt import EncryptedIndex
from .p7_token_gen import SearchToken


@dataclass
class SearchResult:
    """Outcome of one search check."""

    matched: bool
    recovered_bloom: Optional[np.ndarray] = None


def _recover_bloom_and(
    token: SearchToken,
    index: EncryptedIndex,
    user_id: str,
    q: int,
) -> np.ndarray:
    """Recover Bloom bits for AND-gate policies.

    w'_θ = I_{1,θ} − Σ_i (k_i^T I_i)
    """
    bloom_bits = len(index.bloom_scalars)

    # Compute S = Σ (k^T I) — one scalar, independent of θ
    S = 0
    for attr_key, k_vec in token.token_vectors.items():
        idx_key = (user_id, attr_key)
        if idx_key not in index.index_vectors:
            continue
        I_vec = index.index_vectors[idx_key]
        S += sum(int(a) * int(b) for a, b in zip(k_vec, I_vec))
    S = S % q

    # For each θ: w'_θ = I_{1,θ} − S
    raw = (index.bloom_scalars.astype(np.int64) - S) % q

    # Threshold: |w'_θ − ⌊q/2⌋| < ⌊q/4⌋ → 1, else 0
    half_q = q // 2
    quarter_q = q // 4
    recovered = np.where(np.abs(raw - half_q) < quarter_q, 1, 0).astype(np.int64)
    return recovered


def _recover_bloom_or(
    token: SearchToken,
    index: EncryptedIndex,
    user_id: str,
    q: int,
) -> np.ndarray:
    """Recover Bloom bits for OR-gate policies — use any one attribute."""
    bloom_bits = len(index.bloom_scalars)

    # Use the first available attribute
    for attr_key, k_vec in token.token_vectors.items():
        idx_key = (user_id, attr_key)
        if idx_key not in index.index_vectors:
            continue
        I_vec = index.index_vectors[idx_key]
        S = sum(int(a) * int(b) for a, b in zip(k_vec, I_vec)) % q

        raw = (index.bloom_scalars.astype(np.int64) - S) % q
        half_q = q // 2
        quarter_q = q // 4
        recovered = np.where(
            np.abs(raw - half_q) < quarter_q, 1, 0
        ).astype(np.int64)
        return recovered

    # No matching attribute found
    return np.zeros(bloom_bits, dtype=np.int64)


def search(
    gp: GlobalParams,
    token: SearchToken,
    index: EncryptedIndex,
    access_tree: TreeNode,
    user_id: str,
) -> SearchResult:
    """Check whether the search token matches the ciphertext's index.

    Steps (Ref[52] §III.H):
        1. Recover Bloom bits w'_θ from the index using the token
        2. Threshold each bit
        3. Check Bloom containment: w' ⊆ w  (search keywords ⊆ ciphertext keywords)
        4. If match, return the ciphertext; otherwise ⊥

    Returns:
        SearchResult indicating whether the keywords matched.
    """
    q = gp.params.lattice.q

    # Step 1–2: recover the search Bloom vector
    gate = access_tree.gate or GateType.AND
    if gate == GateType.AND:
        recovered = _recover_bloom_and(token, index, user_id, q)
    else:
        recovered = _recover_bloom_or(token, index, user_id, q)

    # Step 3: Bloom containment check
    # Search keywords are a subset iff every bit set in w' (search) is also
    # set in w (ciphertext).  Equivalently: (w_search & w_ct) == w_search.
    w_search = token.bloom_vector
    w_ciphertext = index.bloom_vector

    matched = bool(np.all((w_search & w_ciphertext) == w_search))

    return SearchResult(matched=matched, recovered_bloom=recovered)
