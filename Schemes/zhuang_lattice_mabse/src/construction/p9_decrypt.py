"""Phase 9 — Decryption: b' ← Decrypt(CT, GP, {PK_d}, SK_ID)

Ref[52] §III.I, lines 644–710.

Any user whose attributes satisfy the access tree τ can decrypt.  The
algorithm uses preimage vectors e (from SamplePre) that depend only on
the user's B matrix and trapdoor — they can be precomputed ONCE and
cached across all ciphertexts.

Per-ciphertext cost: l inner products of m-vectors = l · Tmul5 ≈ 0.12 ms.

"To adapt the proposed scheme for transmitting multiple bits, the encryption
process can generate multiple distinct ciphertexts C, with each C carrying
one bit, while other components can be reused." — §III.I note.
"""

from __future__ import annotations

from typing import Optional

import numpy as np

from Common.crypto.lattice import mod_q, sample_pre

from ..access_tree import GateType, TreeNode
from .p1_setup import GlobalParams
from .p3_enroll import AttrKey, UserPrivateKey, UserPublicInfo
from .p6_encrypt import Ciphertext


def _ensure_preimages(
    gp: GlobalParams,
    user_pub: UserPublicInfo,
    user_prv: UserPrivateKey,
    *,
    rng: Optional[np.random.Generator] = None,
) -> None:
    """Precompute and cache preimage vectors e for each held attribute.

    e^ID_{d,i} satisfies B^ID_{d,i} @ e = u (mod q).
    These are reusable across all ciphertexts — compute once at enrollment.
    """
    rng = rng or np.random.default_rng()
    lp = gp.params.lattice

    for attr_key, T_B in user_prv.trapdoors.items():
        if attr_key in user_prv.preimages:
            continue
        B = user_pub.B_matrices[attr_key]
        e = sample_pre(B, T_B, gp.u_vector, s=lp.sigma, rng=rng)
        user_prv.preimages[attr_key] = e


def decrypt(
    gp: GlobalParams,
    ct: Ciphertext,
    access_tree: TreeNode,
    user_pub: UserPublicInfo,
    user_prv: UserPrivateKey,
    *,
    rng: Optional[np.random.Generator] = None,
) -> int:
    """Decrypt a ciphertext to recover the plaintext bit.

    Steps (Ref[52] §III.I):
        1. For each attribute: use precomputed e (SamplePre result)
        2. Compute b':
           AND: b' = C − Σ (e_i^T C_i)
           OR:  b' = C − (e_i^T C_i)  for one attribute
        3. Threshold: |b' − ⌊q/2⌋| < ⌊q/4⌋ → 1, else 0

    Returns:
        The recovered bit (0 or 1).
    """
    rng = rng or np.random.default_rng()
    q = gp.params.lattice.q

    # Step 1: ensure preimages are cached
    _ensure_preimages(gp, user_pub, user_prv, rng=rng)

    gate = access_tree.gate or GateType.AND

    if gate == GateType.AND:
        # Step 2 (AND): b' = C − Σ (e_i^T C_i)
        b_prime = int(ct.C)
        for attr_key, e in user_prv.preimages.items():
            ct_key = (user_prv.user_id, attr_key)
            if ct_key not in ct.C_components:
                continue
            C_i = ct.C_components[ct_key]
            # Dot product mod q — use Python ints to avoid int64 overflow.
            # sum(e_i * C_i) mod q, computed via python big-int arithmetic.
            dot = sum(int(a) * int(b) for a, b in zip(e, C_i)) % q
            b_prime = (b_prime - dot) % q
    else:
        # Step 2 (OR): use any one held attribute
        b_prime = int(ct.C)
        for attr_key, e in user_prv.preimages.items():
            ct_key = (user_prv.user_id, attr_key)
            if ct_key in ct.C_components:
                C_i = ct.C_components[ct_key]
                dot = sum(int(a) * int(b) for a, b in zip(e, C_i)) % q
                b_prime = (b_prime - dot) % q
                break

    # Step 3: threshold decision using centered representation
    # Map b_prime into (-q/2, q/2] for the comparison
    half_q = q // 2
    quarter_q = q // 4
    centered_val = b_prime if b_prime <= half_q else b_prime - q
    if abs(centered_val - half_q) < quarter_q:
        return 1
    if abs(centered_val + half_q) < quarter_q:
        return 1
    # Close to 0 means bit=0, close to ±q/2 means bit=1
    if abs(centered_val) < quarter_q:
        return 0
    return 1

