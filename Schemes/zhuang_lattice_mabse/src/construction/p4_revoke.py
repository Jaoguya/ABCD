"""Phase 4 — Attribute Revocation: (B^ID_{d,t})' ← Revoke(GP, PK_d, ID, t)

Ref[52] §III.D, lines 330–352.

Revocation is simple: replace the user's B matrix for the target attribute
with a fresh random matrix.  Without the corresponding trapdoor the user
can no longer decrypt or search with that attribute.

New ciphertexts encrypted against the UPDATED public key will use the new
random B, which the revoked user cannot invert.
"""

from __future__ import annotations

from typing import Optional

import numpy as np

from Common.crypto.lattice import sample_uniform_zq

from .p1_setup import GlobalParams
from .p3_enroll import UserPublicInfo, UserPrivateKey


def revoke(
    gp: GlobalParams,
    user_pub: UserPublicInfo,
    user_prv: UserPrivateKey,
    authority_id: int,
    target_attribute: int,
    *,
    rng: Optional[np.random.Generator] = None,
) -> None:
    """Revoke attribute ``target_attribute`` from user.

    Steps (Ref[52] §III.D):
        1. Randomly choose (B^ID_{d,t})' ∈ Z_q^{n×m}
        2. Replace B^ID_{d,t} with (B^ID_{d,t})'

    Mutates ``user_pub`` and ``user_prv`` in place.
    """
    rng = rng or np.random.default_rng()
    lp = gp.params.lattice
    key = (authority_id, target_attribute)

    # Step 1–2: replace B with random matrix (no trapdoor)
    user_pub.B_matrices[key] = sample_uniform_zq(
        (lp.n, lp.m), lp.q, rng=rng
    )
    user_pub.held_attributes.discard(key)

    # Remove the user's trapdoor and preimage for this attribute
    user_prv.trapdoors.pop(key, None)
    user_prv.preimages.pop(key, None)
