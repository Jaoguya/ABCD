"""Phase 3 — User Enrollment: (PK_d, SK^ID_d) ← Enroll(GP, PK_d, MK_d, ID, U^ID_d)

Ref[52] §III.C, lines 266–329.

For each attribute the user possesses, the authority generates a delegated
key pair (B, T_B).  For attributes the user does NOT possess, a random B
is published (with no trapdoor — the user cannot decrypt/search with it).

IMPLEMENTATION NOTE ON BasisDel vs TrapGen
------------------------------------------
The paper defines enrollment as:
    R = SampleR(1^m)          ← m×m matrix in {-1, +1}
    B = A R^{-1}              ← requires inverting R over Z_q
    T_B = BasisDel(A, R, T_A) ← derive trapdoor for B from T_A

At the published parameters (m = 13,812, q = 2^24):
  • R ∈ {-1,+1}^{m×m} has det(R) ≡ 0 (mod 2) for m > 1, so R is NEVER
    invertible over Z_{2^24} — the definition is unrealizable as written.
  • Even ignoring invertibility, R is 190M entries (~1.5 GB in int64).

We substitute independent TrapGen(n, m, q, σ) for each user-attribute pair.
This produces an identically-distributed (B, T_B) — both B and AR^{-1} are
statistically close to uniform over Z_q^{n×m}, and both trapdoors support
the same SamplePre / SampleLeft operations.  The difference is invisible
to the MEASURED operations (TokenGen, Search, Decrypt) because they depend
only on the (B, T_B) pair, not on how it was derived.

This is documented in the code and should be stated alongside any reported
figure.  It does not weaken or strengthen the baseline; it implements the
same cryptographic functionality.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

from Common.crypto.lattice import Trapdoor, sample_uniform_zq, trapgen

from .p1_setup import GlobalParams
from .p2_aa_setup import AuthorityMasterKey, AuthorityPublicKey


# Key type: (authority_id, attribute_id)
AttrKey = Tuple[int, int]


@dataclass
class UserPublicInfo:
    """Published per-user matrices {B^ID_{d,i}} — part of the authority PK."""

    user_id: str
    B_matrices: Dict[AttrKey, np.ndarray] = field(default_factory=dict)
    # Track which attributes the user actually holds (vs random B)
    held_attributes: Set[AttrKey] = field(default_factory=set)


@dataclass
class UserPrivateKey:
    """SK_ID = {SK^ID_d}_{d ∈ D} — the user's full private key.

    Contains trapdoors T_B for held attributes and precomputed preimage
    vectors e (for fast Decrypt — §III.I step 1).
    """

    user_id: str
    trapdoors: Dict[AttrKey, Trapdoor] = field(default_factory=dict)
    preimages: Dict[AttrKey, np.ndarray] = field(default_factory=dict)


def enroll(
    gp: GlobalParams,
    authority_pk: AuthorityPublicKey,
    authority_mk: AuthorityMasterKey,
    user_id: str,
    user_attribute_ids: List[int],
    *,
    rng: Optional[np.random.Generator] = None,
) -> Tuple[UserPublicInfo, UserPrivateKey]:
    """Enroll a user under one authority.

    Steps (Ref[52] §III.C):
        1. For each a_i ∈ U^ID_d (user's attributes):
           Generate (B^ID_{d,i}, T_{B^ID_{d,i}}) via TrapGen
        2. For each a_i ∈ U_d − U^ID_d (attributes user lacks):
           Random B^ID_{d,i} ∈ Z_q^{n×m}  (no trapdoor)
        3. Update PK_d with {B^ID_{d,i}}
        4. Return partial private key SK^ID_d = {T_{B^ID_{d,i}}}
        5. If ID ∉ L, add to L
    """
    rng = rng or np.random.default_rng()
    lp = gp.params.lattice
    auth_id = authority_pk.authority_id

    user_pub = UserPublicInfo(user_id=user_id)
    user_prv = UserPrivateKey(user_id=user_id)

    user_attr_set = set(user_attribute_ids)

    for attr_id in authority_pk.attribute_ids:
        key = (auth_id, attr_id)

        if attr_id in user_attr_set:
            # Step 1: user holds this attribute — generate delegated key pair
            B, T_B = trapgen(lp, rng=rng)
            user_pub.B_matrices[key] = B
            user_pub.held_attributes.add(key)
            user_prv.trapdoors[key] = T_B
        else:
            # Step 2: user lacks this attribute — random B, no trapdoor
            B = sample_uniform_zq((lp.n, lp.m), lp.q, rng=rng)
            user_pub.B_matrices[key] = B

    # Step 5: add to enrolled set
    if user_id not in gp.user_ids:
        gp.user_ids.append(user_id)

    return user_pub, user_prv
