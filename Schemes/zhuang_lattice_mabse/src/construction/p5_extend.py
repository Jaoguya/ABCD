"""Phase 5 — Attribute Extension: (PK_d, SK'_d) ← Extend(GP, PK_d, MK_d, ID, t, SK^ID_d)

Ref[52] §III.E, lines 353–409.

Extension grants a new attribute to an existing user.  It is structurally
identical to Enroll for a single attribute: generate a new (B, T_B) pair
and send the trapdoor to the user.

"The Enroll, Revoke, and Extend algorithms collectively enable dynamic
membership management." — §III.E note.
"""

from __future__ import annotations

from typing import Optional, Tuple

import numpy as np

from Common.crypto.lattice import Trapdoor, trapgen

from .p1_setup import GlobalParams
from .p2_aa_setup import AuthorityMasterKey, AuthorityPublicKey
from .p3_enroll import UserPrivateKey, UserPublicInfo


def extend(
    gp: GlobalParams,
    authority_pk: AuthorityPublicKey,
    authority_mk: AuthorityMasterKey,
    user_pub: UserPublicInfo,
    user_prv: UserPrivateKey,
    target_attribute: int,
    *,
    rng: Optional[np.random.Generator] = None,
) -> None:
    """Extend user with attribute ``target_attribute``.

    Steps (Ref[52] §III.E):
        1–2. Generate new (B', T_B') via TrapGen (see p3_enroll.py note)
        3.   Replace B^ID_{d,t} with B'
        4.   Send T_B' to user, update their private key

    Mutates ``user_pub`` and ``user_prv`` in place.
    """
    rng = rng or np.random.default_rng()
    lp = gp.params.lattice
    auth_id = authority_pk.authority_id
    key = (auth_id, target_attribute)

    # Steps 1–2: generate new delegated key pair
    B_new, T_B_new = trapgen(lp, rng=rng)

    # Step 3: update public key
    user_pub.B_matrices[key] = B_new
    user_pub.held_attributes.add(key)

    # Step 4: update user's private key
    user_prv.trapdoors[key] = T_B_new
    # Clear any cached preimage — it's no longer valid
    user_prv.preimages.pop(key, None)
