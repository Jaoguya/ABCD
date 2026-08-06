"""Phase 2 — Authority Setup: (PK_d, MK_d) ← AASetup(GP)

Ref[52] §III.B, lines 248–265.

Each attribute authority AA_d generates a public/master key pair by running
TrapGen for each attribute it manages.  Public keys are the A matrices;
master keys are the corresponding trapdoors T_A.

"Through the AASetup algorithm, each attribute authority independently
generates its own key pair, achieving a decentralized structure with the
multi-authority feature." — §III.B note.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np

from Common.crypto.lattice import Trapdoor, trapgen

from .p1_setup import GlobalParams


@dataclass
class AuthorityPublicKey:
    """PK_d = {A_{d,i}}_{a_i ∈ U_d} — published on the PKB."""

    authority_id: int
    attribute_ids: List[int]
    A_matrices: Dict[int, np.ndarray]  # attr_id → A_{d,i} ∈ Z_q^{n×m}


@dataclass
class AuthorityMasterKey:
    """MK_d = {T_{A_{d,i}}}_{a_i ∈ U_d} — kept secret by AA_d."""

    authority_id: int
    trapdoors: Dict[int, Trapdoor]  # attr_id → T_{A_{d,i}}


def aa_setup(
    gp: GlobalParams,
    authority_id: int,
    attribute_ids: List[int],
    *,
    rng: Optional[np.random.Generator] = None,
) -> tuple[AuthorityPublicKey, AuthorityMasterKey]:
    """Generate one authority's key pair.

    Steps (Ref[52] §III.B):
        1. For each attribute a_i ∈ U_d:
           TrapGen(n, m, q, σ) → (A_{d,i}, T_{A_{d,i}})
        2. PK_d = {A_{d,i}}, publish
        3. MK_d = {T_{A_{d,i}}}, keep secret
    """
    rng = rng or np.random.default_rng()
    lp = gp.params.lattice

    pk_matrices: Dict[int, np.ndarray] = {}
    mk_trapdoors: Dict[int, Trapdoor] = {}

    for attr_id in attribute_ids:
        A, T_A = trapgen(lp, rng=rng)
        pk_matrices[attr_id] = A
        mk_trapdoors[attr_id] = T_A

    return (
        AuthorityPublicKey(authority_id, list(attribute_ids), pk_matrices),
        AuthorityMasterKey(authority_id, mk_trapdoors),
    )
