"""Phase 1 — System Setup: GP ← Setup(λ, D, U)

Ref[52] §III.A, lines 222–247.

The Initializer selects cryptographic parameters and publishes the global
public parameters GP = {q, n, m, σ, H_0, {H_i}, D, U, L, χ, u}.

In the benchmark, most of these come from ``crypto.yaml`` via ``params.py``.
This function generates the random target vector u ∈ Z_q^n and returns the
assembled GP structure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import numpy as np

from Common.crypto.lattice import sample_uniform_zq

from ..params import SchemeParams


@dataclass
class GlobalParams:
    """Global public parameters — the GP output of Setup."""

    params: SchemeParams
    u_vector: np.ndarray       # u ∈ Z_q^n — random target vector
    authority_ids: List[int]   # D — set of authority identifiers
    attribute_ids: List[int]   # U — universe of attributes
    user_ids: List[str]        # L — enrolled user identities


def setup(
    params: SchemeParams,
    num_authorities: int = 1,
    *,
    rng: Optional[np.random.Generator] = None,
) -> GlobalParams:
    """Generate global public parameters.

    Steps (Ref[52] §III.A):
        1–3. Parameters and hash functions — from ``params`` / ``crypto.yaml``
        4.   L initialized empty (users enroll later)
        5.   Randomly choose u ∈ Z_q^n
        6.   Output GP
    """
    rng = rng or np.random.default_rng()
    lp = params.lattice

    # Step 5: random target vector
    u = sample_uniform_zq((lp.n,), lp.q, rng=rng)

    # Authority and attribute IDs — for the benchmark we use simple integers.
    # With one authority managing all ``l`` attributes (the common case):
    authority_ids = list(range(num_authorities))
    attribute_ids = list(range(params.num_attributes))

    return GlobalParams(
        params=params,
        u_vector=u,
        authority_ids=authority_ids,
        attribute_ids=attribute_ids,
        user_ids=[],
    )
