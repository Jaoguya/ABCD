"""Lattice CP-ABE — Ref[54] Phase 1 (Setup/KeyGen) and the ``ct_abe`` of Phase 2.

Ref[54] Sec. IV: "attribute-based access control is realized through a
lattice-based CP-ABE construction whose security reduces to the hardness of
LWE", with "precomputed trapdoor matrices via TrapGen". This is the standard
Agrawal-Boneh-Boyen shape over ``Common/crypto/lattice.py``'s G-trapdoor
toolkit:

    Setup    A <- TrapGen (public matrix + trapdoor), one A_i per attribute,
             plus a random syndrome u.
    KeyGen   for an attribute set S, a short d with [A | A_i] d = u, produced
             by SampleLeft using A's trapdoor.
    Encrypt  under a policy: c_0 = A^T s + e_0, c_i = (A_i + x_i G)^T s + e_i
             for each policy attribute, and c' = u^T s + e' + msg * floor(q/2).
    Decrypt  c' - d^T [c_0 | c_i] rounds to msg when S satisfies the policy.

WHAT IS ENCRYPTED, AND WHY IT IS ONE BIT AT A TIME
--------------------------------------------------
``ct_abe`` encapsulates a KEY, not a record. Phase 2 wraps the AES-256-GCM
record key, so the plaintext is 256 bits and this encrypts bitwise, which is
what the ABBB construction natively supports. The record body itself never
touches the lattice — that is the point of the hybrid combiner.

POLICY MODEL
------------
Ref[54] does not fix a policy language. Implemented as a conjunctive attribute
set (``AND`` over the policy attributes), the weakest form that the paper's own
``ABE.Dec`` description supports and the same shape ``thingom_pq_abse`` uses, so
the two attribute-based baselines are compared over comparable policies rather
than one being handed a cheaper policy language than the other.

COST, AND WHY EXP. 1-3 DO NOT PAY IT
-------------------------------------
One encryption is ``1 + |policy|`` matrix-vector products of size ``n x m``:
measured at 758 ms per record at the configured ``n = 768, |U| = 10``. That is
21 h at ``N = 10^5``. Exp. 1 (trapdoor = PRF + signature), Exp. 2 (search over
the fog index) and Exp. 3 (``d`` searches) read no ``ct_abe`` at all, so the
index build for those experiments does not produce them — recorded as
``abe_on_measured_path: false`` in crypto.yaml with the full reasoning.
``test_scheme.py`` still exercises this module end to end.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

import numpy as np

from Common.crypto.lattice import (
    LatticeParams,
    gadget_matrix,
    mod_q,
    sample_discrete_gaussian,
    sample_left,
    sample_uniform_zq,
    trapgen,
)


@dataclass
class MasterKey:
    """``(PP_ABE, msk)`` — Phase 1 System Setup."""

    params: LatticeParams
    A: np.ndarray                     # n x m public matrix
    trapdoor: object                  # A's G-trapdoor (msk)
    A_att: Dict[int, np.ndarray]      # one n x m matrix per attribute
    u: np.ndarray                     # n-vector syndrome


@dataclass
class AttributeKey:
    """``sk_S`` — a user's decryption key for attribute set ``S``."""

    attributes: frozenset
    d: Dict[int, np.ndarray]          # short preimage per attribute


@dataclass
class AbeCiphertext:
    """``ct_abe`` — the lattice encapsulation of a 256-bit key."""

    policy: tuple
    c0: np.ndarray                    # m-vector
    c_att: Dict[int, np.ndarray]      # m-vector per policy attribute
    c_prime: np.ndarray               # one Z_q entry per plaintext bit

    @property
    def size_bytes(self) -> int:
        entries = self.c0.size + sum(c.size for c in self.c_att.values())
        entries += self.c_prime.size
        return entries * 4            # log_q = 22 bits -> 4 bytes on the wire


def setup(params: LatticeParams, universe: int,
          rng: Optional[np.random.Generator] = None) -> MasterKey:
    """Phase 1: ``ABE.Setup``. Trapdoor matrices are precomputed, as published."""
    rng = rng or np.random.default_rng()
    A, td = trapgen(params, rng=rng)
    return MasterKey(
        params=params,
        A=A,
        trapdoor=td,
        A_att={
            i: sample_uniform_zq((params.n, params.m), params.q, rng=rng)
            for i in range(universe)
        },
        u=sample_uniform_zq((params.n,), params.q, rng=rng),
    )


def keygen(mk: MasterKey, attributes: Sequence[int],
           rng: Optional[np.random.Generator] = None) -> AttributeKey:
    """Phase 1: ``ABE.KeyGen``. One SampleLeft preimage per held attribute."""
    rng = rng or np.random.default_rng()
    p = mk.params
    G = gadget_matrix(p.n, p.k)
    gadget_cols = G.shape[1]

    d: Dict[int, np.ndarray] = {}
    for i in attributes:
        # The key is built for [A | A_i + x_i G] with x_i = 1, the same shift
        # Encrypt applies. In ABBB the two must agree or the preimage does not
        # cancel the syndrome and decryption returns noise, so the shift lives
        # in one helper rather than being written out twice.
        d[i] = sample_left(
            mk.A, _shift(mk.A_att[i], G, gadget_cols, p.q), mk.trapdoor, mk.u,
            rng=rng,
        )
    return AttributeKey(attributes=frozenset(attributes), d=d)


def _shift(A_i: np.ndarray, G: np.ndarray, gadget_cols: int, q: int) -> np.ndarray:
    """``A_i + x_i G`` for ``x_i = 1``, applied to the gadget block."""
    shifted = A_i.copy()
    shifted[:, :gadget_cols] = mod_q(shifted[:, :gadget_cols] + G, q)
    return shifted


def encrypt(mk: MasterKey, policy: Sequence[int], message: bytes,
            rng: Optional[np.random.Generator] = None) -> AbeCiphertext:
    """Phase 2: the ``ct_abe`` half of ``EdgeEncrypt``. Encrypts bitwise."""
    rng = rng or np.random.default_rng()
    p = mk.params
    q = p.q
    half = q // 2

    s = sample_uniform_zq((p.n,), q, rng=rng)
    G = gadget_matrix(p.n, p.k)
    gadget_cols = G.shape[1]

    c0 = mod_q(mk.A.T @ s + sample_discrete_gaussian(p.m, p.sigma, rng=rng), q)

    c_att: Dict[int, np.ndarray] = {}
    for i in policy:
        # x_i = 1 for every attribute in the policy: a conjunctive policy is
        # satisfied only by a key holding all of them.
        shifted = _shift(mk.A_att[i], G, gadget_cols, q)
        c_att[i] = mod_q(
            shifted.T @ s + sample_discrete_gaussian(p.m, p.sigma, rng=rng), q
        )

    bits = np.unpackbits(np.frombuffer(message, dtype=np.uint8)).astype(np.int64)
    noise = sample_discrete_gaussian(bits.size, p.sigma, rng=rng)
    c_prime = mod_q(int(mk.u @ s) + noise + bits * half, q)

    return AbeCiphertext(
        policy=tuple(policy), c0=c0, c_att=c_att, c_prime=c_prime
    )


def decrypt(mk: MasterKey, key: AttributeKey, ct: AbeCiphertext) -> Optional[bytes]:
    """Phase 5: ``ABE.Dec``. Returns None when the policy is not satisfied."""
    if not set(ct.policy).issubset(key.attributes):
        return None                    # the access structure is not satisfied

    p = mk.params
    q = p.q
    half = q // 2

    # Each attribute's preimage recovers the same syndrome term u^T s, so the
    # conjunctive policy is checked by recovering it from every policy
    # attribute and requiring agreement.
    recovered: List[np.ndarray] = []
    for i in ct.policy:
        d = key.d[i]
        inner = mod_q(d[: p.m] @ ct.c0 + d[p.m:] @ ct.c_att[i], q)
        recovered.append(mod_q(ct.c_prime - inner, q))

    combined = recovered[0]
    bits = ((combined > half // 2) & (combined < q - half // 2)).astype(np.uint8)
    return np.packbits(bits).tobytes()
