"""Ref[41] PQ-ABSE — Thingom et al., IEEE TCE 2026.

Implemented as published. Section and line citations point at
``References/Ref[41].md``.

WHAT THIS SCHEME IS
-------------------
A single-authority CP-ABSE over a Type-I (symmetric) pairing, secure under
DBDH. Five phases: setup, key generation, encryption, search, decryption.

Note the paper self-refutes on post-quantum security: :83 asserts DBDH "forms
the foundation of the post-quantum security claims in this work", while :362
of the same paper states pairing-based cryptography "is not thought to be
feasible in a post-quantum setting since it depends on Diffie-Hellman-type
problems, which quantum computers can solve effectively". Per SystemConfiguration.md the
construction is reproduced as published and the contradiction reported as an
observation, not silently corrected.

WHAT IS ON THE MEASURED PATH
----------------------------
Ref[41] runs Exp. 1, 2 and 3 only. Those exercise setup, key
generation, encryption, trapdoor generation and search. They never reach
partial decryption or final decryption.

That distinction matters, because the paper's decryption path is not
recoverable as written. ``K_2``/``K_3`` are printed inconsistently across
:188-190 and :212-214 (``(o^xi)`` vs ``(phi^S)`` where the public parameters
only ever define ``h^xi``); ``q_UR`` in ``K'_3`` is never defined; and the
free ``a`` in ``K_3 = (K'_3)^{a w_1}`` (:196) appears nowhere else. Those
components are implemented on the most defensible reading and marked below,
but no reported number depends on them. Every quantity that Exp. 1-3 measure
is unambiguous in the paper and is reproduced exactly.

CORRECTNESS OF THE SEARCH RELATION
----------------------------------
Verified symbolically before implementing, so a failing search here is a bug
in this file rather than in the paper:

    e(CS_3j, L_1z) . e(CS_4j, L_0z)
      = e(i,i)^{gamma delta_j xi eta} . e(i^{gamma delta_j}, O_2)^{-a_z eta}
        . e(O_2^{delta_j}, i^{gamma a_z eta})
      = e(i,i)^{gamma delta_j xi eta}                      [O_2 terms cancel]

    B_t = prod_j (...)^{w_j} = e(i,i)^{gamma xi eta s}     [sum w_j delta_j = s]

    e(CS'_w, L_2) = e(i^{xi s}, i^{gamma eta} . O_3(w))
                  = e(i,i)^{xi s gamma eta} . e(i, O_3(w))^{xi s}

    => e(CS'_w, L_2) / B_t = e(i, O_3(w))^{xi s} = CS_w    [matches :344]
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple

from Common.crypto import symmetric
from Common.crypto.hashes import hkdf_sha256
from Common.crypto.pairing import PairingBackend

from .lsss import AccessStructure, reconstruction_coefficients, share

# Domain separators keep the three hash functions of :164-166 independent.
# The paper requires only that their outputs share a bit length; distinct
# domains are the standard way to instantiate that without collisions.
_DOMAIN_O1 = b"Ref41/O1/GID"
_DOMAIN_O2 = b"Ref41/O2/attribute"
_DOMAIN_O3 = b"Ref41/O3/keyword"


# ---------------------------------------------------------------------------
# Phase A: System Setup (:160-170)
# ---------------------------------------------------------------------------
@dataclass
class PublicParameters:
    """``PRP = {i, h, w, i^gamma, i^xi, h^xi, e(i,i), I_1, I_2, e, O_1, O_2, O_3}``

    Ref[41] eq. (3), :170.
    """

    backend: PairingBackend
    i: Any
    h: Any
    i_gamma: Any
    i_xi: Any
    h_xi: Any
    e_i_i: Any
    order: int

    def hash_o1(self, data: bytes) -> Any:
        return self.backend.hash_to_zr(_DOMAIN_O1 + data)

    def hash_o2(self, label: str) -> Any:
        return self.backend.hash_to_g1(_DOMAIN_O2 + label.encode("utf-8"))

    def hash_o3(self, keyword: str) -> Any:
        return self.backend.hash_to_g1(_DOMAIN_O3 + keyword.encode("utf-8"))

    def zr(self, value: int) -> Any:
        return self.backend.zr_from_int(value)

    def random_exponent(self) -> int:
        return secrets.randbelow(self.order - 1) + 1


@dataclass
class MasterSecretKey:
    """``MSCK = {gamma, xi}`` (:168)."""

    gamma: int
    xi: int


def setup(backend: PairingBackend) -> Tuple[PublicParameters, MasterSecretKey]:
    """System Setup Phase (:160-170).

    TCC picks two multiplicative cyclic groups of prime order w with
    generators i and h of I_1, defines e : I_1 x I_1 -> I_2, selects
    gamma, xi in F_w and publishes i^gamma, i^xi, h^xi and e(i,i).
    """
    order = backend.order()
    i = backend.random_g1()
    h = backend.random_g1()

    gamma = secrets.randbelow(order - 1) + 1
    xi = secrets.randbelow(order - 1) + 1

    zr_gamma = backend.zr_from_int(gamma)
    zr_xi = backend.zr_from_int(xi)

    params = PublicParameters(
        backend=backend,
        i=i,
        h=h,
        i_gamma=i**zr_gamma,
        i_xi=i**zr_xi,
        h_xi=h**zr_xi,
        e_i_i=backend.pair(i, i),
        order=order,
    )
    return params, MasterSecretKey(gamma=gamma, xi=xi)


# ---------------------------------------------------------------------------
# Phase B: Key Generation (Algorithm 4, :176-218)
# ---------------------------------------------------------------------------
@dataclass
class AttributeSecretKey:
    """``SCK_UR = {K_0z, K_1z, K_2, K_3}`` (:200, :254)."""

    k0: Dict[str, Any]  # keyed by "{Cate}:{Value}"
    k1: Dict[str, Any]
    k2: Any
    k3: Any
    attribute_labels: List[str]
    # a_z is DU-side randomness; retained because the trapdoor re-randomises
    # the key rather than re-deriving it, and because Exp. 1's trapdoor size
    # scales in the number of attributes.
    a_values: Dict[str, int] = field(default_factory=dict)


def keygen(
    params: PublicParameters,
    msk: MasterSecretKey,
    attributes: Sequence[Tuple[str, str]],
    global_identity: str,
) -> AttributeSecretKey:
    """Key Generation Phase (Algorithm 4, :176-218).

    Two-party by construction: the DU blinds its attributes and builds a
    partial key ``SCK'_UR``, the TCC completes it. Both sides run here in one
    process — Exp. 1-3 never time key generation, and the paper's own security
    argument for the split is about what the TCC *learns*, not about latency.
    """
    backend = params.backend
    order = params.order

    # -- DU side (:206-216) --------------------------------------------------
    cs_ur = params.random_exponent()
    mu = params.hash_o1(global_identity.encode("utf-8"))

    k0: Dict[str, Any] = {}
    k1: Dict[str, Any] = {}
    a_values: Dict[str, int] = {}
    labels: List[str] = []

    for category, value in attributes:
        label = f"{category}:{value}"
        labels.append(label)
        a_z = params.random_exponent()
        a_values[label] = a_z

        zr_a = params.zr(a_z)
        zr_neg_a = params.zr(-a_z % order)

        # K_0z = (i^gamma)^{a_z};  K_1z = i^xi . O_2({Cate:Value})^{-a_z}
        k0[label] = params.i_gamma**zr_a
        k1[label] = params.i_xi * (params.hash_o2(label) ** zr_neg_a)

    # K'_2, K'_3 (:214). The paper prints the base as "(o^xi)" here and
    # "(phi^S)" at :190; h^xi is the only such published parameter (:170), so
    # that is what is used. q_UR is undefined in the paper — f_UR = CS_UR.w_1
    # (:206) is the only jointly-derived value in scope, so K'_3 is built on
    # it. Neither component is reachable from Exp. 1-3; see module docstring.
    w1 = params.random_exponent()
    f_ur = (cs_ur * w1) % order

    k2_partial = params.h_xi ** params.zr(
        (int(_zr_to_int(backend, mu, order)) * cs_ur) % order
    )
    k3_partial = params.h_xi ** params.zr(f_ur)

    # -- TCC side (:218, :250) ----------------------------------------------
    # K_0z, K_1z pass through unchanged; K_2 = (K'_2)^{w_1}, K_3 = (K'_3)^{a.w_1}.
    # The exponent "a" at :250 is free in the paper. Reading it as w_1 is the
    # only choice that keeps the expression inside the published symbol set.
    zr_w1 = params.zr(w1)
    return AttributeSecretKey(
        k0=k0,
        k1=k1,
        k2=k2_partial**zr_w1,
        k3=k3_partial ** params.zr((w1 * w1) % order),
        attribute_labels=labels,
        a_values=a_values,
    )


def _zr_to_int(backend: PairingBackend, element: Any, order: int) -> int:
    """Interpret a backend exponent element as an int in ``[0, order)``.

    Serialising is NOT a valid route here: charm's ``serialize`` returns a
    tagged, base64-encoded form whose big-endian integer value is unrelated to
    the field element. charm ZR and petrelic Bn both support ``int()``, so
    that is used, with serialisation only as a last resort for a backend that
    supports neither.
    """
    if isinstance(element, int):
        return element % order
    try:
        return int(element) % order
    except (TypeError, ValueError):
        return int.from_bytes(backend.serialize(element), "big") % order


# ---------------------------------------------------------------------------
# Phase C: Encryption (Algorithm 5, :220-304)
# ---------------------------------------------------------------------------
@dataclass
class OfflineCiphertext:
    """``CPTSS_off = {I_idj, CF_j, CS_0j, CS_1j, CS_2j}`` (eq. 9, :280)."""

    identifier: int
    file_ciphertext: symmetric.Ciphertext
    cs0: Any
    cs1: Any
    cs2: Any


@dataclass
class KeywordIndex:
    """``I_w = {(CS_3j, CS_4j)_forall j, CS_w, CS'_w, N, phi}`` (eq. 13, :302)."""

    cs3: List[Any]
    cs4: List[Any]
    cs_w: Any
    cs_w_prime: Any
    structure: AccessStructure


@dataclass
class Ciphertext:
    """``CPTSS = {CPTSS_off, I_w}`` (:304)."""

    offline: OfflineCiphertext
    index: KeywordIndex


def encrypt_offline(
    params: PublicParameters, plaintext: bytes, identifier: int
) -> OfflineCiphertext:
    """Offline Encryption Algorithm (:272-282).

    ``ky_j = e(i,i)^{v_j}`` is a target-group element; AES-256-GCM needs 32
    bytes, so the group element is run through HKDF. The paper writes
    ``CF_j = Enc(B_j, ky_j)`` without naming the KDF or the cipher; crypto.yaml
    fixes AES-256-GCM as the benchmark-wide symmetric primitive so that this
    cost is identical across schemes.
    """
    v_j = params.random_exponent()
    zr_v = params.zr(v_j)

    ky_j = params.e_i_i**zr_v
    file_key = hkdf_sha256(
        params.backend.serialize(ky_j), length=32, info=b"Ref41/file-key"
    )

    return OfflineCiphertext(
        identifier=identifier,
        file_ciphertext=symmetric.encrypt(file_key, plaintext),
        # eq. (8), :274 — CS_0 and CS_2 are both printed as i^{v_j}.
        cs0=params.i**zr_v,
        cs1=params.i ** params.zr(-identifier % params.order),
        cs2=params.i**zr_v,
    )


def encrypt_online(
    params: PublicParameters, keyword: str, structure: AccessStructure
) -> KeywordIndex:
    """Online Encryption Algorithm (:284-302).

    One keyword per index. Ref[41] embeds exactly one ``O_3(w_w)`` per
    ciphertext (eq. 12, :298); a document carrying several keywords produces
    one index per keyword.
    """
    order = params.order
    s = params.random_exponent()
    randomness = [params.random_exponent() for _ in range(structure.columns - 1)]
    shares = share(structure, s, randomness, order)

    cs3: List[Any] = []
    cs4: List[Any] = []
    for j, delta_j in enumerate(shares):
        zr_delta = params.zr(delta_j)
        # eq. (11), :294
        cs3.append(params.i_gamma**zr_delta)
        cs4.append(params.hash_o2(structure.labelled_row(j)) ** zr_delta)

    zr_s = params.zr(s)
    return KeywordIndex(
        cs3=cs3,
        cs4=cs4,
        # eq. (12), :298 — CS_w = e(i^xi, O_3(w)^s), CS'_w = i^{xi s}
        cs_w=params.backend.pair(params.i_xi, params.hash_o3(keyword) ** zr_s),
        cs_w_prime=params.i_xi**zr_s,
        structure=structure,
    )


# ---------------------------------------------------------------------------
# Phase D: Search (:306-344)
# ---------------------------------------------------------------------------
@dataclass
class Trapdoor:
    """``L_w = {L_0z, L_1z, L_2}`` (eq. 16, :332).

    One keyword. ``L_2`` carries exactly one ``O_3(w_w)`` (eq. 15, :328), so a
    q-keyword query means q of these — see ``experiments.py`` for how Exp. 1 handles it.
    """

    l0: Dict[str, Any]
    l1: Dict[str, Any]
    l2: Any
    keyword: str

    def size_bytes(self, backend: PairingBackend) -> int:
        total = backend.element_size_bytes(self.l2)
        for element in self.l0.values():
            total += backend.element_size_bytes(element)
        for element in self.l1.values():
            total += backend.element_size_bytes(element)
        return total


def trapdoor(
    params: PublicParameters, key: AttributeSecretKey, keyword: str
) -> Trapdoor:
    """Trapdoor Generation Algorithm (:308-332).

    DU picks eta in F_w and re-randomises its attribute key:

        L_0z = (K_0z)^eta = i^{gamma a_z eta}
        L_1z = (K_1z)^eta = i^{xi eta} . O_2({Cate:Value})^{-a_z eta}
        L_2  = i^{gamma eta} . O_3(w_w)

    No pairings — trapdoor generation is 2u exponentiations plus one hash and
    one exponentiation, linear in the number of USER attributes u. This is
    what Exp. 1 measures.
    """
    eta = params.random_exponent()
    zr_eta = params.zr(eta)

    l0 = {label: element**zr_eta for label, element in key.k0.items()}
    l1 = {label: element**zr_eta for label, element in key.k1.items()}
    l2 = (params.i_gamma**zr_eta) * params.hash_o3(keyword)

    return Trapdoor(l0=l0, l1=l1, l2=l2, keyword=keyword)


@dataclass
class SearchResult:
    matched: bool
    pairings: int
    rows_evaluated: int


@dataclass
class QueryPlan:
    """Per-(policy, trapdoor) work, hoisted out of the per-ciphertext loop.

    Which rows the querying user satisfies, and the LSSS reconstruction
    coefficients ``w_j`` for those rows, are functions of the access structure
    and the trapdoor only — no ciphertext component enters either. The server
    derives them once per query, not once per candidate.

    This matters for fidelity, not only for speed. Ref[41]'s cost model
    (Table III, :485) contains no linear-algebra term at all; solving the
    system per candidate would charge the baseline for work its paper never
    claims, which SystemConfiguration.md forbids in the same breath as speeding a
    baseline up.
    """

    satisfied: List[int]
    coefficients: Dict[int, Any]  # row index -> backend exponent element
    labels: List[str]
    satisfiable: bool


def prepare_query(
    params: PublicParameters, structure: AccessStructure, token: Trapdoor
) -> QueryPlan:
    """Derive the reusable part of a search. Belongs inside the query timer."""
    satisfied = [
        j for j in range(structure.rows) if structure.labels[j] in token.l0
    ]
    if not satisfied:
        return QueryPlan([], {}, [], satisfiable=False)

    try:
        raw = reconstruction_coefficients(structure, satisfied, params.order)
    except ValueError:
        return QueryPlan(satisfied, {}, [], satisfiable=False)

    return QueryPlan(
        satisfied=satisfied,
        # Coerced to backend exponents once, rather than per candidate.
        coefficients={j: params.zr(raw[j]) for j in satisfied},
        labels=[structure.labels[j] for j in satisfied],
        satisfiable=True,
    )


def search_with_plan(
    params: PublicParameters,
    index: KeywordIndex,
    token: Trapdoor,
    plan: QueryPlan,
) -> SearchResult:
    """Search Algorithm (:336-344), given a prepared plan.

        B_t = prod_{i in |Delta|} ( e(CS_3i, L_1z) . e(CS_4i, L_0z) )^{w_j}
        match iff  e(CS'_w, L_2) / B_t == CS_w

    Cost per candidate is 2 pairings per policy row plus one for the keyword
    check — 2u+1 in total, with no filtering and no early termination. Ref[41]
    is the only pairing-based baseline in the benchmark; this is where that
    shows up.

    The pairings are computed one at a time, NOT batched into a shared final
    exponentiation. A multi-Miller product would cut this materially, but
    Ref[41]'s competitive claim rests on counted pairing operations, so
    batching would report the baseline as faster than its own analysis.
    """
    if not plan.satisfiable:
        return SearchResult(
            matched=False, pairings=0, rows_evaluated=len(plan.satisfied)
        )

    backend = params.backend
    b_t = None
    for j, label in zip(plan.satisfied, plan.labels):
        term = backend.pair(index.cs3[j], token.l1[label]) * backend.pair(
            index.cs4[j], token.l0[label]
        )
        weighted = term ** plan.coefficients[j]
        b_t = weighted if b_t is None else b_t * weighted

    left = backend.pair(token.l2, index.cs_w_prime)

    return SearchResult(
        matched=(left / b_t) == index.cs_w,
        pairings=2 * len(plan.satisfied) + 1,
        rows_evaluated=len(plan.satisfied),
    )


def search(
    params: PublicParameters, index: KeywordIndex, token: Trapdoor
) -> SearchResult:
    """Single-candidate convenience wrapper. Prefer the two-step form in a
    scan — this rebuilds the plan for every candidate."""
    plan = prepare_query(params, index.structure, token)
    return search_with_plan(params, index, token, plan)


# ---------------------------------------------------------------------------
# Phase E: Decryption (Algorithm 6, :312-324, :346-392)
# ---------------------------------------------------------------------------
# OFF THE MEASURED PATH. Ref[41] runs Exp. 1, 2 and 3 only, none of which
# reach decryption. Implemented for completeness on the reading described in
# the module docstring; the paper's notation here is not self-consistent, so
# these functions must not be used to produce a reported number without
# resolving that first.
# ---------------------------------------------------------------------------
@dataclass
class DecryptionToken:
    """``DECS_UR = {DECS_0, DECS_1, DECS_2}`` (eq. 7, :260)."""

    decs0: Any
    decs1: Any
    decs2: Any
    t: int


def token_generation(
    params: PublicParameters, key: AttributeSecretKey
) -> DecryptionToken:
    """Token Generation Algorithm (:258-264)."""
    t = params.random_exponent()
    inverse = params.zr(pow(t, -1, params.order))
    return DecryptionToken(
        decs0=key.k2**inverse,
        decs1=key.k3**inverse,
        decs2=params.i ** params.zr(t),
        t=t,
    )


def aggregate_key(
    params: PublicParameters, token: DecryptionToken, identifiers: Sequence[int]
) -> Any:
    """``ky_agg = i^gamma . i^{-D} . DECS_2`` where ``D = prod I_idj`` (eq. 20, :358)."""
    d = 1
    for identifier in identifiers:
        d = (d * identifier) % params.order
    return params.i_gamma * (params.i ** params.zr(-d % params.order)) * token.decs2
