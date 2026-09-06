"""Phase III Step 1 — Rouselakis-Waters attribute key generation.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`:

    S_{U,i} subseteq A_i
    SK_{U,i} <- KeyGen(MSK_i, S_{U,i})
    SK_U     = union_{i=1..N_U} SK_{U,i}

The manuscript gives ``KeyGen`` as an interface only — it never defines the
structure of ``SK_{U,i}`` — so the construction was settled by decision on
2026-08-09 as Rouselakis-Waters. Recorded as `benchmark` provenance in
``PHASE_III_PLAN.md`` open decision 1.

**Which Rouselakis-Waters.** The decision named RW13 (Rouselakis and Waters,
*Practical Constructions and New Proof Methods for Large Universe Attribute-Based
Encryption*, CCS 2013). RW13 is **single**-authority: it has one master secret
``alpha`` and a public key carrying the large-universe hashing elements
``(u, h, w, v)``. It has no per-authority ``(alpha_i, beta_i)`` at all, so it
cannot express Phase I Step 2.

What this module implements is the **multi-authority** Rouselakis-Waters
construction (*Efficient Statically-Secure Large-Universe Multi-Authority
Attribute-Based Encryption*, FC 2015), which builds on RW13's large-universe
techniques and is the standard decentralised instantiation. That is not a
substitution for the decision — it is the same construction family, and the
published parameters point at it unambiguously:

    manuscript   MSK_i = (alpha_i, beta_i)   PK_i = (g_1, g_2, e(g_1,g_2)^{alpha_i}, g_1^{beta_i})
    RW15         SK_theta = (alpha_theta, y_theta)   PK_theta = (e(g,g)^{alpha_theta}, g^{y_theta})

with ``beta_i = y_theta``. The manuscript's four-element ``PK_i`` matches RW15's
per-authority key exactly and contains none of RW13's ``(u, h, w, v)``.
**Action for the manuscript:** cite the FC 2015 paper for the multi-authority
construction, not CCS 2013, or cite both with RW13 as the large-universe basis.

**The construction.** For user ``UID`` and each attribute ``u`` in ``S_{U,i}``:

    t_u <-$ Z_p
    K_u  = g_1^{alpha_i} * H(UID)^{beta_i} * F(u)^{t_u}
    K'_u = g_1^{t_u}

Two distinct roles, both load-bearing and both tested:

* ``t_u`` is fresh per attribute per issuance, so re-issuing the same attribute
  set never yields the same key.
* ``H(UID)^{beta_i}`` is the **collusion-resistance** term. It ties every
  component to the user's global identity, so two users cannot pool their key
  components to satisfy a policy neither satisfies alone. Without it the scheme
  is broken regardless of the rest, which is why a test isolates it under fixed
  randomness rather than relying on ``t_u`` to make keys differ.

**Group operations are injected** (:class:`ABEGroupOperations`), as in Phase I
Step 2. The only implementation in this package raises: the Type-III pairing
backend is still absent (``crypto.yaml``: ``backend_implemented: false``). This
module therefore constructs the *structure* of ``SK_{U,i}`` faithfully, but its
group arithmetic is only as real as the injected backend — and a key produced
through an unfaithful group belongs to a context whose ``assert_reportable()``
refuses. **Nothing here has been verified against real group algebra**; that
needs the charm backend on the experiment host.

Consequence for §V, unchanged by this module: the ABE layer is on no measured
path. Exp. 1 times ``T_Q = {H(w_i || VID_U)}`` (pure hashing), Exp. 4 excludes
decryption, and Phases III and V are untimed.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Protocol, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ..types import (  # noqa: E402
    AttributeKeyShare,
    AuthorityMasterKey,
    AuthorityPublicKey,
    EncodingError,
    UserRequest,
    canonical,
)
from ..user.delivery import DeliveryReceipt, seal_key_share  # noqa: E402
from ..user.registration import CredentialPolicy, validate_request  # noqa: E402
from .authority import (  # noqa: E402
    Authority,
    AuthorityError,
    GroupOperations,
    UnavailableGroupOperations,
)


class KeyGenError(AuthorityError):
    """Raised when an attribute key cannot be generated."""


class ABEGroupOperations(GroupOperations, Protocol):
    """The group arithmetic RW15 ``KeyGen`` needs.

    Extends the Phase I Step 2 protocol with the two operations key generation
    requires beyond exponentiation: a group multiplication and a hash into G_1.
    Elements and exponents stay serialised bytes, matching ``types.py``.
    """

    def multiply_g1(self, left: bytes, right: bytes) -> bytes:
        """The group operation in G_1."""

    def hash_to_g1(self, data: bytes) -> bytes:
        """``H`` and ``F`` — hash an identity or attribute name into G_1."""


class UnavailableABEOperations(UnavailableGroupOperations):
    """The only :class:`ABEGroupOperations` in this package. Every method raises.

    Deliberately not a working stub, on the same grounds as its base class: a
    stub would produce a structurally plausible ``SK_{U,i}`` from arithmetic that
    is not a group, and only vigilance would keep a reportable run off it.
    """

    def multiply_g1(self, left: bytes, right: bytes) -> bytes:
        raise KeyGenError(self._REASON)

    def hash_to_g1(self, data: bytes) -> bytes:
        raise KeyGenError(self._REASON)


@dataclass(frozen=True)
class RWKeyComponent:
    """One attribute's key pair ``(K_u, K'_u)``, both in G_1."""

    attribute: str
    k: bytes
    k_prime: bytes

    def __post_init__(self) -> None:
        if not self.attribute:
            raise ValueError("attribute must not be empty")
        for name in ("k", "k_prime"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")


@dataclass(frozen=True)
class RWAttributeKey:
    """``SK_{U,i}`` — the RW15 key an authority issues to one user.

    Secret material: this is only ever serialised into
    ``AttributeKeyShare.key_material`` and sealed by Phase III Step 3. It is not
    a ``Record`` and has no digest, for the same reason ``AttributeKeyShare`` is
    not one.
    """

    authority_id: str
    uid: str
    components: Tuple[RWKeyComponent, ...]

    def __post_init__(self) -> None:
        if not self.components:
            raise ValueError("an attribute key must cover at least one attribute")
        attributes = [component.attribute for component in self.components]
        if attributes != sorted(attributes):
            raise ValueError("components must be in sorted attribute order")
        if len(set(attributes)) != len(attributes):
            raise ValueError("duplicate attribute in the key")

    @property
    def attributes(self) -> Tuple[str, ...]:
        return tuple(component.attribute for component in self.components)

    def to_key_material(self) -> bytes:
        """Serialise the group elements, in sorted attribute order.

        Only the elements are stored: the attribute *names* already travel in
        ``AttributeKeyShare.attributes``, so storing them twice would create two
        sources of truth for which component belongs to which attribute.
        """
        flat: List[bytes] = []
        for component in self.components:
            flat.append(component.k)
            flat.append(component.k_prime)
        return canonical(flat)

    @classmethod
    def from_key_material(
        cls, *, authority_id: str, uid: str, attributes: Sequence[str], raw: bytes
    ) -> "RWAttributeKey":
        """Rebuild the key, pairing elements with ``attributes`` by position."""
        elements = _read_byte_sequence(raw)
        ordered = sorted(attributes)
        if len(elements) != 2 * len(ordered):
            raise EncodingError(
                f"key material holds {len(elements)} elements for "
                f"{len(ordered)} attributes; expected {2 * len(ordered)}"
            )
        return cls(
            authority_id=authority_id,
            uid=uid,
            components=tuple(
                RWKeyComponent(
                    attribute=attribute,
                    k=elements[2 * index],
                    k_prime=elements[2 * index + 1],
                )
                for index, attribute in enumerate(ordered)
            ),
        )

    def __repr__(self) -> str:
        return (
            f"RWAttributeKey(authority_id={self.authority_id!r}, uid={self.uid!r}, "
            f"|S_U,i|={len(self.components)}, elements=<redacted>)"
        )

    __str__ = __repr__


def _read_byte_sequence(raw: bytes) -> List[bytes]:
    """Decode ``canonical([bytes, bytes, ...])``.

    Narrow by design, like ``types._decode_sealed_share``: it reverses exactly
    one shape — a flat sequence of byte strings — rather than being a general
    canonical decoder. The encoder is the side that has to be trusted for every
    commitment in the scheme, and a general decoder would be a second parser for
    that format.
    """
    view = memoryview(raw)
    offset = 0

    def read_tag(expected: bytes) -> None:
        nonlocal offset
        tag = bytes(view[offset : offset + 1])
        if tag != expected:
            raise EncodingError(
                f"key material: expected tag {expected.hex()} at offset "
                f"{offset}, got {tag.hex()}"
            )
        offset += 1

    def read_length() -> int:
        nonlocal offset
        length = int.from_bytes(view[offset : offset + 4], "big")
        offset += 4
        return length

    read_tag(b"\x05")  # _T_SEQ
    count = read_length()
    elements: List[bytes] = []
    for _ in range(count):
        read_tag(b"\x01")  # _T_BYTES
        length = read_length()
        elements.append(bytes(view[offset : offset + length]))
        offset += length
    if offset != len(raw):
        raise EncodingError(
            f"key material: {len(raw) - offset} trailing bytes after decoding"
        )
    return elements


def key_generation(
    master_key: AuthorityMasterKey,
    public_key: AuthorityPublicKey,
    *,
    authority_id: str,
    uid: str,
    attributes: Sequence[str],
    operations: Optional[ABEGroupOperations] = None,
) -> RWAttributeKey:
    """``SK_{U,i} <- KeyGen(MSK_i, S_{U,i}, PK_i)`` — the RW15 construction.

    Per attribute ``u``::

        t_u <-$ Z_p
        K_u  = g_1^{alpha_i} * H(UID)^{beta_i} * F(u)^{t_u}
        K'_u = g_1^{t_u}

    ``g_1^{alpha_i}`` and ``H(UID)^{beta_i}`` do not depend on the attribute, so
    both are computed once and reused across the set: they are the same value for
    every component by construction, and recomputing them per attribute would
    cost ``2|S_{U,i}|`` exponentiations instead of two.
    """
    operations = operations or UnavailableABEOperations()
    ordered = sorted(set(attributes))
    if not ordered:
        raise KeyGenError(
            f"{authority_id}: cannot issue a key over an empty attribute set; an "
            f"authority that grants nothing must refuse"
        )
    if not uid:
        raise ValueError("uid must not be empty")

    # Shared across every component of this key.
    g1_alpha = operations.exponentiate_g1(public_key.g1, master_key.alpha)
    identity_bound = operations.exponentiate_g1(
        operations.hash_to_g1(_identity_input(uid)), master_key.beta
    )

    components: List[RWKeyComponent] = []
    for attribute in ordered:
        t = operations.random_exponent()
        f_u = operations.hash_to_g1(_attribute_input(attribute))
        k = operations.multiply_g1(
            operations.multiply_g1(g1_alpha, identity_bound),
            operations.exponentiate_g1(f_u, t),
        )
        components.append(
            RWKeyComponent(
                attribute=attribute,
                k=k,
                k_prime=operations.exponentiate_g1(public_key.g1, t),
            )
        )
    return RWAttributeKey(
        authority_id=authority_id, uid=uid, components=tuple(components)
    )


def _identity_input(uid: str) -> bytes:
    """Input to ``H`` — domain-separated so H(UID) cannot collide with F(u)."""
    return canonical(["identity", uid])


def _attribute_input(attribute: str) -> bytes:
    """Input to ``F`` — domain-separated from ``H``.

    RW15 uses two independent hash functions into the group. Instantiating both
    from one hash-to-curve with distinct, length-prefixed prefixes is the
    standard realisation, and keeps ``F(u) != H(u)`` for an attribute whose name
    equals some user's identity.
    """
    return canonical(["attribute", attribute])


def issue_key_share(
    authority: Authority,
    *,
    uid: str,
    attributes: Sequence[str],
    operations: Optional[ABEGroupOperations] = None,
) -> AttributeKeyShare:
    """Generate ``SK_{U,i}`` and wrap it for Phase III Step 3 delivery.

    Enforces ``S_{U,i} subseteq A_i`` here as well as at validation: this is the
    boundary where a key is actually minted, and issuing over another authority's
    attributes would break Phase II Step 2 disjointness from the issuance side
    regardless of which policy approved it.
    """
    ordered = sorted(set(attributes))
    outside = set(ordered) - set(authority.attributes)
    if outside:
        raise KeyGenError(
            f"{authority.authority_id}: refusing to issue a key over attributes "
            f"outside its namespace: {sorted(outside)}"
        )
    key = key_generation(
        authority.master_key,
        authority.public_key,
        authority_id=authority.authority_id,
        uid=uid,
        attributes=ordered,
        operations=operations,
    )
    return AttributeKeyShare(
        authority_id=authority.authority_id,
        uid=uid,
        attributes=tuple(ordered),
        key_material=key.to_key_material(),
    )


def recover_key(share: AttributeKeyShare) -> RWAttributeKey:
    """Rebuild ``SK_{U,i}`` from an opened share — the user side after Step 3."""
    return RWAttributeKey.from_key_material(
        authority_id=share.authority_id,
        uid=share.uid,
        attributes=share.attributes,
        raw=share.key_material,
    )


def issue_and_deliver(
    authority: Authority,
    request: UserRequest,
    *,
    policy: CredentialPolicy,
    operations: Optional[ABEGroupOperations] = None,
    allowed_domains: Optional[Sequence[str]] = None,
) -> DeliveryReceipt:
    """Phase III Steps 1-3 as one authority performs them.

    Validates ``Req_U`` under this authority's own local policy, generates
    ``SK_{U,i}`` over the granted subset, and seals it to ``pk_U^KEM``. The
    ordering matters: validation precedes key generation, so a refused request
    never mints a key that has to be discarded.

    ``vid`` for the delivery binding is the authority's current authorization
    version, so a key issued before a revocation cannot be replayed as one issued
    after it.
    """
    granted = validate_request(
        request,
        authority_id=authority.authority_id,
        available_attributes=authority.attributes,
        policy=policy,
        allowed_domains=allowed_domains,
    )
    share = issue_key_share(
        authority, uid=request.uid, attributes=granted, operations=operations
    )
    return seal_key_share(
        share, request.kem_encapsulation_key, vid=authority.vid
    )


__all__ = [
    "KeyGenError",
    "ABEGroupOperations",
    "UnavailableABEOperations",
    "RWKeyComponent",
    "RWAttributeKey",
    "key_generation",
    "issue_key_share",
    "recover_key",
    "issue_and_deliver",
]
