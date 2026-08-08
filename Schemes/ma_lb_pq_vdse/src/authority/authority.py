"""The Attribute Authority: Phase I Step 2 and Phase II Steps 1-3.

Phase I Step 2 — each authority independently runs

    (MSK_i, PK_i) <- Setup(1^lambda)
    MSK_i = (alpha_i, beta_i),  alpha_i, beta_i <-$ Z_p
    PK_i  = ( g_1, g_2, e(g_1,g_2)^{alpha_i}, g_1^{beta_i} )

Phase II Step 1 — registration: ``Reg_i = (ID_i, Dom_i, PK_i)``, anchored.
Phase II Step 2 — attribute namespace: ``A_i = {a_{i,1}, ..., a_{i,n_i}}``, where
"every attribute belongs exclusively to one authority".
Phase II Step 3 — the authorization-state commitment

    C_i^auth = H( ID_i || Dom_i || H(A_i) || VID_i || RevRoot_i )

Phase II Step 4 (publishing ``State_i`` and AIM synchronisation) is not here; the
ledger and AIM own it. This module produces the ``State_i`` record that Step 4
publishes.

**Group operations are injected.** Step 2 needs exponentiation in ``G_T`` and
``G_1``, which lives in the pairing backend that does not exist yet
(``crypto.yaml``: ``backend_implemented: false``). :class:`GroupOperations` is the
seam; the only implementation in this package raises, and the tests supply their
own. A key pair produced through an unfaithful group carries
``faithful=False`` up through :class:`GlobalContext`, so
``assert_reportable()`` still refuses. Phase II Steps 1-3 need no group
arithmetic at all and are therefore complete and fully tested today.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional, Protocol, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..chain.ledger import Ledger, LedgerEntry  # noqa: E402
from ..types import (  # noqa: E402
    AuthorityMasterKey,
    AuthorityPublicKey,
    AuthorityRegistration,
    AuthorityState,
    AuthorizationMeta,
    canonical,
)
from .initializer import GlobalContext  # noqa: E402
from .revocation import RevocationList  # noqa: E402

# Domain tags. H(A_i) and C_i^auth are separated so that a namespace digest can
# never be presented as an authorization-state commitment.
_NAMESPACE_DOMAIN = b"attribute-namespace/v1"
_COMMITMENT_DOMAIN = b"authorization-state-commitment/v1"


class AuthorityError(RuntimeError):
    """Raised on an invalid authority operation."""


class NamespaceConflictError(AuthorityError):
    """Raised when two authorities claim the same attribute.

    Phase II Step 2 requires disjoint attribute universes: "every attribute
    belongs exclusively to one authority. This decentralized namespace eliminates
    attribute conflicts across administrative domains."
    """


class GroupOperationsUnavailableError(AuthorityError):
    """Raised when Phase I Step 2 is attempted with no pairing backend."""


# ===========================================================================
# Phase I Step 2 — Setup(1^lambda)
# ===========================================================================
class GroupOperations(Protocol):
    """The group arithmetic Phase I Step 2 needs.

    Elements and exponents are serialised bytes, matching ``types.py``: this
    layer never holds backend objects, so it stays testable without one.
    """

    def random_exponent(self) -> bytes:
        """A uniform element of Z_p — one of alpha_i, beta_i."""

    def exponentiate_gt(self, base: bytes, exponent: bytes) -> bytes:
        """``base^exponent`` in G_T — computes e(g_1,g_2)^{alpha_i}."""

    def exponentiate_g1(self, base: bytes, exponent: bytes) -> bytes:
        """``base^exponent`` in G_1 — computes g_1^{beta_i}."""


class UnavailableGroupOperations:
    """The only :class:`GroupOperations` in this package. Every method raises.

    Deliberately not a working stub. A stub here would be a code path that
    produces a plausible-looking ``PK_i`` from arithmetic that is not the
    published construction, and nothing but vigilance would keep a reportable
    run off it. Tests inject their own.
    """

    _REASON = (
        "Phase I Step 2 needs exponentiation in G_T and G_1, which requires the "
        "Type-III pairing backend that Common/crypto/pairing.py does not yet "
        "provide (crypto.yaml: ma_lb_pq_vdse.pairing.backend_implemented: "
        "false). Add a Type-III charm backend and verify it on the experiment "
        "host, then wire it here."
    )

    def random_exponent(self) -> bytes:
        raise GroupOperationsUnavailableError(self._REASON)

    def exponentiate_gt(self, base: bytes, exponent: bytes) -> bytes:
        raise GroupOperationsUnavailableError(self._REASON)

    def exponentiate_g1(self, base: bytes, exponent: bytes) -> bytes:
        raise GroupOperationsUnavailableError(self._REASON)


def setup_authority_keys(
    context: GlobalContext, operations: Optional[GroupOperations] = None
) -> Tuple[AuthorityMasterKey, AuthorityPublicKey]:
    """Phase I Step 2: ``(MSK_i, PK_i) <- Setup(1^lambda)``.

    ``e(g_1,g_2)`` comes precomputed from Phase I Step 1, so each authority pays
    one G_T exponentiation and one G_1 exponentiation — not a pairing.
    """
    operations = operations or UnavailableGroupOperations()
    alpha = operations.random_exponent()
    beta = operations.random_exponent()
    if alpha == beta:
        # Overwhelmingly improbable from a uniform draw over Z_p; if it happens
        # the exponent source is broken, and MSK_i would have half the entropy
        # it is supposed to.
        raise AuthorityError(
            "alpha_i and beta_i are equal; the exponent source is not uniform"
        )
    return (
        AuthorityMasterKey(alpha=alpha, beta=beta),
        AuthorityPublicKey(
            g1=context.group.g1,
            g2=context.group.g2,
            e_g1g2_alpha=operations.exponentiate_gt(context.group.e_g1_g2, alpha),
            g1_beta=operations.exponentiate_g1(context.group.g1, beta),
        ),
    )


# ===========================================================================
# Phase II Step 2 — attribute namespace
# ===========================================================================
def namespace_digest(attributes: Iterable[str]) -> bytes:
    """``H(A_i)`` — the digest of an authority's attribute namespace.

    Phase II Step 3 calls it "the digest of the authority's attribute namespace"
    without fixing a construction. This is SHA-256 over the canonical encoding
    of the **sorted** attribute list under a dedicated domain tag, which makes it
    order-independent (a set has no order, and a digest that depended on
    insertion order could not be recomputed by a verifier) while remaining
    sensitive to membership.
    """
    ordered = sorted(attributes)
    if not ordered:
        raise AuthorityError(
            "an empty attribute namespace has no digest; Phase II Step 2 "
            "initialises A_i with the authority's managed attributes"
        )
    if len(set(ordered)) != len(ordered):
        raise AuthorityError("duplicate attribute in the namespace")
    return hashes.sha256(canonical(ordered), domain=_NAMESPACE_DOMAIN)


class AttributeNamespaceRegistry:
    """Enforces the system-wide disjointness of Phase II Step 2.

    Disjointness is a property of the *federation*, not of one authority, so it
    cannot be checked inside a single :class:`Authority`. This registry is the
    one place that sees every namespace, and it refuses a claim on an attribute
    another authority already owns.
    """

    def __init__(self) -> None:
        self._owner: Dict[str, str] = {}

    def claim(self, authority_id: str, attributes: Iterable[str]) -> None:
        ordered = sorted(attributes)
        conflicts = {
            attribute: self._owner[attribute]
            for attribute in ordered
            if attribute in self._owner and self._owner[attribute] != authority_id
        }
        if conflicts:
            detail = ", ".join(
                f"{attribute!r} already owned by {owner!r}"
                for attribute, owner in sorted(conflicts.items())
            )
            raise NamespaceConflictError(
                f"authority {authority_id!r} cannot claim attributes that belong "
                f"to another authority: {detail}. Phase II Step 2 requires "
                f"disjoint attribute universes."
            )
        for attribute in ordered:
            self._owner[attribute] = authority_id

    def release(self, authority_id: str) -> None:
        self._owner = {
            attribute: owner
            for attribute, owner in self._owner.items()
            if owner != authority_id
        }

    def owner_of(self, attribute: str) -> Optional[str]:
        return self._owner.get(attribute)

    @property
    def attribute_count(self) -> int:
        return len(self._owner)

    def universe(self) -> Tuple[str, ...]:
        return tuple(sorted(self._owner))


# ===========================================================================
# Phase II Step 3 — the authorization-state commitment
# ===========================================================================
def authorization_state_commitment(
    *,
    authority_id: str,
    domain: str,
    namespace_digest_value: bytes,
    vid: int,
    revocation_root: bytes,
) -> bytes:
    """``C_i^auth = H(ID_i || Dom_i || H(A_i) || VID_i || RevRoot_i)``.

    The single definition of the commitment in the codebase. Phase VII Step 3
    recomputes it with an incremented ``VID`` and an updated ``RevRoot``, and must
    call this rather than reimplement the concatenation — two copies of a
    commitment rule is one copy too many.

    Each ``||`` is a length-prefixed, type-tagged field (``types.canonical``), so
    no two distinct authorization states can produce one commitment by field
    reframing.
    """
    if vid < 0:
        raise ValueError(f"VID must be non-negative, got {vid}")
    return hashes.sha256(
        canonical([authority_id, domain, namespace_digest_value, vid, revocation_root]),
        domain=_COMMITMENT_DOMAIN,
    )


# ===========================================================================
# The authority
# ===========================================================================
@dataclass
class Authority:
    """One Attribute Authority ``AA_i``.

    Mutable, unlike the records it produces: an authority's version and
    revocation state evolve across Phase VII, while every ``State_i`` it has
    published stays immutable on the ledger.
    """

    authority_id: str
    domain: str
    attributes: Tuple[str, ...]
    public_key: AuthorityPublicKey
    master_key: AuthorityMasterKey
    vid: int = 0
    revocation: RevocationList = field(default_factory=RevocationList)

    def __post_init__(self) -> None:
        if not self.authority_id:
            raise ValueError("authority_id must not be empty")
        if not self.domain:
            raise ValueError("domain must not be empty")
        self.attributes = tuple(sorted(self.attributes))
        if not self.attributes:
            raise AuthorityError(
                f"authority {self.authority_id!r} has an empty attribute namespace"
            )
        if len(set(self.attributes)) != len(self.attributes):
            raise AuthorityError("duplicate attribute in the namespace")
        if self.vid < 0:
            raise ValueError("vid must be non-negative")

    # -- Phase I Step 2 -----------------------------------------------------
    @classmethod
    def create(
        cls,
        context: GlobalContext,
        *,
        authority_id: str,
        domain: str,
        attributes: Sequence[str],
        operations: Optional[GroupOperations] = None,
        registry: Optional[AttributeNamespaceRegistry] = None,
        vid: Optional[int] = None,
    ) -> "Authority":
        """Run Phase I Step 2 and initialise the Phase II Step 2 namespace.

        ``vid`` defaults to ``global.yaml``'s ``authorities.initial_vid`` rather
        than to a literal, so the initial version is configuration rather than a
        constant buried in code.
        """
        expected = context.config.authorities.attributes_per_authority
        if len(attributes) != expected:
            raise AuthorityError(
                f"authority {authority_id!r} was given {len(attributes)} "
                f"attributes but global.yaml sets attributes_per_authority="
                f"{expected}; per-authority namespace sizes must match, or one "
                f"authority silently carries more of the policy space than "
                f"another"
            )
        # Claim before generating keys: a namespace conflict is a configuration
        # error, and there is no reason to mint a key pair that must be discarded.
        if registry is not None:
            registry.claim(authority_id, attributes)
        master_key, public_key = setup_authority_keys(context, operations)
        return cls(
            authority_id=authority_id,
            domain=domain,
            attributes=tuple(attributes),
            public_key=public_key,
            master_key=master_key,
            vid=context.config.authorities.initial_vid if vid is None else vid,
        )

    # -- Phase II Step 1 ----------------------------------------------------
    def registration(self) -> AuthorityRegistration:
        """``Reg_i = (ID_i, Dom_i, PK_i)``."""
        return AuthorityRegistration(
            authority_id=self.authority_id,
            domain=self.domain,
            public_key=self.public_key,
        )

    def register(self, ledger: Ledger) -> LedgerEntry:
        """Phase II Step 1: anchor ``Reg_i`` on the consortium blockchain."""
        return ledger.register_authority(self.registration())

    # -- Phase II Steps 2-3 -------------------------------------------------
    def namespace_digest(self) -> bytes:
        """``H(A_i)``."""
        return namespace_digest(self.attributes)

    def revocation_root(self) -> bytes:
        """``RevRoot_i`` over the current revocation list."""
        return self.revocation.root()

    def commitment(self) -> bytes:
        """``C_i^auth`` for the authority's current state.

        Recomputed on every call rather than cached: a cached commitment would
        survive a change to the revocation list or the version, which is exactly
        the drift the commitment exists to make impossible.
        """
        return authorization_state_commitment(
            authority_id=self.authority_id,
            domain=self.domain,
            namespace_digest_value=self.namespace_digest(),
            vid=self.vid,
            revocation_root=self.revocation_root(),
        )

    def state(self) -> AuthorityState:
        """``State_i = (ID_i, PK_i, C_i^auth, VID_i)`` — published by Step 4."""
        return AuthorityState(
            authority_id=self.authority_id,
            public_key=self.public_key,
            commitment=self.commitment(),
            vid=self.vid,
        )

    def meta(self) -> AuthorizationMeta:
        """``Meta_i = (Dom_i, VID_i, C_i^auth)`` — what the AIM synchronises."""
        return AuthorizationMeta(
            domain=self.domain, vid=self.vid, commitment=self.commitment()
        )

    def __repr__(self) -> str:
        # No key material: master_key redacts itself, but the public key's
        # elements are noise in a log and the commitment is the useful identity.
        return (
            f"Authority(id={self.authority_id!r}, domain={self.domain!r}, "
            f"|A_i|={len(self.attributes)}, vid={self.vid}, "
            f"revoked={len(self.revocation)}, "
            f"C_auth={self.commitment().hex()[:16]}...)"
        )


def default_attributes(authority_id: str, count: int) -> Tuple[str, ...]:
    """Namespace-prefixed attribute names for one authority.

    The prefix is what makes the universes disjoint by construction: two
    authorities cannot accidentally mint the same attribute name. The manuscript
    requires disjointness (Phase II Step 2) but names no attributes, so these are
    ``benchmark`` values — a placeholder namespace of the configured size, not a
    claim about which clinical attributes a real authority manages.
    """
    if count < 1:
        raise ValueError("count must be >= 1")
    width = len(str(count))
    return tuple(f"{authority_id}:attr{index:0{width}d}" for index in range(1, count + 1))


__all__ = [
    "AuthorityError",
    "NamespaceConflictError",
    "GroupOperationsUnavailableError",
    "GroupOperations",
    "UnavailableGroupOperations",
    "AttributeNamespaceRegistry",
    "Authority",
    "authorization_state_commitment",
    "namespace_digest",
    "setup_authority_keys",
    "default_attributes",
]
