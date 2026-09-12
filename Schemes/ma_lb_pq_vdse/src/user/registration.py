"""Phase III Step 1 — User Registration.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`:

    Req_U = (UID, Dom, Role, Cred)

"Each participating Attribute Authority **independently** validates the submitted
credentials according to its **local** policy."

Both roles enrol through this path: — "each Data Owner (DO) and Data User
(DU) enrolls with one or more Attribute Authorities according to their
organizational roles". A DO and a DU differ in the attributes they are granted,
not in the mechanism, which is why the Data Owner's authorization profile —
``AuthRoot_DO``, consumed by Phase IV Step 5's ``Commit_i`` — comes out of this
same phase.

**Independence is enforced structurally.** Each authority validates with its own
:class:`CredentialPolicy` instance and reaches its own verdict; no authority sees
another's decision, and there is no shared validator object to consult. A single
validator would collapse the multi-authority model into one trusted gatekeeper,
which is the arrangement §III's system model exists to remove.

**Decisions** (`benchmark`, Phase III open decision 4).
The manuscript specifies no credential format and no policy language. ``Cred`` is
therefore an opaque byte blob, and a policy is a callable from
``(role, domain)`` to the attribute subset an authority will issue. None of this
reaches a reported number: Phase III is untimed and no experiment exercises
enrolment.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional, Protocol, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import kem as kem_mod  # noqa: E402

from ..types import AttributeKeyShare, UserRequest  # noqa: E402


class RegistrationError(RuntimeError):
    """Raised when a registration request cannot be accepted."""


class CredentialRejected(RegistrationError):
    """Raised when an authority's local policy refuses a request.

    A refusal is a normal outcome, not a fault: authorities administer disjoint
    attribute universes for different domains, so most authorities will refuse
    most users.
    """


class CredentialPolicy(Protocol):
    """One authority's local validation policy.

    Returns the attribute subset ``S_{U,i} subseteq A_i`` the authority is willing
    to issue, or raises :class:`CredentialRejected`.
    """

    def evaluate(
        self, request: UserRequest, available_attributes: Sequence[str]
    ) -> Tuple[str, ...]:
        ...


@dataclass(frozen=True)
class RolePrefixPolicy:
    """Default policy: grant a fixed share of the namespace to known roles.

    A placeholder with a documented rule, not a claim about how a hospital issues
    attributes. It grants the first ``attributes_per_role`` attributes of the
    authority's namespace to any role in ``accepted_roles``, and refuses every
    other role. Deterministic, so a user's granted set is reproducible.

    ``require_domain_match`` models the common case that an authority only
    enrols users of its own administrative domain; a user needing cross-domain
    authorization enrols with that domain's authority instead, which is what
    makes ``D_U`` in Phase III Step 4 a set rather than a single value.
    """

    accepted_roles: Tuple[str, ...]
    attributes_per_role: int
    domain: str
    require_domain_match: bool = False

    def __post_init__(self) -> None:
        if not self.accepted_roles:
            raise ValueError("a policy must accept at least one role")
        if self.attributes_per_role < 1:
            raise ValueError("attributes_per_role must be >= 1")

    def evaluate(
        self, request: UserRequest, available_attributes: Sequence[str]
    ) -> Tuple[str, ...]:
        if request.role not in self.accepted_roles:
            raise CredentialRejected(
                f"role {request.role!r} is not accepted by the authority for "
                f"domain {self.domain!r}; accepted roles are "
                f"{list(self.accepted_roles)}"
            )
        if self.require_domain_match and request.domain != self.domain:
            raise CredentialRejected(
                f"user domain {request.domain!r} does not match the authority's "
                f"domain {self.domain!r}"
            )
        if not request.credential:
            raise CredentialRejected("empty credential")
        if self.attributes_per_role > len(available_attributes):
            raise RegistrationError(
                f"policy grants {self.attributes_per_role} attributes but the "
                f"authority's namespace holds {len(available_attributes)}"
            )
        return tuple(sorted(available_attributes)[: self.attributes_per_role])


@dataclass
class User:
    """A Data Owner or Data User enrolling across one or more authorities.

    Holds the ML-KEM decapsulation key, which is the reason the user — not the
    authority and not the AIM — generates the KEM keypair. ``shares`` accumulates
    the ``SK_{U,i}`` received in Step 3, keyed by authority.
    """

    uid: str
    domain: str
    role: str
    credential: bytes
    encapsulation_key: bytes
    _decapsulation_key: bytes = field(repr=False)
    shares: Dict[str, AttributeKeyShare] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for name in ("uid", "domain", "role"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")
        if not self.credential:
            raise ValueError("credential must not be empty")

    @classmethod
    def create(
        cls,
        *,
        uid: str,
        domain: str,
        role: str,
        credential: bytes,
        kem: Optional[kem_mod.MLKEM768] = None,
    ) -> "User":
        """Enrol a new user, generating ``(pk_U^KEM, sk_U^KEM)``."""
        keypair = (kem or kem_mod.MLKEM768()).keygen()
        return cls(
            uid=uid,
            domain=domain,
            role=role,
            credential=credential,
            encapsulation_key=keypair.encapsulation_key,
            _decapsulation_key=keypair.decapsulation_key,
        )

    @property
    def decapsulation_key(self) -> bytes:
        """``sk_U^KEM``. Only :mod:`..user.delivery` should need this."""
        return self._decapsulation_key

    def request(self) -> UserRequest:
        """``Req_U = (UID, Dom, Role, Cred)``, carrying ``pk_U^KEM``."""
        return UserRequest(
            uid=self.uid,
            domain=self.domain,
            role=self.role,
            credential=self.credential,
            kem_encapsulation_key=self.encapsulation_key,
        )

    def accept_share(self, share: AttributeKeyShare) -> None:
        """Record an opened ``SK_{U,i}``."""
        if share.uid != self.uid:
            raise RegistrationError(
                f"share is for {share.uid!r}, not {self.uid!r}"
            )
        if share.authority_id in self.shares:
            raise RegistrationError(
                f"a share from {share.authority_id!r} is already held; an "
                f"authority reissuing a key must replace it deliberately"
            )
        self.shares[share.authority_id] = share

    @property
    def authorities(self) -> Tuple[str, ...]:
        """The user's participating authorities, in ID order."""
        return tuple(sorted(self.shares))

    @property
    def authority_count(self) -> int:
        """``N_U``. Not specified in §VI; chosen as a Phase III decision."""
        return len(self.shares)

    def attribute_set(self) -> Tuple[str, ...]:
        """``S_U = union of S_{U,i}`` — the input to ``H(S_U)`` in Step 4."""
        attributes = {
            attribute
            for share in self.shares.values()
            for attribute in share.attributes
        }
        return tuple(sorted(attributes))

    def __repr__(self) -> str:
        return (
            f"User(uid={self.uid!r}, domain={self.domain!r}, role={self.role!r}, "
            f"N_U={self.authority_count}, |S_U|={len(self.attribute_set())}, "
            f"sk_U^KEM=<redacted>)"
        )


def validate_request(
    request: UserRequest,
    *,
    authority_id: str,
    available_attributes: Sequence[str],
    policy: CredentialPolicy,
    allowed_domains: Optional[Iterable[str]] = None,
) -> Tuple[str, ...]:
    """One authority's independent verdict on ``Req_U``.

    Returns ``S_{U,i}``, which Step 2 feeds to ``KeyGen``. Raises
    :class:`CredentialRejected` when the local policy refuses.

    ``allowed_domains`` checks the user's domain against the federation's real
    domains — the four the corpus defines. A request naming a domain no authority
    administers cannot be authorized by anyone, so accepting it would create a
    user whose ``D_U`` is unsatisfiable.
    """
    if allowed_domains is not None:
        allowed = set(allowed_domains)
        if request.domain not in allowed:
            raise CredentialRejected(
                f"user domain {request.domain!r} is not an administered domain; "
                f"known domains are {sorted(allowed)}"
            )
    granted = policy.evaluate(request, available_attributes)
    if not granted:
        raise CredentialRejected(
            f"{authority_id}: policy granted no attributes; an authority that "
            f"grants nothing must refuse rather than issue an empty key"
        )
    outside = set(granted) - set(available_attributes)
    if outside:
        # S_{U,i} subseteq A_i (Step 2). Violating it would issue a key over
        # another authority's attributes, breaking Phase II Step 2 disjointness
        # from the issuance side.
        raise RegistrationError(
            f"{authority_id}: policy granted attributes outside the authority's "
            f"namespace: {sorted(outside)}"
        )
    return tuple(sorted(granted))


__all__ = [
    "RegistrationError",
    "CredentialRejected",
    "CredentialPolicy",
    "RolePrefixPolicy",
    "User",
    "validate_request",
]
