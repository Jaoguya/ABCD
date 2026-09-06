"""Phase VI Step 2 — Authorization Verification and Token Derivation at the AIM.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`:

"The Authorization Index Manager verifies the submitted authorization state by
checking the user's **authorization root**, **authorization version**,
**participating authority commitments**, and **permitted administrative domains**.
If ``(AuthRoot_U, VID_U, C_U)`` are consistent with the latest authorization state
maintained by the participating Attribute Authorities, the AIM identifies the
authorized searchable-index shards and forwards the validated search request to
the AASS. **Otherwise, the request is rejected without traversing the encrypted
index.**"

Four named checks, so :class:`AuthorizationDecision` reports four outcomes rather
than one boolean. "Rejected without traversing" is only auditable if a rejection
says *which* check failed — and Exp. 2's latency story depends on a rejection
costing nothing, which cannot be shown by a function that returns ``False``.

**``rho`` is also verified here**, because nowhere else can. The manuscript
introduces it as "a fresh random nonce preventing replay attacks", but a nonce
prevents nothing unless a verifier remembers it: without
:class:`NonceRegistry`, ``rho`` is a field that gets transmitted and ignored, and
a captured ``ST`` replays forever.

**What this does not do: evaluate an access policy against the user's attributes.**
Deciding which policies a user's ``S_U`` satisfies is LSSS evaluation over the
MA-CP-ABE construction — Phase III/ABE work, on no measured path (Exp. 1 is
hashing, Exp. 4 excludes decryption). :class:`PolicyResolver` is the seam, so the
authorization *protocol* is complete and testable while the attribute algebra
stays where it belongs. ``MappingPolicyResolver`` is an explicit lookup, not a
guess at the algebra.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Protocol, Sequence, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..types import SearchToken, VersionBoundAuthorizationProfile  # noqa: E402
from ..user.profile import aggregate_vid, verify_profile  # noqa: E402
from .aim import AIMError, AuthorizationIndexManager  # noqa: E402


class VerificationRejected(RuntimeError):
    """Raised only for malformed input, never for a failed check.

    A failed check is a :class:`AuthorizationDecision` with ``accepted = False`` —
    the protocol's intended outcome for an unauthorized request. Raising for it
    would make rejection cost an exception unwind, and Exp. 2 would be timing that.
    """


class PolicyResolver(Protocol):
    """Which policies in a domain a user's attribute set satisfies."""

    def policies_for(
        self, *, uid: str, domain: str, attributes: Sequence[str]
    ) -> Tuple[str, ...]:
        ...


@dataclass(frozen=True)
class MappingPolicyResolver:
    """An explicit ``(uid, domain) -> policies`` lookup.

    Deliberately a lookup and not an attribute-algebra approximation: guessing at
    LSSS evaluation would put a construction this module has no basis for on the
    authorization path. Real policy evaluation replaces this without touching
    anything else here.
    """

    mapping: Mapping[Tuple[str, str], Tuple[str, ...]]

    def policies_for(
        self, *, uid: str, domain: str, attributes: Sequence[str]
    ) -> Tuple[str, ...]:
        return tuple(sorted(self.mapping.get((uid, domain), ())))


class NonceRegistry:
    """Seen ``rho`` values, which is what makes the nonce do anything.

    Bounded by ``capacity`` so a long Exp. 7-8 run at 5,000 concurrency cannot grow
    it without limit. Eviction is FIFO, which means a nonce can in principle be
    replayed after ``capacity`` further requests — a real deployment would bound by
    time instead. Recorded rather than hidden: the alternative is an unbounded set
    that turns a throughput experiment into a memory experiment.
    """

    def __init__(self, capacity: int = 1_000_000) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._seen: Set[bytes] = set()
        self._order: list[bytes] = []

    def __len__(self) -> int:
        return len(self._seen)

    def seen(self, nonce: bytes) -> bool:
        return nonce in self._seen

    def remember(self, nonce: bytes) -> None:
        if nonce in self._seen:
            return
        self._seen.add(nonce)
        self._order.append(nonce)
        if len(self._order) > self.capacity:
            self._seen.discard(self._order.pop(0))

    def check_and_remember(self, nonce: bytes) -> bool:
        """True if fresh; records it. False if this ``rho`` has been seen."""
        if self.seen(nonce):
            return False
        self.remember(nonce)
        return True


@dataclass(frozen=True)
class Check:
    """One of Step 2's four named checks, plus the nonce check."""

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class AuthorizationDecision:
    """Step 2's outcome: accept with a shard set, or reject with a reason."""

    accepted: bool
    checks: Tuple[Check, ...]
    authorized_shards: Tuple[Tuple[str, str], ...] = ()

    @property
    def failed_check(self) -> Optional[str]:
        for check in self.checks:
            if not check.passed:
                return check.name
        return None

    @property
    def reason(self) -> str:
        for check in self.checks:
            if not check.passed:
                return check.detail or check.name
        return ""

    @property
    def domains(self) -> Tuple[str, ...]:
        return tuple(sorted({domain for domain, _ in self.authorized_shards}))

    @property
    def policy_count(self) -> int:
        """``|P_Q|`` — what the AASS score's ``C_j^auth`` term counts."""
        return len({policy for _, policy in self.authorized_shards})


def verify_search_request(
    aim: AuthorizationIndexManager,
    token: SearchToken,
    profile: VersionBoundAuthorizationProfile,
    *,
    authority_ids: Sequence[str],
    attributes: Sequence[str],
    resolver: PolicyResolver,
    nonces: Optional[NonceRegistry] = None,
) -> AuthorizationDecision:
    """Phase VI Step 2, returning the authorized shard set on acceptance.

    The five checks, in the order that fails cheapest first — a rejected request
    must not pay for the checks after the one that rejected it:

    1. ``rho`` freshness (a replay is the cheapest thing to detect);
    2. the profile's own consistency — ``AuthRoot_U`` recomputes from
       ``(UID, S_U, VID_U, C_U)``;
    3. ``AuthRoot_U`` and ``VID_U`` in ``ST`` match the profile;
    4. ``C_U`` matches the authorities' **latest** commitments at the AIM;
    5. ``VID_U`` matches the aggregate of those authorities' versions.

    Check 4 is the one that makes the whole thing worth doing: it is what detects a
    stale profile after a Phase VII revocation, since the AIM's view is
    ledger-backed and the user's ``C_U`` is a snapshot.
    """
    if not authority_ids:
        raise VerificationRejected(
            "no participating authorities; N_U must be at least 1"
        )
    checks: list[Check] = []

    # 1 — replay.
    if nonces is not None:
        fresh = nonces.check_and_remember(token.nonce)
        checks.append(
            Check(
                name="nonce",
                passed=fresh,
                detail="" if fresh else "rho has been seen; replayed request",
            )
        )
        if not fresh:
            return AuthorizationDecision(accepted=False, checks=tuple(checks))

    # 2 — the profile is internally consistent.
    profile_ok = verify_profile(profile, attributes=attributes)
    checks.append(
        Check(
            name="profile",
            passed=profile_ok,
            detail="" if profile_ok else "AuthRoot_U does not recompute from (UID, S_U, VID_U, C_U)",
        )
    )
    if not profile_ok:
        return AuthorizationDecision(accepted=False, checks=tuple(checks))

    # 3 — the token's claims match the profile.
    root_ok = hashes.constant_time_equal(token.auth_root, profile.auth_root)
    version_ok = token.vid_u == profile.vid
    checks.append(
        Check(
            name="authorization_root",
            passed=root_ok,
            detail="" if root_ok else "ST's AuthRoot_U does not match the profile",
        )
    )
    checks.append(
        Check(
            name="authorization_version",
            passed=version_ok,
            detail=""
            if version_ok
            else f"ST claims VID_U={token.vid_u}, profile holds {profile.vid}",
        )
    )
    if not (root_ok and version_ok):
        return AuthorizationDecision(accepted=False, checks=tuple(checks))

    # 4 — C_U against the AIM's latest, ledger-backed commitments.
    try:
        current = aim.commitments(authority_ids)
    except AIMError as exc:
        checks.append(
            Check(name="authority_commitments", passed=False, detail=str(exc))
        )
        return AuthorizationDecision(accepted=False, checks=tuple(checks))
    commitments_ok = tuple(sorted(current)) == profile.commitments
    checks.append(
        Check(
            name="authority_commitments",
            passed=commitments_ok,
            detail=""
            if commitments_ok
            else "C_U does not match the authorities' latest commitments; the "
            "profile is stale (an authority has evolved its state)",
        )
    )
    if not commitments_ok:
        return AuthorizationDecision(accepted=False, checks=tuple(checks))

    # 5 — VID_U against the same authorities' aggregate.
    expected_vid = aggregate_vid(
        [aim.meta_for_authority(a).vid for a in authority_ids]
    )
    aggregate_ok = profile.vid == expected_vid
    checks.append(
        Check(
            name="version_aggregate",
            passed=aggregate_ok,
            detail=""
            if aggregate_ok
            else f"VID_U={profile.vid} but the authorities aggregate to "
            f"{expected_vid}",
        )
    )
    if not aggregate_ok:
        return AuthorizationDecision(accepted=False, checks=tuple(checks))

    # Permitted domains, then the shards within them.
    shards: list[Tuple[str, str]] = []
    for domain in profile.domains:
        for policy in resolver.policies_for(
            uid=profile.uid, domain=domain, attributes=attributes
        ):
            shards.append((domain, policy))

    if not shards:
        checks.append(
            Check(
                name="permitted_domains",
                passed=False,
                detail=f"no policy in D_U={list(profile.domains)} is satisfied by "
                f"this user's attributes; nothing to search",
            )
        )
        return AuthorizationDecision(accepted=False, checks=tuple(checks))

    checks.append(Check(name="permitted_domains", passed=True))
    return AuthorizationDecision(
        accepted=True,
        checks=tuple(checks),
        authorized_shards=tuple(sorted(set(shards))),
    )


__all__ = [
    "VerificationRejected",
    "PolicyResolver",
    "MappingPolicyResolver",
    "NonceRegistry",
    "Check",
    "AuthorizationDecision",
    "verify_search_request",
]
