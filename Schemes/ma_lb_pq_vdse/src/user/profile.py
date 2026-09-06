"""Phase III Step 3 — Version-Bound Authorization Profile Generation.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`:

    S_U        = union_{i=1..N_U} S_{U,i}
    C_U        = { C_1^auth, ..., C_{N_U}^auth }
    AuthRoot_U = H( UID || H(S_U) || VID_U || H(C_U) )
    VAP_U      = ( UID, D_U, AuthRoot_U, VID_U, C_U )

The profile "uniquely binds the user identity, authorized attributes,
authorization version, and authority commitments into a single cryptographic
fingerprint", and is what the rest of the protocol treats as the user's
authorization: Phase VI Step 1 puts ``AuthRoot_U`` and ``VID_U`` into the search
token, Phase VI Step 2 checks them, Phase VI Step 3 computes
``C_j^sync = |VID_U - VID_j|`` from ``VID_U``, and Phase VIII Step 2 recomputes
``AuthRoot_U`` to verify retrieval. The Data Owner's profile supplies
``AuthRoot_DO`` to Phase IV Step 5's ``Commit_i``.

The AIM *maintains* the profile, so :func:`build_profile_from_aim` reads
its commitments and version table rather than taking them from the user or the
authorities. Deriving the profile from the AIM's ledger-backed view is what makes
it verifiable: ``aim.verify_against_ledger()`` already proves that view matches
the chain, so a profile built from it inherits that guarantee.

**Decisions** — three, all `benchmark`, all recorded in ``PHASE_III_PLAN.md``.

* ``H(S_U)`` and ``H(C_U)`` are unspecified, exactly as ``H(A_i)`` was in
  Phase II Step 2. Both use the rule already implemented there: SHA-256 over the
  canonical encoding of the **sorted** collection under a per-use domain tag.
  Order independence is required rather than cosmetic — the AIM enumerates
  authorities in no guaranteed order, and Phase VIII Step 2 must recompute the
  same root from the same set.
* ``VID_U`` is the **minimum** over the participating authorities' versions. The
  manuscript says only that "the AIM assigns the current authorization version
  identifier ``VID_U``", while ``C_U`` spans ``N_U`` authorities each with its own
  ``VID_i``. Phase VI Step 3 subtracts ``VID_j`` from it, so the two must share a
  scale and an aggregation rule or the difference is meaningless;
  ``fsn/fsn.py::FogSearchNode.vid`` already takes the minimum. This is the same
  single decision, not a second one. It does reach a reported number — it feeds
  the AASS score, hence Exp. 7-8.
* ``D_U`` is derived as ``{Dom_i : AA_i participating}`` rather than from the
  user's own ``Dom``: a user's *authorized* domains are the domains of the
  authorities that granted them attributes, which is what makes cross-domain
  search possible for a user enrolled in one domain.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..aim.aim import AuthorizationIndexManager  # noqa: E402
from ..types import (  # noqa: E402
    VersionBoundAuthorizationProfile,
    canonical,
)

# Domain tags. H(S_U), H(C_U) and AuthRoot_U are separated so that no one of them
# can be presented in place of another, and so H(S_U) cannot be confused with the
# H(A_i) of Phase II Step 2 over the same attribute strings.
_ATTRIBUTE_SET_DOMAIN = b"user-attribute-set/v1"
_COMMITMENT_SET_DOMAIN = b"authority-commitment-set/v1"
_AUTH_ROOT_DOMAIN = b"authorization-root/v1"


class ProfileError(RuntimeError):
    """Raised when a version-bound authorization profile cannot be built."""


def attribute_set_digest(attributes: Iterable[str]) -> bytes:
    """``H(S_U)`` over the sorted, deduplicated attribute set."""
    ordered = sorted(set(attributes))
    if not ordered:
        raise ProfileError(
            "S_U is empty; a user with no authorized attributes has no "
            "authorization profile to bind"
        )
    return hashes.sha256(canonical(ordered), domain=_ATTRIBUTE_SET_DOMAIN)


def commitment_set_digest(commitments: Iterable[bytes]) -> bytes:
    """``H(C_U)`` over the sorted authority commitments.

    Sorted by commitment bytes, not by authority ID: ``C_U`` is written as a set,
    and sorting its members makes the digest independent of how the caller
    enumerated them. Duplicates are rejected rather than collapsed — two
    authorities with an identical ``C_i^auth`` would mean two authorities with
    identical identity, domain, namespace, version and revocation state, which is
    a bug upstream, not a set to be silently shrunk.
    """
    ordered = sorted(commitments)
    if not ordered:
        raise ProfileError("C_U is empty; no participating authority commitments")
    if len(set(ordered)) != len(ordered):
        raise ProfileError("duplicate authority commitment in C_U")
    return hashes.sha256(canonical(ordered), domain=_COMMITMENT_SET_DOMAIN)


def aggregate_vid(vids: Sequence[int]) -> int:
    """``VID_U`` — the minimum across participating authorities.

    See the module docstring: this must match
    ``fsn/fsn.py::FogSearchNode.vid``'s aggregation, because Phase VI Step 3
    subtracts one from the other.
    """
    if not vids:
        raise ProfileError("no authorization versions to aggregate")
    for vid in vids:
        if vid < 0:
            raise ValueError(f"VID must be non-negative, got {vid}")
    return min(vids)


def authorization_root(
    *, uid: str, attribute_digest: bytes, vid: int, commitment_digest: bytes
) -> bytes:
    """``AuthRoot_U = H(UID || H(S_U) || VID_U || H(C_U))``.

    The single definition of the authorization root in the codebase. Phase VI
    Step 2 and Phase VIII Step 2 both recompute it and must call this rather than
    reimplement the concatenation.
    """
    if not uid:
        raise ValueError("uid must not be empty")
    if vid < 0:
        raise ValueError(f"VID must be non-negative, got {vid}")
    return hashes.sha256(
        canonical([uid, attribute_digest, vid, commitment_digest]),
        domain=_AUTH_ROOT_DOMAIN,
    )


def build_profile(
    *,
    uid: str,
    domains: Iterable[str],
    attributes: Iterable[str],
    vids: Sequence[int],
    commitments: Iterable[bytes],
    allowed_domains: Optional[Iterable[str]] = None,
) -> VersionBoundAuthorizationProfile:
    """Assemble ``VAP_U`` from its parts, sorting ``D_U`` and ``C_U``."""
    domain_tuple = tuple(sorted(set(domains)))
    if not domain_tuple:
        raise ProfileError("D_U is empty; the user is authorized for no domain")
    if allowed_domains is not None:
        unknown = set(domain_tuple) - set(allowed_domains)
        if unknown:
            raise ProfileError(
                f"D_U names domains no authority administers: {sorted(unknown)}"
            )
    commitment_tuple = tuple(sorted(commitments))
    vid = aggregate_vid(vids)
    return VersionBoundAuthorizationProfile(
        uid=uid,
        domains=domain_tuple,
        auth_root=authorization_root(
            uid=uid,
            attribute_digest=attribute_set_digest(attributes),
            vid=vid,
            commitment_digest=commitment_set_digest(commitment_tuple),
        ),
        vid=vid,
        commitments=commitment_tuple,
    )


def build_profile_from_aim(
    aim: AuthorizationIndexManager,
    *,
    uid: str,
    authority_ids: Sequence[str],
    attributes: Iterable[str],
) -> VersionBoundAuthorizationProfile:
    """Phase III Step 4 as the AIM performs it.

    ``D_U``, ``C_U`` and ``VID_U`` all come from the AIM's ledger-backed registry;
    only ``UID`` and ``S_U`` come from enrolment. That split is the point — a user
    cannot inflate their own authorization state, because every field that grants
    authority is read from the AIM.
    """
    if not authority_ids:
        raise ProfileError(
            f"{uid}: no participating authorities; N_U must be at least 1"
        )
    if len(set(authority_ids)) != len(authority_ids):
        raise ProfileError(f"{uid}: duplicate authority in the participating set")

    metas = [aim.meta_for_authority(authority_id) for authority_id in authority_ids]
    return build_profile(
        uid=uid,
        domains=[meta.domain for meta in metas],
        attributes=attributes,
        vids=[meta.vid for meta in metas],
        commitments=aim.commitments(authority_ids),
        allowed_domains=aim.domains(),
    )


def verify_profile(
    profile: VersionBoundAuthorizationProfile, *, attributes: Iterable[str]
) -> bool:
    """Recompute ``AuthRoot_U`` from ``(UID, S_U, VID_U, C_U)``.

    The Phase VIII Step 2 check, and the reason ``AuthRoot_U`` is a commitment
    rather than an identifier: a verifier holding the attribute set and the
    profile can confirm the root without trusting the AIM that issued it.
    """
    try:
        expected = authorization_root(
            uid=profile.uid,
            attribute_digest=attribute_set_digest(attributes),
            vid=profile.vid,
            commitment_digest=commitment_set_digest(profile.commitments),
        )
    except (ProfileError, ValueError):
        return False
    return hashes.constant_time_equal(expected, profile.auth_root)


def profile_matches_aim(
    profile: VersionBoundAuthorizationProfile,
    aim: AuthorizationIndexManager,
    authority_ids: Sequence[str],
) -> bool:
    """Whether a profile still reflects the AIM's current authorization state.

    False once any participating authority has advanced its version — which is
    exactly the stale-profile condition Phase VI Step 2 rejects and Phase VII
    creates. Returning a bool rather than raising: a stale profile is a normal
    consequence of authorization evolving, not an error.
    """
    try:
        current = aim.commitments(authority_ids)
        versions = [
            aim.meta_for_authority(authority_id).vid for authority_id in authority_ids
        ]
    except Exception:
        return False
    return (
        tuple(sorted(current)) == profile.commitments
        and aggregate_vid(versions) == profile.vid
    )


__all__ = [
    "ProfileError",
    "attribute_set_digest",
    "commitment_set_digest",
    "aggregate_vid",
    "authorization_root",
    "build_profile",
    "build_profile_from_aim",
    "verify_profile",
    "profile_matches_aim",
]
