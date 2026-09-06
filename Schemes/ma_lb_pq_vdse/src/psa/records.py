"""D4/D5 — the index entry and the authorization profile, in manuscript form.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`:

    I_{i,j}    = (T_{i,j}, CID_i, PID_i, PV_i)             eq:index-entry
    AuthRoot_U = H( UID ‖ H(Encode(S_U)) ‖ H(Encode(V_U)) ‖ H(Encode(C_U)) )
    VAP_U      = (UID, D_U, V_U, C_U, AuthRoot_U)          Phase III Step 3

Both differ from ``types.py`` in the same way and for the same reason: the
scalar ``VID`` becomes policy-relevant state.

* :class:`PolicyStateIndexEntry` carries ``PV_i`` (32 bytes) where
  :class:`~..types.IndexEntry` carries ``vid`` (an int). The Merkle leaf is
  ``L_{i,j} = H(Encode(I_{i,j}))`` over this record, so the policy state is
  under ``Root_i`` and hence under ``Commit_i`` — a stale entry cannot be
  presented under a current root.

* :class:`PolicyStateProfile` carries ``V_U`` and ``C_U`` as **per-authority
  pairs**, where :class:`~..types.VersionBoundAuthorizationProfile` carries one
  ``vid`` and a bare tuple of commitments with no authority attached. The
  pairing is what Phase VII Step 4 needs to "refresh the affected entries of
  ``V_U`` and ``C_U``" — with an unattributed tuple there is no *affected
  entry* to refresh, only the whole thing.

These are new records rather than added fields on the existing ones. Adding a
field to a frozen :class:`~..types.Record` changes its canonical encoding and
therefore every digest ever taken over it, which would invalidate the banked
Option D results this package exists not to disturb.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Mapping, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..types import (  # noqa: E402
    Record,
    _check_digest,
    _check_identifier,
    canonical,
)
from .state import PolicyAuthorityState, PolicyVersionState  # noqa: E402


class RecordError(RuntimeError):
    """Raised when a policy-state-aware record cannot be formed."""


@dataclass(frozen=True)
class PolicyStateIndexEntry(Record):
    """``I_{i,j} = (T_{i,j}, CID_i, PID_i, PV_i)`` — eq:index-entry."""

    DOMAIN: ClassVar[bytes] = b"psa-index-entry/v1"

    token: bytes
    cid: str
    policy_id: str
    pv: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.token, (bytes, bytearray)):
            raise TypeError("token must be bytes")
        if not self.token:
            raise ValueError("token must not be empty")
        _check_identifier("cid", self.cid)
        _check_identifier("policy_id", self.policy_id)
        _check_digest("pv", self.pv)

    def _encoded_fields(self) -> Tuple[object, ...]:
        return (self.token, self.cid, self.policy_id, self.pv)

    def leaf(self) -> bytes:
        """``L_{i,j} = H(Encode(I_{i,j}))`` — Phase IV Step 4."""
        return self.digest()

    def re_tokenized(self, *, token: bytes, pv: bytes) -> "PolicyStateIndexEntry":
        """The Phase VII Step 2 update ``I'_{i,j} = (T'_{i,j}, CID_i, PID_i, PV'_i)``.

        There is no ``with_policy``-style payload-only rewrite here, and that
        absence is the point: under this construction a policy-state change
        moves the TOKEN, so the entry leaves its old posting list and joins a
        new one. ``types.IndexEntry.with_policy`` can rewrite payload alone
        because Option D's token does not depend on the policy state; that is
        the difference Exp. 5 measures (D1).
        """
        return PolicyStateIndexEntry(
            token=token, cid=self.cid, policy_id=self.policy_id, pv=pv
        )


@dataclass(frozen=True)
class PolicyStateProfile(Record):
    """``VAP_U = (UID, D_U, V_U, C_U, AuthRoot_U)`` — Phase III Step 3."""

    DOMAIN: ClassVar[bytes] = b"psa-vap/v1"

    uid: str
    domains: Tuple[str, ...]
    versions: PolicyVersionState
    commitments: PolicyAuthorityState
    auth_root: bytes

    def __post_init__(self) -> None:
        _check_identifier("uid", self.uid)
        _check_digest("auth_root", self.auth_root)
        if not self.domains:
            raise RecordError("D_U must name at least one authorized domain")
        if list(self.domains) != sorted(self.domains):
            raise RecordError("domains must be sorted; use build_profile()")
        if len(set(self.domains)) != len(self.domains):
            raise RecordError("duplicate domain in D_U")
        if self.versions.authority_ids != self.commitments.authority_ids:
            raise RecordError(
                f"V_U covers {self.versions.authority_ids} but C_U covers "
                f"{self.commitments.authority_ids}; Phase VI Step 2 checks that "
                f"every authority governing a policy is present in BOTH, so a "
                f"profile whose halves disagree would pass one check and fail "
                f"the other depending on which was consulted"
            )

    def _encoded_fields(self) -> Tuple[object, ...]:
        return (
            self.uid,
            list(self.domains),
            self.versions,
            self.commitments,
            self.auth_root,
        )

    @property
    def authority_ids(self) -> Tuple[str, ...]:
        """``AA_U`` — the authorities this profile is bound to."""
        return self.versions.authority_ids

    def version_of(self, authority_id: str) -> int:
        for authority, version in self.versions.versions:
            if authority == authority_id:
                return version
        raise RecordError(f"{authority_id!r} is not an authority of {self.uid!r}")

    def covers(self, governing: Sequence[str]) -> bool:
        """Phase VI Step 2's check that ``AA(P_ℓ) ⊆ AA_U``."""
        known = set(self.authority_ids)
        return all(authority in known for authority in governing)


def authorization_root(
    *,
    uid: str,
    attributes: Sequence[str],
    versions: PolicyVersionState,
    commitments: PolicyAuthorityState,
) -> bytes:
    """``AuthRoot_U = H(UID ‖ H(Encode(S_U)) ‖ H(Encode(V_U)) ‖ H(Encode(C_U)))``.

    ``S_U`` is hashed as a sorted sequence: the manuscript writes it as a set
    union over the issuing authorities, and a set has no order, so the order
    has to be fixed somewhere or two honest parties derive different roots.
    """
    _check_identifier("uid", uid)
    if not attributes:
        raise RecordError("S_U must contain at least one authorized attribute")
    attribute_digest = hashes.sha256(
        canonical(sorted(attributes)), domain=b"psa-attribute-set/v1"
    )
    return hashes.sha256(
        uid.encode("utf-8"),
        attribute_digest,
        versions.digest(),
        commitments.digest(),
        domain=b"psa-auth-root/v1",
    )


def build_profile(
    *,
    uid: str,
    domains: Sequence[str],
    attributes: Sequence[str],
    versions: Mapping[str, int],
    commitments: Mapping[str, bytes],
) -> PolicyStateProfile:
    """Assemble ``VAP_U`` over the authorities the user is enrolled with."""
    authority_ids = sorted(set(versions) & set(commitments))
    if not authority_ids:
        raise RecordError(
            "no authority appears in both V_U and C_U; the user is enrolled "
            "with nothing the AIM can validate against"
        )
    version_state = PolicyVersionState.build(versions, authority_ids)
    commitment_state = PolicyAuthorityState.build(commitments, authority_ids)
    return PolicyStateProfile(
        uid=uid,
        domains=tuple(sorted(set(domains))),
        versions=version_state,
        commitments=commitment_state,
        auth_root=authorization_root(
            uid=uid,
            attributes=attributes,
            versions=version_state,
            commitments=commitment_state,
        ),
    )


__all__ = [
    "PolicyStateIndexEntry",
    "PolicyStateProfile",
    "RecordError",
    "authorization_root",
    "build_profile",
]
