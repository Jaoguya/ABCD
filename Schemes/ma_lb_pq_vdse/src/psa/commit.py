"""D3 — the policy-state-aware record commitment.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`, Phase IV Steps 4-5:

    L_{i,j}  = H(Encode(I_{i,j}))
    Root_i   = MerkleRoot({L_{i,j}}_{j=1..t})              eq:index-root
    Commit_i = H( CID_i ‖ Root_i ‖ PID_i ‖ PV_i ‖ AuthState_i )
                                                           eq:record-commitment
    AMeta_i  = (CID_i, PID_i, PV_i, Root_i, AuthState_i, Commit_i)
                                                      eq:authenticated-metadata

WHAT CHANGED AGAINST ``index/commit.py``
----------------------------------------
Two inputs, and both matter:

* ``CID_i`` is now **inside** the commitment. In the implemented scheme
  ``Commit_i = H(Root_i ‖ PID_i ‖ VID_i ‖ AuthRoot_DO)`` and the ciphertext
  reference is not covered, so binding a returned entry to the exact encrypted
  object rests on the entry's own ``CID`` field being under ``Root_i``. Folding
  it in directly is what lets Phase VIII Step 2 detect a substituted ``CID``
  without re-deriving the Merkle path.

* ``AuthRoot_DO`` (the Data Owner's authorization root) is replaced by
  ``AuthState_i`` (a digest over the commitments of the **policy-governing**
  authorities). The DO's root says who outsourced the record; ``AuthState_i``
  says which authority states the record's authorization currently depends on,
  which is the thing Phase VIII Step 2 needs to check for freshness.

The consequence is that a commitment now moves whenever a governing authority's
state moves — Phase VII Step 3 recomputes it — where the implemented scheme's
commitment is stable under authority evolution. That is a cost, and Exp. 6 under
``--construction psa`` is what prices it.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes, merkle  # noqa: E402

from ..types import Record, _check_digest, _check_identifier, canonical  # noqa: E402
from .records import PolicyStateIndexEntry  # noqa: E402

#: Distinct from ``index/commit.py``'s tag, so an Option D commitment and a PSA
#: commitment over the same record cannot be substituted for one another.
_COMMIT_DOMAIN = b"psa-record-commitment/v1"


class CommitmentError(RuntimeError):
    """Raised when a policy-state-aware commitment cannot be formed."""


def record_root(
    entries: Sequence[PolicyStateIndexEntry],
) -> Tuple[bytes, merkle.MerkleTree]:
    """``Root_i`` — eq:index-root."""
    if not entries:
        raise CommitmentError(
            "a record with no index entries has no Merkle root (Phase IV Step 4)"
        )
    tree = merkle.MerkleTree([entry.leaf() for entry in entries])
    return tree.root, tree


def record_commitment(
    *, cid: str, root: bytes, policy_id: str, pv: bytes, auth_state: bytes
) -> bytes:
    """``Commit_i`` — eq:record-commitment. The single definition.

    Every ``‖`` is a length-prefixed, type-tagged field via ``canonical``, so no
    two distinct commitments collide by reframing
    field boundaries.
    """
    _check_identifier("cid", cid)
    _check_identifier("policy_id", policy_id)
    _check_digest("root", root)
    _check_digest("pv", pv)
    _check_digest("auth_state", auth_state)
    return hashes.sha256(
        canonical([cid, root, policy_id, pv, auth_state]), domain=_COMMIT_DOMAIN
    )


@dataclass(frozen=True)
class AuthenticatedMetadata(Record):
    """``AMeta_i`` — eq:authenticated-metadata, the tuple anchored on-chain.

    Phase VIII Step 2 fetches this and re-derives ``Commit_i`` from its other
    five fields, so it is self-checking: :meth:`verify` is exactly the acceptance
    test the Data User performs.
    """

    DOMAIN: ClassVar[bytes] = b"psa-authenticated-metadata/v1"

    cid: str
    policy_id: str
    pv: bytes
    root: bytes
    auth_state: bytes
    commit: bytes

    def __post_init__(self) -> None:
        _check_identifier("cid", self.cid)
        _check_identifier("policy_id", self.policy_id)
        _check_digest("pv", self.pv)
        _check_digest("root", self.root)
        _check_digest("auth_state", self.auth_state)
        _check_digest("commit", self.commit)

    def _encoded_fields(self) -> Tuple[object, ...]:
        return (
            self.cid, self.policy_id, self.pv,
            self.root, self.auth_state, self.commit,
        )

    def verify(self) -> bool:
        """``Commit_i* == Commit_i`` — Phase VIII Step 2."""
        expected = record_commitment(
            cid=self.cid, root=self.root, policy_id=self.policy_id,
            pv=self.pv, auth_state=self.auth_state,
        )
        return hashes.constant_time_equal(expected, self.commit)


@dataclass(frozen=True)
class PolicyStateCommitment:
    """The commitment plus the tree its proofs come from.

    The tree is retained rather than rebuilt per proof: ``index/commit.py``
    learned that the hard way (Exp. 4 was O(r^2) until the anchor fetch was
    batched), and rebuilding here would put the same shape back.
    """

    record_id: int
    root: bytes
    commit: bytes
    tree: merkle.MerkleTree
    entry_count: int
    meta: AuthenticatedMetadata

    def prove(self, entry_index: int) -> merkle.MerkleProof:
        return self.tree.prove(entry_index)


def commit_record(
    *,
    record_id: int,
    cid: str,
    entries: Sequence[PolicyStateIndexEntry],
    policy_id: str,
    pv: bytes,
    auth_state: bytes,
) -> PolicyStateCommitment:
    """Phase IV Steps 4-5 for one record.

    Entries must agree with the record on ``(CID_i, PID_i, PV_i)``. The check is
    not defensive tidiness: ``Commit_i`` binds one such triple, so an entry
    carrying a different one would sit under ``Root_i`` while contradicting
    ``Commit_i``, and Phase VIII would be verifying two different claims that
    both "pass".
    """
    mismatched = [
        entry for entry in entries
        if entry.policy_id != policy_id or entry.pv != pv or entry.cid != cid
    ]
    if mismatched:
        raise CommitmentError(
            f"record {record_id}: {len(mismatched)} of {len(entries)} entries "
            f"disagree with the record's (CID, PID, PV); Commit_i binds one triple"
        )
    root, tree = record_root(entries)
    commit = record_commitment(
        cid=cid, root=root, policy_id=policy_id, pv=pv, auth_state=auth_state
    )
    return PolicyStateCommitment(
        record_id=record_id,
        root=root,
        commit=commit,
        tree=tree,
        entry_count=len(entries),
        meta=AuthenticatedMetadata(
            cid=cid, policy_id=policy_id, pv=pv,
            root=root, auth_state=auth_state, commit=commit,
        ),
    )


__all__ = [
    "AuthenticatedMetadata",
    "CommitmentError",
    "PolicyStateCommitment",
    "commit_record",
    "record_commitment",
    "record_root",
]
