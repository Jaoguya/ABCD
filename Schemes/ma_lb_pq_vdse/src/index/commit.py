"""Phase IV Steps 4-5 — Batch Integrity Commitment and Policy Commitment.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`, Phase IV Step 4 and Step 5:

    L_j      = H(I_j)
    Root_i   = MerkleRoot({L_j})
    Commit_i = H( Root_i ‖ PID_i ‖ VID_i ‖ AuthRoot_DO )

"Only the Merkle root is committed to the blockchain, while the authentication
paths are maintained by the cloud infrastructure for subsequent verifiable
retrieval" — so the ledger takes ``Root_i`` and the paths stay off-chain.

**Batch scope is one record** (: "batches all index entries associated with
one IoMT record into a Merkle tree"; ``index.yaml → merkle.batch_scope:
per_record``). At the frozen corpus's mean ``|W_i| = 31.7`` that is a ~32-leaf
tree of height 5, which sets the Exp. 4 proof size at roughly 5 x 33 bytes per
record.

``Commit_i`` binds ``AuthRoot_DO``, the Data Owner's version-bound authorization
root from Phase III Step 4 — the concrete reason Phase III had to precede Phase
IV. That binding is what ties outsourced data to its owner's authorization state
at the time of indexing.

:func:`policy_commitment` is the **single definition** of ``Commit_i``. Phase VII
Step 4 recomputes it as ``Commit_i'`` and Phase VIII Step 1 verifies it; both must
call this rather than reimplement the concatenation.

Note on the request's wording: ``Commit_i`` is the **policy** commitment of Step
**5**, not a domain commitment of Step 3. Step 3 (the DSI itself) is
``index/dsi.py``; the Merkle machinery is here because Steps 4 and 5 are one
chain — leaves to root to commitment — and splitting it would put ``Root_i``'s
construction in one module and its only consumer in another.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes, merkle  # noqa: E402

from ..types import IndexEntry, canonical  # noqa: E402

# Domain tag for the policy commitment, so a Commit_i cannot be presented as any
# other 32-byte digest in the scheme.
_COMMIT_DOMAIN = b"policy-commitment/v1"


class CommitmentError(RuntimeError):
    """Raised when a record's integrity commitment cannot be built."""


def entry_leaf(entry: IndexEntry) -> bytes:
    """``L_j = H(I_j)`` — the Merkle leaf data for one index entry.

    Returns the **domain-tagged** canonical encoding (``canonical(entry)``, which
    wraps the record with its ``DOMAIN``), for two reasons:

    * Not a digest. ``Common/crypto/merkle.py`` applies ``hash_leaf`` — with its
      ``0x00`` prefix — itself, so hashing here as well would build a tree over
      digests of digests: still sound, but no longer the ``L_j = H(I_j)`` the
      manuscript writes, and one more place for the two sides of a verification
      to disagree.
    * Domain-tagged rather than ``entry.encode()``, which is the bare field
      encoding. The tag means an ``IndexEntry`` leaf cannot collide with a leaf of
      some other record type that happens to encode to the same field bytes.
    """
    return canonical(entry)


@dataclass(frozen=True)
class RecordCommitment:
    """Everything Phase IV Step 4-5 produces for one record.

    ``tree`` is retained because the authentication paths live off-chain with the
    cloud infrastructure; only :attr:`root` is anchored.
    """

    record_id: int
    root: bytes
    commit: bytes
    tree: merkle.MerkleTree
    entry_count: int

    @property
    def height(self) -> int:
        return self.tree.height

    def prove(self, entry_index: int) -> merkle.MerkleProof:
        """Authentication path for one entry — the Exp. 4 client-side input."""
        return self.tree.prove(entry_index)

    def verify(self, proof: merkle.MerkleProof) -> bool:
        return merkle.MerkleTree.verify(proof, self.root)

    def proof_metrics(self, entry_index: int = 0) -> Tuple[int, int]:
        """``(path_length, size_bytes)`` — the Exp. 4 secondary metrics.

        Measured from an actual proof rather than derived as ``log2(N)``, because
        the tree promotes odd nodes instead of duplicating them, so a path can be
        shorter than the height and the derived figure would be wrong.
        """
        proof = self.prove(entry_index)
        return proof.path_length, proof.size_bytes


def record_root(entries: Sequence[IndexEntry]) -> Tuple[bytes, merkle.MerkleTree]:
    """``Root_i = MerkleRoot({L_j})`` over one record's entries."""
    if not entries:
        raise CommitmentError(
            "a record with no index entries has no Merkle root; Phase IV Step 4 "
            "batches the entries of one record, and the corpus guarantees "
            "|W_i| >= 5"
        )
    tree = merkle.MerkleTree([entry_leaf(entry) for entry in entries])
    return tree.root, tree


def policy_commitment(
    *, root: bytes, policy_id: str, vid: int, auth_root_do: bytes
) -> bytes:
    """``Commit_i = H(Root_i ‖ PID_i ‖ VID_i ‖ AuthRoot_DO)``.

    The single definition. Every ``‖`` is a length-prefixed, type-tagged field, so
    no two distinct commitments collide by field reframing.
    """
    if len(root) != merkle.DIGEST_BYTES:
        raise CommitmentError(
            f"Root_i must be {merkle.DIGEST_BYTES} bytes, got {len(root)}"
        )
    if len(auth_root_do) != merkle.DIGEST_BYTES:
        raise CommitmentError(
            f"AuthRoot_DO must be {merkle.DIGEST_BYTES} bytes, got "
            f"{len(auth_root_do)}"
        )
    if not policy_id:
        raise ValueError("policy_id must not be empty")
    if vid < 0:
        raise ValueError(f"VID must be non-negative, got {vid}")
    return hashes.sha256(
        canonical([root, policy_id, vid, auth_root_do]), domain=_COMMIT_DOMAIN
    )


def commit_record(
    *,
    record_id: int,
    entries: Sequence[IndexEntry],
    policy_id: str,
    vid: int,
    auth_root_do: bytes,
) -> RecordCommitment:
    """Phase IV Steps 4-5 for one record.

    The entries' own ``policy_id``/``vid`` must agree with the record's: the
    commitment binds one ``(PID_i, VID_i)`` pair, so an entry carrying a different
    one would be covered by ``Root_i`` while contradicting ``Commit_i``, and the
    verification of Phase VIII Step 1 would be checking two different claims.
    """
    mismatched = [
        entry
        for entry in entries
        if entry.policy_id != policy_id or entry.vid != vid
    ]
    if mismatched:
        raise CommitmentError(
            f"record {record_id}: {len(mismatched)} of {len(entries)} entries "
            f"carry a policy/version other than ({policy_id!r}, {vid}); "
            f"Commit_i binds a single pair"
        )
    root, tree = record_root(entries)
    return RecordCommitment(
        record_id=record_id,
        root=root,
        commit=policy_commitment(
            root=root, policy_id=policy_id, vid=vid, auth_root_do=auth_root_do
        ),
        tree=tree,
        entry_count=len(entries),
    )


def update_record_commitment(
    commitment: RecordCommitment,
    *,
    entry_index: int,
    entry: IndexEntry,
    policy_id: str,
    vid: int,
    auth_root_do: bytes,
) -> Tuple[RecordCommitment, int]:
    """Phase VII Step 3: ``Root_i' = MerkleUpdate(Root_i, L_delta)``.

    Returns the new commitment and the number of internal nodes recomputed — the
    Exp. 5 secondary metric "Merkle nodes recomputed", measured by
    ``merkle.update_leaf`` rather than derived as ``log2(N)``.

    Rebuilding the whole tree here would be the Phase VII bug global.yaml's Exp. 5
    rule calls out, so this refreshes only the affected authentication path.
    """
    tree = commitment.tree
    recomputed = tree.update_leaf(entry_index, entry_leaf(entry))
    root = tree.root
    return (
        RecordCommitment(
            record_id=commitment.record_id,
            root=root,
            commit=policy_commitment(
                root=root, policy_id=policy_id, vid=vid, auth_root_do=auth_root_do
            ),
            tree=tree,
            entry_count=commitment.entry_count,
        ),
        recomputed,
    )


def verify_commitment(
    commitment: RecordCommitment,
    *,
    policy_id: str,
    vid: int,
    auth_root_do: bytes,
) -> bool:
    """Recompute ``Commit_i`` from its inputs — the Phase VIII Step 1 check.

    Constant-time comparison: this is a verification result an adversary would
    like to learn incrementally.
    """
    expected = policy_commitment(
        root=commitment.root,
        policy_id=policy_id,
        vid=vid,
        auth_root_do=auth_root_do,
    )
    return hashes.constant_time_equal(expected, commitment.commit)


__all__ = [
    "CommitmentError",
    "RecordCommitment",
    "entry_leaf",
    "record_root",
    "policy_commitment",
    "commit_record",
    "update_record_commitment",
    "verify_commitment",
]
