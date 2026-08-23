"""RevRoot_i — the authenticated revocation root of Phase II Step 3.

Phase II Step 3: "Each authority initializes its authorization state by assigning
a version identifier ``VID_i`` and constructing an **authenticated revocation
root** ``RevRoot_i`` over the current revocation list." Phase VII Step 3 then
"updates its revocation root ``RevRoot_k'``" whenever revocation state changes.

*Authenticated* is why this is a Merkle tree rather than a flat digest: a root
that can only be recomputed from the whole list proves nothing to a party
holding one identifier, whereas a Merkle root admits an inclusion proof. Nothing
in Phases I-II consumes such a proof yet, but the construction the paper names is
the one built here, and :meth:`RevocationList.prove` exposes it.

Two design points the manuscript leaves open, both settled here and tested:

**Leaf order is the sorted set, not insertion order.** "Over the current
revocation list" reads as a function of the *set* of revoked identifiers.
Sorting makes ``RevRoot_i`` reproducible by any party holding the same set — a
verifier who had to know the order in which revocations happened could not
recompute the root at all. The cost is that an insertion shifts leaf positions,
so the tree is rebuilt rather than path-updated (see :meth:`root`).

**The empty list needs a sentinel.** ``Common/crypto/merkle.py`` refuses a
zero-leaf tree ("a Merkle tree needs at least one leaf"), and rightly — there is
no meaningful root over nothing. But every authority starts with an empty
revocation list at Phase II Step 3, so ``RevRoot_i`` must be defined there.
:data:`EMPTY_REVOCATION_ROOT` is a domain-separated constant that cannot collide
with any populated tree's root: a populated root is built from
``merkle.hash_leaf``/``hash_node``, which prefix their inputs with ``0x00``/
``0x01``, while the sentinel is a ``hashes.sha256`` digest under its own domain
tag. Using ``bytes(32)`` or an all-zero root instead would collide with any tree
an adversary could contrive to produce zeros, and would make "no revocations"
indistinguishable from "root not yet computed".
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes, merkle  # noqa: E402

# Domain tag for revocation-list leaves, so a revoked-identifier leaf cannot be
# reinterpreted as a leaf of the searchable index or of any other tree in the
# scheme.
_LEAF_DOMAIN = b"revocation/leaf/v1"

#: RevRoot_i for an empty revocation list — the state every authority is in at
#: Phase II Step 3. Distinct by construction from every populated root.
EMPTY_REVOCATION_ROOT = hashes.sha256(
    b"empty-revocation-list", domain=b"revocation/empty/v1"
)


class RevocationError(RuntimeError):
    """Raised on an invalid revocation-list operation."""


def revocation_leaf(identifier: str) -> bytes:
    """Canonical leaf bytes for a revoked identifier.

    The identifier is domain-tagged and hashed rather than used raw, so leaves
    are fixed width and the tree does not carry plaintext user identifiers.
    """
    if not isinstance(identifier, str):
        raise TypeError(
            f"revoked identifier must be str, got {type(identifier).__name__}"
        )
    if not identifier:
        raise ValueError("revoked identifier must not be empty")
    return hashes.sha256(identifier.encode("utf-8"), domain=_LEAF_DOMAIN)


class RevocationList:
    """The revocation list of one Attribute Authority, with its Merkle root.

    The root is computed lazily and cached, then invalidated by any mutation.
    That is what keeps Phase VII affordable: revoking ``delta`` identifiers and
    then reading :meth:`root` once costs a single O(n) rebuild, not ``delta`` of
    them. Since the protocol recomputes ``RevRoot_k'`` once per version increment
    (Phase VII Step 3), batching per version is what the construction describes
    anyway — and Exp. 6 sweeps ``delta`` to 10^5, where a rebuild per revocation
    would be O(delta^2) hashing and would measure this class rather than the IAS
    mechanism it is meant to measure.
    """

    def __init__(self, revoked: Iterable[str] = ()) -> None:
        self._revoked: set[str] = set()
        self._cached_root: Optional[bytes] = None
        self._cached_order: Optional[Tuple[str, ...]] = None
        self._rebuilds = 0
        for identifier in revoked:
            self.revoke(identifier)

    # -- state --------------------------------------------------------------
    def __len__(self) -> int:
        return len(self._revoked)

    def __contains__(self, identifier: str) -> bool:
        return identifier in self._revoked

    @property
    def is_empty(self) -> bool:
        return not self._revoked

    @property
    def revoked(self) -> Tuple[str, ...]:
        """The revoked set in canonical (sorted) order."""
        return tuple(sorted(self._revoked))

    @property
    def rebuild_count(self) -> int:
        """How many times the tree has been rebuilt.

        Exposed so a caller can assert that a batch of revocations produced ONE
        rebuild. A test that only checked the root would pass either way.
        """
        return self._rebuilds

    # -- mutation -----------------------------------------------------------
    def revoke(self, identifier: str) -> None:
        """Add one identifier. Idempotent; does not recompute the root."""
        revocation_leaf(identifier)  # validate before mutating
        if identifier not in self._revoked:
            self._revoked.add(identifier)
            self._invalidate()

    def revoke_many(self, identifiers: Iterable[str]) -> int:
        """Add several identifiers. Returns how many were newly revoked."""
        added = 0
        for identifier in identifiers:
            if identifier not in self._revoked:
                self.revoke(identifier)
                added += 1
        return added

    def restore(self, identifier: str) -> None:
        """Remove an identifier from the revocation list.

        Present because ``RevRoot_i`` is defined over the *current* list and the
        list is not append-only in principle. The ledger's history of published
        ``C_i^auth`` values is what remains immutable.
        """
        if identifier not in self._revoked:
            raise RevocationError(f"{identifier!r} is not revoked")
        self._revoked.discard(identifier)
        self._invalidate()

    def _invalidate(self) -> None:
        self._cached_root = None
        self._cached_order = None

    # -- root ---------------------------------------------------------------
    def root(self) -> bytes:
        """RevRoot_i over the current list.

        Returns :data:`EMPTY_REVOCATION_ROOT` when the list is empty, and the
        Merkle root over the sorted leaves otherwise.
        """
        if self._cached_root is None:
            self._cached_root = self._compute_root()
        return self._cached_root

    def _compute_root(self) -> bytes:
        if not self._revoked:
            self._cached_order = ()
            return EMPTY_REVOCATION_ROOT
        order = self.revoked
        self._cached_order = order
        self._rebuilds += 1
        return merkle.MerkleTree([revocation_leaf(i) for i in order]).root

    def tree(self) -> merkle.MerkleTree:
        """The underlying tree. Raises when the list is empty."""
        if not self._revoked:
            raise RevocationError(
                "an empty revocation list has no Merkle tree; its root is the "
                "EMPTY_REVOCATION_ROOT sentinel"
            )
        return merkle.MerkleTree([revocation_leaf(i) for i in self.revoked])

    def prove(self, identifier: str) -> merkle.MerkleProof:
        """Inclusion proof that ``identifier`` is revoked."""
        if identifier not in self._revoked:
            raise RevocationError(f"{identifier!r} is not revoked; nothing to prove")
        order = self.revoked
        return self.tree().prove(order.index(identifier))

    def verify(self, identifier: str, proof: merkle.MerkleProof) -> bool:
        """Check an inclusion proof against the current root."""
        if self.is_empty:
            return False
        return merkle.MerkleTree.verify(proof, self.root())

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return (
            f"RevocationList(size={len(self._revoked)}, "
            f"root={self.root().hex()[:16]}...)"
        )


def revocation_root(revoked: Sequence[str]) -> bytes:
    """One-shot ``RevRoot_i`` over a revocation list."""
    return RevocationList(revoked).root()


__all__ = [
    "EMPTY_REVOCATION_ROOT",
    "RevocationError",
    "RevocationList",
    "revocation_leaf",
    "revocation_root",
]
