"""Merkle tree over SHA-256, with incremental update accounting.

Used by the proposed scheme for Phase IV commitments, Phase VII path updates,
and Phase VIII verifiable retrieval. Exposed to any baseline that needs an
authenticated data structure.

Three experiments read secondary metrics straight off this module, so it
counts work rather than making the caller estimate it:

* Exp. 4 — proof size (KB) and Merkle path length
* Exp. 5 — Merkle nodes recomputed per update
* Exp. 6 — Merkle path update inside the IAS round
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import List, Sequence, Tuple

# RFC 6962 domain separation. Without distinct prefixes an internal node's
# preimage could be presented as a leaf, letting a prover pass off an interior
# hash as data — the classic Merkle second-preimage attack.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

DIGEST_BYTES = 32


def hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


@dataclass(frozen=True)
class MerkleProof:
    """An inclusion proof: the sibling hashes from leaf to root."""

    leaf_index: int
    leaf_hash: bytes
    # (sibling_hash, sibling_is_left)
    path: Tuple[Tuple[bytes, bool], ...]

    @property
    def path_length(self) -> int:
        """Secondary metric for Exp. 4."""
        return len(self.path)

    @property
    def size_bytes(self) -> int:
        """Serialised proof size. Exp. 4 reports this in KB."""
        # Each step: 32-byte sibling digest + 1 direction byte.
        return len(self.path) * (DIGEST_BYTES + 1)


class MerkleTree:
    """Binary Merkle tree with an odd-node-promotion layout.

    A level with an odd number of nodes promotes its last node unchanged to
    the next level, rather than duplicating it. Duplication is the well-known
    CVE-2012-2459 pattern, where two distinct leaf sets yield the same root.
    """

    def __init__(self, leaves: Sequence[bytes]) -> None:
        if not leaves:
            raise ValueError("a Merkle tree needs at least one leaf")
        self._leaf_data: List[bytes] = [bytes(x) for x in leaves]
        self._levels: List[List[bytes]] = []
        self._build()

    # -- construction -------------------------------------------------------
    def _build(self) -> None:
        level = [hash_leaf(x) for x in self._leaf_data]
        self._levels = [level]
        while len(level) > 1:
            level = self._next_level(level)
            self._levels.append(level)

    @staticmethod
    def _next_level(level: Sequence[bytes]) -> List[bytes]:
        out: List[bytes] = []
        for i in range(0, len(level) - 1, 2):
            out.append(hash_node(level[i], level[i + 1]))
        if len(level) % 2:
            out.append(level[-1])  # promote, never duplicate
        return out

    # -- accessors ----------------------------------------------------------
    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    @property
    def leaf_count(self) -> int:
        return len(self._leaf_data)

    @property
    def height(self) -> int:
        return len(self._levels) - 1

    @property
    def node_count(self) -> int:
        return sum(len(level) for level in self._levels)

    # -- proofs -------------------------------------------------------------
    def prove(self, index: int) -> MerkleProof:
        """Inclusion proof for the leaf at ``index``."""
        self._check_index(index)
        path: List[Tuple[bytes, bool]] = []
        position = index
        for level in self._levels[:-1]:
            sibling = position ^ 1
            if sibling < len(level):
                path.append((level[sibling], sibling < position))
            # else: this node was promoted; it has no sibling at this level.
            position //= 2
        return MerkleProof(
            leaf_index=index,
            leaf_hash=self._levels[0][index],
            path=tuple(path),
        )

    @staticmethod
    def verify(proof: MerkleProof, root: bytes) -> bool:
        """Recompute the root from a proof. Client-side step of Exp. 4."""
        current = proof.leaf_hash
        for sibling, sibling_is_left in proof.path:
            current = (
                hash_node(sibling, current)
                if sibling_is_left
                else hash_node(current, sibling)
            )
        return hmac.compare_digest(current, root)

    @staticmethod
    def verify_leaf(data: bytes, proof: MerkleProof, root: bytes) -> bool:
        """Verify that ``data`` is the leaf the proof claims."""
        if hash_leaf(data) != proof.leaf_hash:
            return False
        return MerkleTree.verify(proof, root)

    # -- incremental update -------------------------------------------------
    def update_leaf(self, index: int, data: bytes) -> int:
        """Replace one leaf and refresh only the affected path.

        Returns the number of internal nodes recomputed — the Exp. 5
        secondary metric "Merkle nodes recomputed". Counting it here rather
        than deriving it as ``log2(N)`` keeps the reported figure a
        measurement, which is what README §14 requires.

        Rebuilding the whole tree instead would be the Phase VII bug that
        README §5's Exp. 5 rule explicitly calls out.
        """
        self._check_index(index)
        self._leaf_data[index] = bytes(data)
        self._levels[0][index] = hash_leaf(data)

        recomputed = 0
        position = index
        for depth in range(len(self._levels) - 1):
            level = self._levels[depth]
            parent_index = position // 2
            left_index = parent_index * 2
            right_index = left_index + 1
            if right_index < len(level):
                value = hash_node(level[left_index], level[right_index])
            else:
                value = level[left_index]  # promoted node
            self._levels[depth + 1][parent_index] = value
            recomputed += 1
            position = parent_index
        return recomputed

    def _check_index(self, index: int) -> None:
        if not 0 <= index < len(self._leaf_data):
            raise IndexError(
                f"leaf index {index} out of range for {len(self._leaf_data)} leaves"
            )


def commitment(items: Sequence[bytes]) -> bytes:
    """Merkle root over ``items`` — a one-shot commitment helper."""
    return MerkleTree(items).root
