"""Merkle tree over SHA-256, with incremental update accounting.

Used by the proposed scheme for Phase IV commitments, Phase VII path updates,
and Phase VIII verifiable retrieval. Exposed to any baseline that needs an
authenticated data structure.

Three experiments read secondary metrics straight off this module, so it
counts work rather than making the caller estimate it:

* Exp. 4 — proof size (KB) and Merkle path length
* Exp. 5 — Merkle nodes recomputed per update
* Exp. 6 — Merkle path update inside the DIAS round
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

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
        measurement, which is what skill.md requires.

        Rebuilding the whole tree instead would be the Phase VII bug that
        skill.md's Exp. 5 rule explicitly calls out.
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


# ===========================================================================
# SetMerkleTrie — a Merkle root over a SET, updatable in O(log n)
# ===========================================================================
#
# WHY THIS EXISTS, AND WHY MerkleTree COULD NOT DO IT
# ---------------------------------------------------
# ``MerkleTree`` is an array tree: leaf i sits at position i. That is right when
# positions are stable (a record's index entries), and wrong when the leaves are
# a SET that must hash the same no matter what order it was built in. Sorting
# the leaves gives set-determined roots, but then inserting one element shifts
# every leaf after it, so a single insertion costs a full O(n) rebuild — and
# ``delta`` insertions with a root read after each cost O(delta^2). That is
# exactly what made the proposed scheme's Exp. 6 unable to complete (skill.md
# item 10, measured at O(n^2.02)).
#
# A binary radix trie keyed by the leaf digest fixes it. The trie shape is
# CANONICAL — determined by the key set alone, never by insertion order — so the
# root stays a pure function of the set, while an insertion or deletion touches
# only the O(log n) nodes on one root-to-leaf path.
#
# HASHING RULE, AND WHY EDGES ARE NOT PADDED
# ------------------------------------------
# A leaf hashes as ``hash_leaf(key)`` regardless of how deep it sits, and a
# branch as ``hash_node(left, right)``. Compressed edges are NOT padded with
# empty-subtree hashes for the levels they skip.
#
# That is safe because the key is inside the leaf hash: a leaf cannot be
# relocated to a different position without changing its own hash, which is the
# property padding would otherwise be buying. It matters for cost — padding a
# skipped edge means folding in one hash per skipped level, and with 256-bit
# keys that is ~256 hashes per insertion instead of ~log2(n), which would leave
# Exp. 6 an order of magnitude too slow rather than fixed. This is the same
# construction and the same argument as the Jellyfish Merkle Tree.
#
# Every branch has exactly two non-empty children, maintained on deletion by
# collapsing a branch that would be left with one. Without that the shape would
# depend on history and the root would stop being a function of the set.


def _key_bit(key: bytes, depth: int) -> int:
    """Bit ``depth`` of ``key``, most-significant first."""
    return (key[depth >> 3] >> (7 - (depth & 7))) & 1


class _TrieLeaf:
    __slots__ = ("key", "hash")

    def __init__(self, key: bytes) -> None:
        self.key = key
        self.hash = hash_leaf(key)


class _TrieBranch:
    """An internal node, tagged with the bit index it discriminates on.

    The depth is stored rather than inferred from position in the path: edges
    are compressed, so a branch is generally NOT at depth equal to how many
    branches were walked to reach it, and inferring it was the first thing that
    made this structure non-canonical.
    """

    __slots__ = ("left", "right", "depth", "hash")

    def __init__(self, left, right, depth: int) -> None:
        self.left = left
        self.right = right
        self.depth = depth
        self.hash = hash_node(left.hash, right.hash)


class SetMerkleTrie:
    """Authenticated set with an O(log n) insert, delete, and inclusion proof.

    Keys are fixed-width digests (32 bytes here). ``root`` is ``None`` for the
    empty set — callers supply their own sentinel, because what "no elements"
    should hash to is a protocol decision, not this structure's.

    The shape is canonical: a branch discriminates on the first bit at which its
    two subtrees differ, so the same key set always yields the same trie and the
    same root, whatever order it was built in and whatever was inserted and later
    deleted along the way.
    """

    __slots__ = ("_root", "_size", "_key_bits", "_key_bytes", "_updates")

    def __init__(self, key_bytes: int = DIGEST_BYTES) -> None:
        self._root = None
        self._size = 0
        self._key_bytes = key_bytes
        self._key_bits = key_bytes * 8
        self._updates = 0

    def __len__(self) -> int:
        return self._size

    @property
    def path_updates(self) -> int:
        """How many root-to-leaf paths have been rewritten.

        The Exp. 6 counterpart of ``MerkleTree.update_leaf``'s return value: it
        lets a test assert that one revocation rewrote one path, which is the
        incremental-update claim, rather than merely checking that the root
        changed — which a full rebuild would also do.
        """
        return self._updates

    def root(self) -> Optional[bytes]:
        return self._root.hash if self._root is not None else None

    # -- navigation ---------------------------------------------------------
    def _find_leaf(self, key: bytes):
        """Descend to the one leaf whose subtree ``key`` belongs to."""
        node = self._root
        while isinstance(node, _TrieBranch):
            node = node.left if _key_bit(key, node.depth) == 0 else node.right
        return node

    def _path_to(self, key: bytes, stop_depth: int):
        """Branches from the root down to ``stop_depth``, and what is below."""
        stack: List[Tuple[_TrieBranch, int]] = []
        node = self._root
        while isinstance(node, _TrieBranch) and node.depth < stop_depth:
            bit = _key_bit(key, node.depth)
            stack.append((node, bit))
            node = node.left if bit == 0 else node.right
        return stack, node

    @staticmethod
    def _rebuild(stack: List[Tuple[_TrieBranch, int]], sub):
        """Re-hash the recorded path from the change point up to the root."""
        for branch, bit in reversed(stack):
            sub = (
                _TrieBranch(sub, branch.right, branch.depth) if bit == 0
                else _TrieBranch(branch.left, sub, branch.depth)
            )
        return sub

    def __contains__(self, key: bytes) -> bool:
        leaf = self._find_leaf(key)
        return leaf is not None and leaf.key == key

    def _first_differing_bit(self, a: bytes, b: bytes) -> int:
        for depth in range(self._key_bits):
            if _key_bit(a, depth) != _key_bit(b, depth):
                return depth
        raise ValueError("keys are identical; no differing bit exists")

    # -- mutation -----------------------------------------------------------
    def insert(self, key: bytes) -> bool:
        """Add ``key``. Returns False when it was already present."""
        if len(key) != self._key_bytes:
            raise ValueError(
                f"key must be {self._key_bytes} bytes, got {len(key)}"
            )
        if self._root is None:
            self._root = _TrieLeaf(key)
            self._size = 1
            self._updates += 1
            return True

        neighbour = self._find_leaf(key)
        if neighbour.key == key:
            return False  # idempotent: the set already contains it

        split = self._first_differing_bit(key, neighbour.key)
        stack, below = self._path_to(key, split)

        fresh = _TrieLeaf(key)
        sub = (
            _TrieBranch(fresh, below, split) if _key_bit(key, split) == 0
            else _TrieBranch(below, fresh, split)
        )
        self._root = self._rebuild(stack, sub)
        self._size += 1
        self._updates += 1
        return True

    def delete(self, key: bytes) -> bool:
        """Remove ``key``. Returns False when it was not present."""
        if self._root is None:
            return False
        stack, node = self._path_to(key, self._key_bits)
        if not isinstance(node, _TrieLeaf) or node.key != key:
            return False

        if not stack:
            self._root = None            # the trie was this single leaf
        else:
            branch, bit = stack.pop()
            # Collapse: a branch left with one child is replaced by that child,
            # which is what keeps the shape a function of the set alone.
            sibling = branch.right if bit == 0 else branch.left
            self._root = self._rebuild(stack, sibling)
        self._size -= 1
        self._updates += 1
        return True

    # -- proofs -------------------------------------------------------------
    def prove(self, key: bytes) -> MerkleProof:
        """Inclusion proof for ``key``, verifiable by ``MerkleTree.verify``."""
        if self._root is None:
            raise KeyError("the trie is empty")
        stack, node = self._path_to(key, self._key_bits)
        if not isinstance(node, _TrieLeaf) or node.key != key:
            raise KeyError(f"{key.hex()} is not in the trie")
        path: List[Tuple[bytes, bool]] = []
        for branch, bit in reversed(stack):
            sibling = branch.right if bit == 0 else branch.left
            # sibling_is_left is True when the sibling hashes on the left,
            # i.e. when we descended right.
            path.append((sibling.hash, bit == 1))
        return MerkleProof(
            # No array position exists in a trie; the key read as a big-endian
            # integer is its canonical address in the 2^(8*key_bytes) space.
            leaf_index=int.from_bytes(key, "big"),
            leaf_hash=node.hash,
            path=tuple(path),
        )
