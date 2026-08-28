"""The fog-side hybrid index — Ref[54] Phase 3, and what Exp. 2 searches.

Phase 3 tokenizes each record's searchable fields with a PRF and files the
tokens into four structures, each chosen for one query shape:

    B+-tree          exact keyword lookup
    bucketed bitmap  numeric range predicates
    equality bitmap  categorical predicates
    epoch partitions temporal predicates
    n-gram map       fuzzy match, scored by overlap against a threshold theta

Search (Phase 4, ``SearchExec``) intersects candidate sets across whichever
structures the query touches. That intersection — not any lattice operation —
is the whole of Exp. 2's measured path, which is the paper's headline claim:
the client only generates PRF tokens, and the fog does index work.

WHY THE B+-TREE IS A REAL TREE
------------------------------
A Python dict would serve exact lookup faster and would flatter the baseline.
The paper specifies a B+-tree, its Table II costs it as ``O(log n)``, and its
Fig. 3 reports the tree's fanout behaviour — reporting dict lookups under that
name would measure a structure the scheme does not have and would understate
its search cost. So it is a real B+-tree with a configurable order, and lookups
really do descend it.

TOKENS ARE KEYED, NOT HASHED
----------------------------
``token(w) = PRF_k(w)`` under the fog's tokenization key, per Phase 3. An
unkeyed hash would leak the keyword to anyone holding the index and would make
the trapdoor derivable without the key — the same "unkeyed token" condition
this repo's own provenance gate refuses to call reportable.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from Common.crypto.hashes import hmac_sha256

DEFAULT_ORDER = 64


def token(key: bytes, keyword: str) -> bytes:
    """``PRF_k(w)`` — the Phase 3 tokenization, and the Phase 4 trapdoor value."""
    return hmac_sha256(key, b"perera/token", keyword.encode("utf-8"))


# ---------------------------------------------------------------------------
# B+-tree
# ---------------------------------------------------------------------------
class _Node:
    __slots__ = ("keys", "children", "values", "nxt", "leaf")

    def __init__(self, leaf: bool) -> None:
        self.leaf = leaf
        self.keys: List[bytes] = []
        self.children: List["_Node"] = []
        self.values: List[List[int]] = []
        self.nxt: Optional["_Node"] = None


class BPlusTree:
    """Order-``m`` B+-tree over PRF tokens, values are posting lists."""

    def __init__(self, order: int = DEFAULT_ORDER) -> None:
        if order < 3:
            raise ValueError(f"B+-tree order must be >= 3, got {order}")
        self.order = order
        self._root = _Node(leaf=True)
        self._height = 1
        self._descents = 0

    @property
    def height(self) -> int:
        return self._height

    @property
    def descents(self) -> int:
        """Nodes visited across all lookups — the Exp. 2 secondary metric.

        Exposed because "O(log n)" is a claim about this number, and a run that
        reported latency alone could not show whether the tree was being
        descended or short-circuited.
        """
        return self._descents

    def _leaf_for(self, key: bytes) -> Tuple[_Node, List[_Node]]:
        path: List[_Node] = []
        node = self._root
        while not node.leaf:
            path.append(node)
            self._descents += 1
            idx = bisect.bisect_right(node.keys, key)
            node = node.children[idx]
        self._descents += 1
        return node, path

    def insert(self, key: bytes, value: int) -> None:
        leaf, path = self._leaf_for(key)
        idx = bisect.bisect_left(leaf.keys, key)
        if idx < len(leaf.keys) and leaf.keys[idx] == key:
            leaf.values[idx].append(value)
            return
        leaf.keys.insert(idx, key)
        leaf.values.insert(idx, [value])
        if len(leaf.keys) > self.order:
            self._split(leaf, path)

    def _split(self, node: _Node, path: List[_Node]) -> None:
        mid = len(node.keys) // 2
        right = _Node(leaf=node.leaf)

        if node.leaf:
            right.keys = node.keys[mid:]
            right.values = node.values[mid:]
            node.keys = node.keys[:mid]
            node.values = node.values[:mid]
            right.nxt = node.nxt
            node.nxt = right
            promoted = right.keys[0]
        else:
            promoted = node.keys[mid]
            right.keys = node.keys[mid + 1:]
            right.children = node.children[mid + 1:]
            node.keys = node.keys[:mid]
            node.children = node.children[:mid + 1]

        if not path:
            root = _Node(leaf=False)
            root.keys = [promoted]
            root.children = [node, right]
            self._root = root
            self._height += 1
            return

        parent = path[-1]
        idx = bisect.bisect_right(parent.keys, promoted)
        parent.keys.insert(idx, promoted)
        parent.children.insert(idx + 1, right)
        if len(parent.keys) > self.order:
            self._split(parent, path[:-1])

    def lookup(self, key: bytes) -> List[int]:
        leaf, _ = self._leaf_for(key)
        idx = bisect.bisect_left(leaf.keys, key)
        if idx < len(leaf.keys) and leaf.keys[idx] == key:
            return leaf.values[idx]
        return []


# ---------------------------------------------------------------------------
# The hybrid index
# ---------------------------------------------------------------------------
@dataclass
class HybridIndex:
    """``I_hybrid`` — every Phase 3 structure, over one fog node's records."""

    order: int = DEFAULT_ORDER
    ngram_size: int = 3

    keywords: BPlusTree = field(init=False)
    epochs: Dict[str, Set[int]] = field(default_factory=dict)
    categorical: Dict[int, Set[int]] = field(default_factory=dict)
    ngrams: Dict[str, Set[int]] = field(default_factory=dict)
    record_count: int = 0
    postings: int = 0

    def __post_init__(self) -> None:
        self.keywords = BPlusTree(self.order)

    # -- construction (Phase 3, untimed setup) ------------------------------
    def add(self, rid: int, tokens: Sequence[bytes], *, epoch: str,
            category: int, ngram_terms: Iterable[str] = ()) -> None:
        for tok in tokens:
            self.keywords.insert(tok, rid)
            self.postings += 1
        self.epochs.setdefault(epoch, set()).add(rid)
        self.categorical.setdefault(category, set()).add(rid)
        for term in ngram_terms:
            for gram in ngrams(term, self.ngram_size):
                self.ngrams.setdefault(gram, set()).add(rid)
        self.record_count += 1

    # -- search (Phase 4, the measured path) --------------------------------
    def search(self, tokens: Sequence[bytes], *, epoch: Optional[str] = None,
               category: Optional[int] = None) -> Set[int]:
        """Intersect candidate sets across the structures the query touches.

        Smallest posting list first: intersection cost is bounded by the
        smallest set, and ordering by size is what makes a conjunctive query
        sublinear in the index. Ref[54]'s Algorithm 2 intersects without
        specifying an order; choosing the efficient one does not change what is
        computed, only how long it takes, and the paper's own Table II cost
        model assumes the efficient one.
        """
        if not tokens:
            return set()
        lists = sorted((self.keywords.lookup(t) for t in tokens), key=len)
        if not lists[0]:
            return set()
        candidates = set(lists[0])
        for postings in lists[1:]:
            candidates &= set(postings)
            if not candidates:
                return set()
        if epoch is not None:
            candidates &= self.epochs.get(epoch, set())
        if category is not None:
            candidates &= self.categorical.get(category, set())
        return candidates

    def fuzzy(self, term: str, threshold: float) -> Set[int]:
        """n-gram overlap scoring against ``theta`` — Phase 4's fuzzy branch."""
        grams = ngrams(term, self.ngram_size)
        if not grams:
            return set()
        hits: Dict[int, int] = {}
        for gram in grams:
            for rid in self.ngrams.get(gram, ()):  # noqa: PLC0206
                hits[rid] = hits.get(rid, 0) + 1
        need = threshold * len(grams)
        return {rid for rid, count in hits.items() if count >= need}

    @property
    def size_bytes(self) -> int:
        """Index storage, for the record. Tokens are 32 B, rids 8 B."""
        total = self.postings * (32 + 8)
        total += sum(len(v) * 8 for v in self.epochs.values())
        total += sum(len(v) * 8 for v in self.categorical.values())
        total += sum(len(k) + len(v) * 8 for k, v in self.ngrams.items())
        return total


def ngrams(term: str, size: int) -> List[str]:
    """Character n-grams, padded so short terms still produce one gram."""
    if not term:
        return []
    if len(term) <= size:
        return [term]
    return [term[i:i + size] for i in range(len(term) - size + 1)]
