"""Phase IV Step 3 — the Policy-State-Aware Dynamic Search Index.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex`:

    I_j = (T_j, CID_i, PID_i, VID_i)
    DSI = ∪ I_j

"Unlike conventional inverted indexes, each index entry remains **independently
updateable**, allowing insertions, deletions, and policy modifications **without
rebuilding the entire searchable index**."

That sentence is the Exp. 5 property, and it dictates the data structure. Three
consequences, each of which a test pins:

* **Entry ordinals are stable.** Deletion tombstones rather than compacts. Every
  bitmap is indexed by ordinal, so compaction would silently invalidate every
  bitmap in the shard — the failure mode that looks like a correct index returning
  wrong results.
* **A policy change rewrites payload only.** Under the recommended matching option
  (``PHASE_IV_PLAN.md`` §1.5 option D) the token does not encode the policy, so
  re-policying an entry touches no posting list. That is what keeps Exp. 5
  incremental instead of re-tokenizing.
* **Authorization filtering precedes matching.** §V: "authorization-aware
  bitmap filtering removes unauthorized ciphertexts **before** encrypted matching,
  so the online search cost depends mainly on the effective authorized candidate
  set ``n_eff``". ``n_eff`` is therefore measured here, not derived.

**The token function is injected.** Phase IV Step 2's matching relation is an open
author decision (``PHASE_IV_PLAN.md`` §1) and ``index/tokens.py`` does not exist
yet. This module never constructs a token: it takes them as opaque bytes, so the
whole structure is buildable and testable today and none of it changes when the
decision lands.

Query *execution* is Phase VI. What lives here is the structure and the
authorization filter it is searched through; :meth:`DynamicSearchIndex.lookup`
exists so the filter can be measured now, not to pre-empt Phase VI's scheduling.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from bitarray import bitarray

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import bloom  # noqa: E402

from ..types import IndexEntry  # noqa: E402

#: Ordinal capacity is grown in blocks so bitmaps are resized amortised rather
#: than on every insertion. A power of two keeps it aligned with the 64-bit words
#: ``index.yaml`` specifies.
_CAPACITY_BLOCK = 1024


class DSIError(RuntimeError):
    """Raised on an invalid index operation."""


@dataclass(frozen=True)
class SearchStatistics:
    """The Exp. 2 secondary metrics, measured rather than derived.

    ``n_eff`` is "the effective authorized candidate set" of §V — the
    entries that survive bitmap filtering AND match a query token.
    ``entries_traversed`` is what the search actually examined, and
    ``prune_ratio`` is the fraction of the shard the bitmap removed before
    matching. Reporting all three is what lets a reader see whether latency
    tracks ``n_eff`` or the raw index size, which is the PDSI claim.
    """

    n_eff: int
    entries_traversed: int
    authorized_candidates: int
    shard_entries: int
    bloom_rejections: int

    @property
    def prune_ratio(self) -> float:
        """Fraction of the shard removed by authorization filtering."""
        if self.shard_entries == 0:
            return 0.0
        return 1.0 - (self.authorized_candidates / self.shard_entries)


@dataclass
class DynamicSearchIndex:
    """One Fog Search Node's PDSI shard.

    Holds only entries whose domain this shard serves — ``index.yaml`` shards by
    domain, so authorization locality is a real property of the partition rather
    than something simulated at query time.
    """

    domains: FrozenSet[str]
    bloom_bits_per_entry: int = 10
    bloom_num_hashes: int = 7

    _entries: List[Optional[IndexEntry]] = field(default_factory=list, repr=False)
    _entry_domain: List[Optional[str]] = field(default_factory=list, repr=False)
    _postings: Dict[bytes, List[int]] = field(default_factory=dict, repr=False)
    # CID -> ordinals. Phase VII's ApplyIAS and Phase VIII's retrieval both
    # need a record's entries by CID; scanning would be O(N) per update, and
    # Exp. 5 sweeps k to 10^5.
    _by_cid: Dict[str, List[int]] = field(default_factory=dict, repr=False)
    _bitmaps: Dict[Tuple[str, str], bitarray] = field(default_factory=dict, repr=False)
    _capacity: int = field(default=0, repr=False)
    _live: int = field(default=0, repr=False)
    _deleted: int = field(default=0, repr=False)
    _bloom: Optional[bloom.BloomFilter] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.domains = frozenset(self.domains)
        if not self.domains:
            raise DSIError("a shard must serve at least one domain")

    # -- construction -------------------------------------------------------
    @classmethod
    def from_config(cls, domains: Iterable[str], config) -> "DynamicSearchIndex":
        """Build a shard sized from ``index.yaml`` rather than from literals."""
        return cls(
            domains=frozenset(domains),
            bloom_bits_per_entry=config.index.bloom_bits_per_entry,
            bloom_num_hashes=config.index.bloom_num_hashes,
        )

    # -- state --------------------------------------------------------------
    @property
    def entry_count(self) -> int:
        """``N_j`` — live entries, the figure Phase VI's ``C_j^verify`` uses."""
        return self._live

    @property
    def deleted_count(self) -> int:
        """Tombstones. Ordinals are never reused, so this only grows."""
        return self._deleted

    @property
    def token_count(self) -> int:
        return len(self._postings)

    @property
    def policy_pairs(self) -> Tuple[Tuple[str, str], ...]:
        """The ``(domain, policy)`` pairs this shard holds bitmaps for."""
        return tuple(sorted(self._bitmaps))

    def ordinals_for_cid(self, cid: str) -> Tuple[int, ...]:
        """Live ordinals holding entries of one record.

        Phase VII Step 2 rewrites a record's entries and Phase VII Step 4 applies
        a DIAS message scoped to one ``CID_i``; both need this in O(|W_i|) rather
        than O(N).
        """
        return tuple(sorted(self._by_cid.get(cid, ())))

    def records_held(self) -> int:
        """Distinct records with at least one live entry in this shard."""
        return len(self._by_cid)

    def entry(self, ordinal: int) -> IndexEntry:
        entry = self._entry_or_none(ordinal)
        if entry is None:
            raise DSIError(f"ordinal {ordinal} has been deleted")
        return entry

    def _entry_or_none(self, ordinal: int) -> Optional[IndexEntry]:
        if not 0 <= ordinal < len(self._entries):
            raise DSIError(
                f"ordinal {ordinal} out of range for {len(self._entries)} slots"
            )
        return self._entries[ordinal]

    # -- capacity and bitmaps -----------------------------------------------
    def _grow(self, needed: int) -> None:
        if needed <= self._capacity:
            return
        blocks = -(-needed // _CAPACITY_BLOCK)
        target = blocks * _CAPACITY_BLOCK
        for key, bits in self._bitmaps.items():
            extension = bitarray(target - len(bits))
            extension.setall(0)
            bits.extend(extension)
        self._capacity = target

    def _bitmap_for(self, domain: str, policy_id: str) -> bitarray:
        key = (domain, policy_id)
        if key not in self._bitmaps:
            bits = bitarray(self._capacity)
            bits.setall(0)
            self._bitmaps[key] = bits
        return self._bitmaps[key]

    # -- mutation (Phase IV Step 3 / Phase VII Step 2) -----------------------
    def insert(self, entry: IndexEntry, *, domain: str) -> int:
        """Add one index entry. Returns its ordinal, which is stable for life."""
        if domain not in self.domains:
            raise DSIError(
                f"this shard serves {sorted(self.domains)} and cannot hold an "
                f"entry for domain {domain!r}"
            )
        ordinal = len(self._entries)
        self._grow(ordinal + 1)
        self._entries.append(entry)
        self._entry_domain.append(domain)
        self._postings.setdefault(entry.token, []).append(ordinal)
        self._by_cid.setdefault(entry.cid, []).append(ordinal)
        self._bitmap_for(domain, entry.policy_id)[ordinal] = 1
        self._live += 1
        self._bloom = None  # membership set changed
        return ordinal

    def insert_record(
        self, entries: Sequence[IndexEntry], *, domain: str
    ) -> Tuple[int, ...]:
        """Insert one record's entries, returning their ordinals in order."""
        return tuple(self.insert(entry, domain=domain) for entry in entries)

    def delete(self, ordinal: int) -> None:
        """Tombstone an entry.

        The slot is never reused and later ordinals never shift. Compaction would
        be cheaper in memory and catastrophic in correctness: every bitmap indexes
        by ordinal, so shifting would silently re-point authorization bits at
        different entries.
        """
        entry = self.entry(ordinal)
        domain = self._entry_domain[ordinal]
        self._entries[ordinal] = None
        self._bitmaps[(domain, entry.policy_id)][ordinal] = 0
        postings = self._postings.get(entry.token, [])
        if ordinal in postings:
            postings.remove(ordinal)
        if not postings:
            self._postings.pop(entry.token, None)
        by_cid = self._by_cid.get(entry.cid, [])
        if ordinal in by_cid:
            by_cid.remove(ordinal)
        if not by_cid:
            self._by_cid.pop(entry.cid, None)
        self._live -= 1
        self._deleted += 1
        self._bloom = None

    def repolicy(self, ordinal: int, *, policy_id: str, vid: int) -> IndexEntry:
        """Change an entry's policy binding without touching its token.

        Phase IV Step 3's "policy modifications without rebuilding the entire
        searchable index", and Phase VII Step 2's per-entry update. The posting
        list is untouched — only the payload and the two affected bitmaps move —
        which is precisely why Exp. 5 measures an incremental update rather than a
        re-tokenization.
        """
        entry = self.entry(ordinal)
        domain = self._entry_domain[ordinal]
        updated = entry.with_policy(policy_id=policy_id, vid=vid)
        self._bitmaps[(domain, entry.policy_id)][ordinal] = 0
        self._bitmap_for(domain, policy_id)[ordinal] = 1
        self._entries[ordinal] = updated
        return updated

    # -- authorization filtering (§V :1892) ---------------------------------
    def authorized_bitmap(
        self, authorized: Iterable[Tuple[str, str]]
    ) -> bitarray:
        """Union of the bitmaps for the authorized ``(domain, policy)`` pairs.

        A union, not an intersection: a user authorized for several policies may
        read entries under any of them. (An intersection would return only entries
        somehow under every policy at once, which no entry is.)
        """
        result = bitarray(self._capacity)
        result.setall(0)
        for pair in authorized:
            bits = self._bitmaps.get(tuple(pair))  # type: ignore[arg-type]
            if bits is not None:
                result |= bits
        return result

    def candidates(self, authorized: Iterable[Tuple[str, str]]) -> Set[int]:
        """Ordinals surviving authorization filtering, before token matching."""
        return set(self.authorized_bitmap(authorized).search(1))

    def lookup(
        self,
        tokens: Sequence[bytes],
        authorized: Iterable[Tuple[str, str]],
        *,
        conjunctive: bool = True,
        use_bloom: bool = True,
    ) -> Tuple[Tuple[IndexEntry, ...], SearchStatistics]:
        """Match ``tokens`` against the authorized candidate set.

        Filter-then-match, in that order, because §V claims the online
        cost depends on ``n_eff`` rather than total index size — an
        implementation that matched first and filtered after would produce the
        same results and refute its own claim.

        ``conjunctive=True`` implements the q-keyword conjunctive query of §V; the
        corpus's ``min_keywords_per_record: 5`` exists so that such a query can
        match at all.
        """
        authorized_bits = self.authorized_bitmap(authorized)
        authorized_ordinals = set(authorized_bits.search(1))
        traversed = 0
        bloom_rejections = 0
        filter_ = self._bloom_filter() if use_bloom else None

        matched: Optional[Set[int]] = None
        for token in tokens:
            if filter_ is not None and token not in filter_:
                bloom_rejections += 1
                # A negative is definitive: the token is in no posting list, so a
                # conjunctive query cannot match anything.
                if conjunctive:
                    return (), SearchStatistics(
                        n_eff=0,
                        entries_traversed=traversed,
                        authorized_candidates=len(authorized_ordinals),
                        shard_entries=self._live,
                        bloom_rejections=bloom_rejections,
                    )
                continue
            postings = self._postings.get(token, [])
            traversed += len(postings)
            hits = {o for o in postings if o in authorized_ordinals}
            matched = hits if matched is None else (
                matched & hits if conjunctive else matched | hits
            )
            if conjunctive and not matched:
                break

        ordinals = sorted(matched or set())
        entries = tuple(
            self._entries[o] for o in ordinals if self._entries[o] is not None
        )
        return entries, SearchStatistics(
            n_eff=len(entries),
            entries_traversed=traversed,
            authorized_candidates=len(authorized_ordinals),
            shard_entries=self._live,
            bloom_rejections=bloom_rejections,
        )

    # -- Bloom pre-filter ---------------------------------------------------
    def _bloom_filter(self) -> Optional[bloom.BloomFilter]:
        """Lazily (re)built membership filter over the shard's tokens.

        Rebuilt on demand rather than maintained incrementally because deletion
        cannot clear a Bloom bit — a decrement would create false negatives, which
        unlike false positives would drop real results.
        """
        if self._bloom is None and self._postings:
            array_bits = max(
                64, self.bloom_bits_per_entry * max(1, len(self._postings))
            )
            filter_ = bloom.BloomFilter(
                array_bits=array_bits, num_hashes=self.bloom_num_hashes
            )
            filter_.add_all(self._postings)
            self._bloom = filter_
        return self._bloom

    def __repr__(self) -> str:
        return (
            f"DynamicSearchIndex(domains={sorted(self.domains)}, "
            f"N_j={self._live}, tokens={len(self._postings)}, "
            f"policies={len(self._bitmaps)}, tombstones={self._deleted})"
        )


def build_shards(
    domain_assignment: Sequence[Sequence[str]],
    *,
    bloom_bits_per_entry: int = 10,
    bloom_num_hashes: int = 7,
) -> Tuple[DynamicSearchIndex, ...]:
    """One PDSI shard per Fog Search Node.

    ``domain_assignment`` is what ``fsn.assign_domains_to_fsns()`` returns, so the
    shard set and the node set are partitioned by the same rule rather than by two
    rules that agree by luck.
    """
    return tuple(
        DynamicSearchIndex(
            domains=frozenset(domains),
            bloom_bits_per_entry=bloom_bits_per_entry,
            bloom_num_hashes=bloom_num_hashes,
        )
        for domains in domain_assignment
    )


__all__ = [
    "DSIError",
    "SearchStatistics",
    "DynamicSearchIndex",
    "build_shards",
]
