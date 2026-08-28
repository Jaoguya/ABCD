"""Corpus -> Peony workload adaptation, shared by all five runners.

Two jobs, both of which the Zhuang baseline got wrong and which are worth
keeping in one reviewed place rather than copy-pasted five times:

1. **Actually read the corpus.** Every runner here builds its index from
   ``Dataset.corpus.Record`` objects and draws its query keywords from the real
   vocabulary. No synthetic ``f"keyword_{i}"`` strings, and no experiment that
   accepts ``--dataset`` and then ignores it.

2. **Batch the updates.** Ref[55] is a *batched* dynamic scheme: the index is
   ``I = union of I_c`` over ``c`` update batches (§V-D), and search cost is
   ``O(c)`` because the server repeats its derivation per batch. Splitting the
   corpus into ``params.update_batches_c`` batches is therefore part of running
   the construction faithfully, not a benchmark convenience.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

from Common.crypto.rng import DeterministicRNG
from Dataset.corpus import Record

from .levels import assign_level
from .params import SchemeParams


@dataclass
class Workload:
    """A corpus slice prepared for indexing."""

    # batch_id -> {keyword: [(file_id, level), ...]}
    batches: Dict[int, Dict[str, List[Tuple[int, int]]]]
    level_of: Dict[int, int]
    keyword_freq: Counter
    record_count: int
    pair_count: int

    @property
    def batch_count(self) -> int:
        return len(self.batches)


def build_workload(
    records: Sequence[Record],
    params: SchemeParams,
    *,
    batch_count: int | None = None,
) -> Workload:
    """Split ``records`` into ``c`` update batches keyed by keyword.

    Access levels come from ``levels.assign_level`` on the record's ``pid`` —
    the benchmark decision documented in ``levels.py`` and declared in
    crypto.yaml as ``yue_ge.level_assignment``.
    """
    c = batch_count or params.update_batches_c
    batches: Dict[int, Dict[str, List[Tuple[int, int]]]] = {
        i: defaultdict(list) for i in range(1, c + 1)
    }
    level_of: Dict[int, int] = {}
    freq: Counter = Counter()
    pairs = 0

    # STRATIFIED BATCHING — round-robin WITHIN each access level.
    #
    # How records map to update batches is a benchmark decision: Ref[55] says
    # only "we implement batch updating; thus c is relatively small" (§V-D) and
    # never specifies the assignment. Two properties are wanted, and plain
    # positional round-robin gives only the first:
    #
    #   1. Batches are of comparable size (so search cost per batch is even).
    #   2. Every batch contains files at EVERY access level.
    #
    # Property 2 matters because of the limitation documented in
    # peony.list_gen's "ON X_w" note: a batch holding no file at level l stores
    # bottom for level l, and level-l users then see nothing from it — including
    # files below them they are entitled to. That is the published behaviour and
    # is not repaired, but it is a degenerate regime the paper's own scale (2.2M
    # files over 3 levels) never enters. Stratifying keeps the benchmark in the
    # same regime instead of manufacturing recall loss that Ref[55] would not
    # exhibit on the corpus it was evaluated against.
    #
    # This changes only which batch a record lands in — never what is indexed,
    # searched, or returned.
    by_level: Dict[int, List] = defaultdict(list)
    for rec in records:
        by_level[assign_level(rec.pid, params.access_levels)].append(rec)

    for level, group in by_level.items():
        for pos, rec in enumerate(group):
            level_of[rec.rid] = level
            batch_id = (pos % c) + 1
            for kw in rec.kw:
                batches[batch_id][kw].append((rec.rid, level))
                freq[kw] += 1
                pairs += 1

    return Workload(
        batches={k: dict(v) for k, v in batches.items()},
        level_of=level_of,
        keyword_freq=freq,
        record_count=len(records),
        pair_count=pairs,
    )


def select_keywords(
    freq: Counter,
    rng: DeterministicRNG,
    count: int,
    *,
    min_frequency: int = 5,
    max_share: float = 0.5,
    total_records: int | None = None,
) -> List[str]:
    """Pick ``count`` query keywords from the real vocabulary.

    Mirrors ``guo_vdsse/src/exp2_search.py``'s selection so the two verifiable
    baselines are queried at comparable selectivity: skip keywords that are too
    rare to produce a measurable traversal, and skip ones so common they swamp
    the scan and hide the scaling behaviour.
    """
    ceiling = (
        total_records * max_share if total_records else float("inf")
    )
    eligible = [
        kw for kw, n in freq.items() if n >= min_frequency and n <= ceiling
    ]
    if len(eligible) < count:
        eligible = sorted(freq.keys())
    if not eligible:
        return []
    eligible.sort()
    take = min(count, len(eligible))
    return list(rng.choice(eligible, size=take, replace=False))


#: Fraction of a keyword's postings that may be deleted when seeding a
#: steady-state revocation filter. See ``seed_deletions``.
MAX_DELETION_SHARE = 0.10


def seed_deletions(
    state, workload: Workload, keywords: Sequence[str], params: SchemeParams
) -> int:
    """Delete a realistic share of each keyword's postings before measuring.

    Searching against an empty revocation filter would understate both the token
    size (``MSRE.KLRev`` punctures at nothing) and the search cost (no
    ``MSRE.Dec`` misses), so the benchmark puts the scheme in steady state first.

    HOW MANY TO DELETE — the corpus cannot reproduce the paper's ratio
    -----------------------------------------------------------------
    Ref[55] §VII-B sets up its deletion experiments by inserting **1,000,000
    files for one keyword** and then deleting ``d`` of them, with
    ``d`` in {10, 100, 1000, 10000}. At the configured ``d = 1000`` that is a
    deletion share of 0.1%.

    Our corpus is nowhere near that shape: it holds ~18k records over a 2,102
    word vocabulary (README §4), so a keyword has hundreds of postings, not a
    million. Deleting a literal ``d = 1000`` would delete every posting of most
    keywords, leaving an empty result set — which is what makes ``prune_ratio``
    collapse to zero and turns Exp. 2 into a measurement of misses.

    So the count is capped at ``MAX_DELETION_SHARE`` of the keyword's postings.
    The **Bloom filter is still sized at the published ``d``** via
    ``params.bloom_array_bits()`` — the array dimension is what drives the
    paper's published storage (Table V) and communication (§VII-B) figures, and
    it is left exactly as published. Only the number of bits actually set is
    scaled down, because the corpus cannot supply more.

    Returns the number of postings deleted, so runners can report it.
    """
    from . import peony_plus

    d = params.deletions_between_searches
    deleted = 0
    for kw in keywords:
        postings: List[Tuple[int, int]] = []
        for batch in workload.batches.values():
            postings.extend(batch.get(kw, ()))
        if not postings:
            continue
        take = min(d, max(1, int(len(postings) * MAX_DELETION_SHARE)))
        peony_plus.delete(state, kw, postings[:take])
        deleted += take
    return deleted


def index_workload(state, index, prooflist, workload: Workload, variant: str):
    """Build the encrypted index for a whole workload. NOT timed.

    Index construction is offline for Exp. 2 (README §5), so every runner calls
    this outside its measurement loop.
    """
    from . import peony, peony_plus

    for batch_id in sorted(workload.batches):
        per_keyword = workload.batches[batch_id]
        if not per_keyword:
            continue
        if variant == "peony":
            peony.update(state.params, state.key, index, batch_id, per_keyword)
        else:
            peony_plus.add(state, index, prooflist, batch_id, per_keyword)
    return index
