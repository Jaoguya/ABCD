"""Phase VI Step 4 — Distributed Encrypted Search on a Fog Search Node.

Manuscript `Overleaf/PQ-AVDSE-OJCOMS`, Phase VI Step 4:

    R = { (CID_i, PID_i, VID_i) | T_Q → I_i }

"The selected Fog Search Node performs encrypted search **only over the
authorized searchable-index shards**… Since only authorized index shards are
searched, unnecessary encrypted-search operations over unrelated domains are
avoided."

The matching relation ``T_Q → I_i`` is Option D's equality (``index/tokens.py``):
``T_j = T_Q = H(w)``, so a token presented by a query is the token stored in the
index, and one trapdoor serves every domain.

**Filter, then match — in that order.** §V `:1892`: "authorization-aware bitmap
filtering removes unauthorized ciphertexts **before** encrypted matching, so the
online search cost depends mainly on the effective authorized candidate set
``n_eff`` rather than the total encrypted index size". An implementation that
matched first and filtered after would return identical results and refute its
own claim, so ``n_eff`` is measured here rather than derived.

**What is timed.** README §5's Exp. 2 rule measures the full online path — AIM
check, AASS selection, shard search, response assembly. This module owns the
third of those and reports its own elapsed time, so the experiment harness can
attribute latency to a stage rather than to the whole path.

Phase VI Step 5 (Verifiable Search Response Generation) and Phase VIII
(verification) are not here: this returns the ``R`` triples the manuscript
defines, and proof generation is the next step's work.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ..index.dsi import SearchStatistics  # noqa: E402
from .fsn import FSNError, FogSearchNode  # noqa: E402


class SearchRejected(RuntimeError):
    """Raised when a request is refused before the index is traversed.

    Phase VI Step 2: an unauthorized request "is rejected without traversing the
    encrypted index". A rejection is therefore not an error in the protocol's
    terms — it is the intended outcome, and it must cost nothing.
    """


@dataclass(frozen=True)
class SearchHit:
    """One element of ``R`` — ``(CID_i, PID_i, VID_i)``.

    Deliberately not the index entry: Step 4 returns the record's identity and
    authorization metadata, never the token that found it. Returning the token
    would hand a caller the lookup key for a keyword it may not have queried.
    """

    cid: str
    policy_id: str
    vid: int


@dataclass(frozen=True)
class SearchResponse:
    """``R`` plus the measurements Exp. 2 reports."""

    node_id: str
    hits: Tuple[SearchHit, ...]
    statistics: SearchStatistics
    elapsed_ns: int

    @property
    def result_count(self) -> int:
        return len(self.hits)

    @property
    def n_eff(self) -> int:
        """The Exp. 2 secondary metric — measured, not derived."""
        return self.statistics.n_eff

    @property
    def elapsed_ms(self) -> float:
        """Shard-search latency in ms, the unit README §9 requires."""
        return self.elapsed_ns / 1e6

    @property
    def cids(self) -> Tuple[str, ...]:
        return tuple(hit.cid for hit in self.hits)


def _authorized_for_node(
    node: FogSearchNode, authorized: Sequence[Tuple[str, str]]
) -> Tuple[Tuple[str, str], ...]:
    """Restrict the authorization set to the domains this node actually holds.

    Step 4 searches "only over the authorized searchable-index shards". Passing a
    node authorization pairs for domains it does not serve would not return wrong
    results — its bitmaps hold nothing for them — but it would inflate the
    candidate count the scheduler and ``n_eff`` are computed from, which is a
    measurement bug rather than a correctness one.
    """
    served = set(node.domains)
    return tuple(pair for pair in authorized if pair[0] in served)


def execute_search(
    node: FogSearchNode,
    tokens: Sequence[bytes],
    authorized: Sequence[Tuple[str, str]],
    *,
    conjunctive: bool = True,
    use_bloom: bool = True,
    record_service: bool = True,
) -> SearchResponse:
    """Phase VI Step 4 on one node: filter by authorization, then match ``T_Q``.

    ``record_service`` accumulates the elapsed time on the node, which is what the
    Exp. 8 utilization sample reads. It is a parameter because a scheduler probing
    a node must not make it look busier for having been considered.
    """
    if not tokens:
        raise SearchRejected("a search must present at least one token")
    if not authorized:
        raise SearchRejected(
            "no authorized (domain, policy) pairs; Phase VI Step 2 rejects an "
            "unauthorized request without traversing the encrypted index"
        )

    scoped = _authorized_for_node(node, authorized)
    if not scoped:
        raise SearchRejected(
            f"{node.node_id} serves {sorted(node.domains)} and holds no shard "
            f"for the authorized domains "
            f"{sorted({domain for domain, _ in authorized})}"
        )

    started = time.perf_counter_ns()
    entries, statistics = node.index.lookup(
        tokens, scoped, conjunctive=conjunctive, use_bloom=use_bloom
    )
    elapsed = time.perf_counter_ns() - started

    if record_service:
        node.record_service(elapsed)

    return SearchResponse(
        node_id=node.node_id,
        hits=tuple(
            SearchHit(cid=entry.cid, policy_id=entry.policy_id, vid=entry.vid)
            for entry in entries
        ),
        statistics=statistics,
        elapsed_ns=elapsed,
    )


def execute_search_across(
    nodes: Sequence[FogSearchNode],
    tokens: Sequence[bytes],
    authorized: Sequence[Tuple[str, str]],
    *,
    conjunctive: bool = True,
) -> Tuple[SearchResponse, ...]:
    """Run one trapdoor against every node holding an authorized shard.

    This is the Exp. 3 path: ``d`` domains, **one** trapdoor. Nodes holding no
    authorized shard are skipped rather than searched, which is the "unnecessary
    encrypted-search operations over unrelated domains are avoided" claim.

    Each node is searched independently and no state crosses between them —
    README §1 makes them separate processes, and a shared intermediate here would
    not survive that split.
    """
    responses = []
    for node in nodes:
        if not _authorized_for_node(node, authorized):
            continue
        responses.append(
            execute_search(node, tokens, authorized, conjunctive=conjunctive)
        )
    if not responses:
        raise SearchRejected(
            f"no node holds a shard for the authorized domains "
            f"{sorted({domain for domain, _ in authorized})}"
        )
    return tuple(responses)


def merge_responses(responses: Sequence[SearchResponse]) -> Tuple[SearchHit, ...]:
    """Assemble the cross-node result set, deduplicated and ordered.

    Deduplicated by ``CID_i``: with ``d > m`` a record's domain and a query's
    domains can put one record within reach of a single node only, but a future
    replicated deployment could return it twice, and a duplicated hit would
    inflate the ``r`` that Exp. 4 sweeps.
    """
    seen = {}
    for response in responses:
        for hit in response.hits:
            seen.setdefault(hit.cid, hit)
    return tuple(sorted(seen.values(), key=lambda hit: hit.cid))


def aggregate_statistics(responses: Sequence[SearchResponse]) -> SearchStatistics:
    """Sum the per-node measurements into the figures Exp. 2 reports."""
    if not responses:
        raise ValueError("no responses to aggregate")
    return SearchStatistics(
        n_eff=sum(r.statistics.n_eff for r in responses),
        entries_traversed=sum(r.statistics.entries_traversed for r in responses),
        authorized_candidates=sum(
            r.statistics.authorized_candidates for r in responses
        ),
        shard_entries=sum(r.statistics.shard_entries for r in responses),
        bloom_rejections=sum(r.statistics.bloom_rejections for r in responses),
    )


__all__ = [
    "SearchRejected",
    "SearchHit",
    "SearchResponse",
    "execute_search",
    "execute_search_across",
    "merge_responses",
    "aggregate_statistics",
]
