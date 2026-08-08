"""Fog Search Nodes — Phase I Step 4.

Phase I Step 4 initializes the Fog Search Node set

    F = {FSN_1, FSN_2, ..., FSN_m}

"where each Fog Search Node maintains searchable-index shards and executes
encrypted search requests". This module builds the ``F`` that later phases fill:
per-node shard state, the request queue, and the synchronized authorization
version ``VID_j``.

Everything here exists because Phase VI Step 3 reads it. The AASS score

    SC_j = L1*C_j^auth + L2*C_j^index + L3*C_j^verify + L4*C_j^sync + L5*C_j^queue

estimates its terms from ``|Cand_Q^(j)|`` (local index statistics), ``N_j`` (the
node's entry count), ``|VID_U - VID_j|`` (version skew), and ``T_j^queue``. Those
counters are created here rather than retrofitted when Exp. 7-8 needs them,
because a counter added later tends to be a counter that measures something
slightly different from what the scheduler actually used.

**Shard contents are Phase IV's.** A shard tracks its domains and its entry
count; the layout of the index entries themselves is
``I_j = (T_j, CID_i, PID_i, VID_i)`` from Phase IV Step 3, and guessing that
structure now would mean building the PDSI before the phase that defines it.
``N_j`` is what Phase VI needs, and ``N_j`` is available.

**No shared state between nodes.** README §1 requires each FSN to be an
independent process. Phases I-II run them in one process, so nothing here may
hold a reference to another node, to the AIM, or to the ledger: the AIM pushes
state in (:meth:`FogSearchNode.apply_meta`), and a node never reaches out. That
is what makes the later process split a change of transport rather than a change
of behaviour.
"""

from __future__ import annotations

import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ..types import AuthorizationMeta  # noqa: E402


class FSNError(RuntimeError):
    """Raised on an invalid Fog Search Node operation."""


@dataclass
class QueuedRequest:
    """One pending search request.

    ``enqueued_ns`` is a monotonic timestamp, so ``T_j^queue`` is a measured
    waiting time rather than a queue-length proxy.
    """

    request_id: str
    enqueued_ns: int


@dataclass
class ShardState:
    """One FSN's searchable-index shard.

    ``domains`` is the set of administrative domains whose entries live on this
    node. ``index.yaml`` shards by domain, which is what makes authorization
    locality real: ``C_j^auth`` and the AIM's shard selection both key off it,
    rather than off a hash that has no relationship to who is authorized for what.
    """

    domains: FrozenSet[str]
    entry_count: int = 0

    def add_entries(self, count: int) -> int:
        """Record ``count`` new index entries. Returns the new ``N_j``."""
        if count < 0:
            raise ValueError(f"count must be non-negative, got {count}")
        self.entry_count += count
        return self.entry_count

    def remove_entries(self, count: int) -> int:
        if count < 0:
            raise ValueError(f"count must be non-negative, got {count}")
        if count > self.entry_count:
            raise FSNError(
                f"cannot remove {count} entries from a shard holding "
                f"{self.entry_count}"
            )
        self.entry_count -= count
        return self.entry_count

    def serves_domain(self, domain: str) -> bool:
        return domain in self.domains


@dataclass
class FogSearchNode:
    """``FSN_j`` — index shard, request queue, and synchronized ``VID_j``."""

    node_id: str
    shard: ShardState
    _queue: Deque[QueuedRequest] = field(default_factory=deque, repr=False)
    # Meta_i per authority, as delivered by the AIM in Phase II Step 4 and
    # updated by IAS in Phase VII Step 6.
    _synced: Dict[str, AuthorizationMeta] = field(default_factory=dict, repr=False)
    _service_ns: int = field(default=0, repr=False)
    _served: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id must not be empty")

    # -- construction -------------------------------------------------------
    @classmethod
    def create(cls, node_id: str, domains: Iterable[str]) -> "FogSearchNode":
        domains = frozenset(domains)
        if not domains:
            raise FSNError(
                f"{node_id}: a Fog Search Node must serve at least one domain; "
                f"an unassigned node would never be selected and would distort "
                f"the Exp. 8 utilization spread"
            )
        return cls(node_id=node_id, shard=ShardState(domains=domains))

    # -- authorization state (Phase II Step 4 / Phase VII Step 6) -----------
    def apply_meta(self, authority_id: str, meta: AuthorizationMeta) -> bool:
        """Apply ``Meta_i = (Dom_i, VID_i, C_i^auth)`` from the AIM.

        Returns whether this node's state changed. A node rejects a version older
        than the one it holds: authorization versions only advance
        (``VID' = VID + 1``, Phase VII Step 3), so an older message is a replay or
        a reordered delivery, and applying it would silently roll the node's
        authorization state backwards.
        """
        existing = self._synced.get(authority_id)
        if existing is not None:
            if meta.vid < existing.vid:
                raise FSNError(
                    f"{self.node_id}: refusing Meta for {authority_id!r} at VID "
                    f"{meta.vid}; already synchronized at VID {existing.vid}. "
                    f"Authorization versions only advance."
                )
            if meta == existing:
                return False
        self._synced[authority_id] = meta
        return True

    def synced_authorities(self) -> Tuple[str, ...]:
        return tuple(sorted(self._synced))

    def meta_for_authority(self, authority_id: str) -> AuthorizationMeta:
        try:
            return self._synced[authority_id]
        except KeyError:
            raise FSNError(
                f"{self.node_id} holds no authorization state for "
                f"{authority_id!r}"
            ) from None

    def vid_for_authority(self, authority_id: str) -> int:
        return self.meta_for_authority(authority_id).vid

    def vid_for_domains(self, domains: Iterable[str]) -> int:
        """The synchronized version across ``domains``, as the minimum.

        This is the accurate form of ``VID_j`` for a query: a node is only as
        fresh as the stalest authority among the domains the query touches, since
        it cannot serve a version it has not received.

        Raises if the node holds no state for a requested domain — that is not a
        version-zero node, it is a node that was never synchronized, and treating
        the two alike would let an unsynchronized node look perfectly fresh.
        """
        requested = list(domains)
        if not requested:
            raise ValueError("domains must not be empty")
        versions: List[int] = []
        for domain in requested:
            matches = [
                meta.vid for meta in self._synced.values() if meta.domain == domain
            ]
            if not matches:
                raise FSNError(
                    f"{self.node_id} holds no authorization state for domain "
                    f"{domain!r}"
                )
            versions.extend(matches)
        return min(versions)

    def vid(self) -> int:
        """``VID_j`` — the scalar of Phase VI Step 3's ``C_j^sync``.

        Phase VI writes ``C_j^sync = |VID_U - VID_j|`` with a single ``VID_j``,
        while Phase II Step 4 synchronizes one ``Meta_i`` per authority. The
        aggregation is therefore ours to choose, and it is the **minimum** across
        synchronized authorities: a node that has not applied the newest IAS for
        any one authority genuinely cannot serve that authority's current state,
        so the minimum is the version the node can actually honour across the
        board. Taking the maximum would let one freshly-synced authority mask
        staleness in every other.

        ``benchmark`` provenance, and it only affects the ``aass`` variant — the
        three authorization-oblivious variants never read ``C_j^sync``. Prefer
        :meth:`vid_for_domains`, which is strictly more accurate when the query's
        domains are known.

        Returns 0 for a node with no synchronized state, which is the honest
        floor: it holds nothing, so it is behind every published version.
        """
        if not self._synced:
            return 0
        return min(meta.vid for meta in self._synced.values())

    def commitment_for_authority(self, authority_id: str) -> bytes:
        return self.meta_for_authority(authority_id).commitment

    # -- request queue (Phase VI / Exp. 7-8) --------------------------------
    def enqueue(self, request_id: str, *, now_ns: Optional[int] = None) -> int:
        """Append a request. Returns the queue length after insertion."""
        self._queue.append(
            QueuedRequest(
                request_id=request_id,
                enqueued_ns=time.perf_counter_ns() if now_ns is None else now_ns,
            )
        )
        return len(self._queue)

    def dequeue(self) -> QueuedRequest:
        if not self._queue:
            raise FSNError(f"{self.node_id}: queue is empty")
        return self._queue.popleft()

    @property
    def queue_length(self) -> int:
        return len(self._queue)

    def queue_wait_ns(self, *, now_ns: Optional[int] = None) -> int:
        """``T_j^queue`` — how long the oldest pending request has waited.

        A measured wait rather than the queue length: two nodes with equal queues
        but different service rates do not have equal waiting times, and the
        published estimator is a time.
        """
        if not self._queue:
            return 0
        now = time.perf_counter_ns() if now_ns is None else now_ns
        return max(0, now - self._queue[0].enqueued_ns)

    def record_service(self, duration_ns: int) -> None:
        """Record time spent serving, for the Exp. 8 utilization sample."""
        if duration_ns < 0:
            raise ValueError("duration_ns must be non-negative")
        self._service_ns += duration_ns
        self._served += 1

    @property
    def service_ns(self) -> int:
        return self._service_ns

    @property
    def served_count(self) -> int:
        return self._served

    def utilization(self, window_ns: int) -> float:
        """Busy fraction over ``window_ns`` — sampled every 100 ms in Exp. 8."""
        if window_ns <= 0:
            raise ValueError("window_ns must be positive")
        return min(1.0, self._service_ns / window_ns)

    # -- Phase VI inputs ----------------------------------------------------
    @property
    def entry_count(self) -> int:
        """``N_j`` — index entries held, used by ``C_j^verify``."""
        return self.shard.entry_count

    @property
    def domains(self) -> FrozenSet[str]:
        return self.shard.domains

    def serves_domain(self, domain: str) -> bool:
        return self.shard.serves_domain(domain)

    def __repr__(self) -> str:
        return (
            f"FogSearchNode(id={self.node_id!r}, "
            f"domains={sorted(self.domains)}, N_j={self.entry_count}, "
            f"VID_j={self.vid()}, queue={self.queue_length})"
        )


def assign_domains_to_fsns(
    domains: Sequence[str], fsn_count: int
) -> Tuple[Tuple[str, ...], ...]:
    """Distribute ``domains`` across ``fsn_count`` nodes, largest-first.

    ``index.yaml`` sets ``overflow_policy: pack_largest_first``, matching the rule
    ``Dataset/prepare_dataset.py`` uses to balance domains. With ``d == m`` (the
    §V default of 4 and 4) this is one domain per node, which is what makes
    Phase VII's selective propagation observable: an update from one authority
    touches exactly one node. Exp. 3 sweeps ``d`` to 10 against ``m = 4``, where
    nodes take multiple domains.

    Domains are assumed equal-sized, which the frozen corpus makes true
    (285,268 records x 4 exactly), so round-robin over sorted domains IS
    largest-first for our data. The name follows the config; if domains ever
    become unequal, this needs their sizes.
    """
    if fsn_count < 1:
        raise ValueError("fsn_count must be >= 1")
    if not domains:
        raise ValueError("domains must not be empty")
    if len(set(domains)) != len(domains):
        raise ValueError("duplicate domain in the assignment")
    buckets: List[List[str]] = [[] for _ in range(fsn_count)]
    for index, domain in enumerate(sorted(domains)):
        buckets[index % fsn_count].append(domain)
    empty = [i for i, bucket in enumerate(buckets) if not bucket]
    if empty:
        raise FSNError(
            f"{len(domains)} domains cannot fill {fsn_count} Fog Search Nodes; "
            f"nodes {empty} would hold no shard and never be selected"
        )
    return tuple(tuple(bucket) for bucket in buckets)


def build_fsn_set(
    domains: Sequence[str], fsn_count: int, *, prefix: str = "FSN"
) -> Tuple[FogSearchNode, ...]:
    """Phase I Step 4: build ``F = {FSN_1, ..., FSN_m}``.

    Node identifiers are 1-based to match the manuscript's ``FSN_1..FSN_m``.
    """
    assignment = assign_domains_to_fsns(domains, fsn_count)
    return tuple(
        FogSearchNode.create(f"{prefix}{index}", node_domains)
        for index, node_domains in enumerate(assignment, start=1)
    )


__all__ = [
    "FSNError",
    "QueuedRequest",
    "ShardState",
    "FogSearchNode",
    "assign_domains_to_fsns",
    "build_fsn_set",
]
