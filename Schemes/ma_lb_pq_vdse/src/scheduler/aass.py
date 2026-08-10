"""Phase VI Step 3 — Adaptive Authorization-Aware Search Scheduling.

Manuscript `Overleaf/PQ-AVDSE-OJCOMS:868`:

    SC_j = L1*C_j^auth + L2*C_j^index + L3*C_j^verify + L4*C_j^sync + L5*C_j^queue

    C_j^auth   = |P_Q|                  authorization policies in the query
    C_j^index  = |Cand_Q^(j)|           estimated candidate set size
    C_j^verify = |R_Q^(j)| * log N_j    predicted matches x log entry count
    C_j^sync   = |VID_U - VID_j|        version-synchronisation cost
    C_j^queue  = T_j^queue              queue waiting time

    FSN* = arg min_j SC_j                                      (Alg. 1)

"Unlike conventional load balancing algorithms that rely solely on processor
utilization or memory consumption, AASS **predicts** the expected cryptographic
workload **before** executing encrypted search."

That word *predicts* sets the cost ceiling: every term is estimated from
statistics the node already keeps, never by evaluating the query. A scheduler
that searched in order to decide where to search would cost as much as the search
it was scheduling, and Exp. 7's throughput would measure the scheduler.
:func:`estimate_costs` therefore does O(q) dict lookups and one bitmap popcount.

**Normalization is ours, and it is load-bearing** (``scheduler.yaml →
normalization``). The five published estimators have incommensurable units and
magnitudes: at the §6 defaults ``|P_Q|`` is O(1), ``|Cand_Q^(j)|`` is O(10^4),
``|R|*log N`` is O(10^3), ``|VID_U - VID_j|`` is O(1), and ``T_j^queue`` is a time
in nanoseconds. Applying raw weights would let ``C_index`` dominate by orders of
magnitude regardless of the lambdas, making the weight vector — and with it the
AASS claim — vacuous. Each term is mapped to [0,1] by dividing by the maximum
across the candidate nodes, which is scale-free and needs no calibration
constants.

A term equal across all nodes is mapped to **0**, not 1: it cannot affect
``arg min``, so giving it a value would silently consume weight that belongs to
the terms that do differ.

**The weights are not yet fixed.** ``scheduler.yaml`` carries
``weights.status: pending_sweep`` with a provisional uniform vector (README §14
issue #5). :class:`Scheduler` constructed with ``reportable=True`` calls
``config.scheduler.require_fixed()`` and therefore **raises** until the
documented hold-out sweep has run. That is the gate, live rather than
documented.
"""

from __future__ import annotations

import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from .. import config as scheme_config  # noqa: E402
from ..fsn.fsn import FogSearchNode  # noqa: E402

#: The four ablation variants of README §5 / SCHEME.md.
VARIANT_NO_LB = "no_lb"
VARIANT_ROUND_ROBIN = "round_robin"
VARIANT_LEAST_LOADED = "least_loaded"
VARIANT_AASS = "aass"

VARIANTS: Tuple[str, ...] = (
    VARIANT_NO_LB,
    VARIANT_ROUND_ROBIN,
    VARIANT_LEAST_LOADED,
    VARIANT_AASS,
)

#: Variants that read authorization state. Only ``aass`` does — which is why the
#: VID_j aggregation and the normalization rule affect that variant alone.
AUTHORIZATION_AWARE: Tuple[str, ...] = (VARIANT_AASS,)


class SchedulerError(RuntimeError):
    """Raised when a search request cannot be scheduled."""


@dataclass(frozen=True)
class SearchRequest:
    """What the scheduler needs to know about a query, before running it.

    ``authorized`` is the ``(domain, policy)`` set the AIM resolved in Phase VI
    Step 2 — scheduling happens after authorization, never before, so an
    unauthorized request is rejected without any node being costed.
    """

    tokens: Tuple[bytes, ...]
    authorized: Tuple[Tuple[str, str], ...]
    vid_u: int

    def __post_init__(self) -> None:
        if not self.tokens:
            raise SchedulerError("a search request must carry at least one token")
        if not self.authorized:
            raise SchedulerError(
                "a search request must carry at least one authorized "
                "(domain, policy) pair; Phase VI Step 2 rejects an unauthorized "
                "request without traversing the index"
            )
        if self.vid_u < 0:
            raise ValueError(f"VID_U must be non-negative, got {self.vid_u}")

    @property
    def policy_count(self) -> int:
        """``|P_Q|`` — the authorization policies involved in the query."""
        return len({policy for _, policy in self.authorized})

    @property
    def domains(self) -> Tuple[str, ...]:
        return tuple(sorted({domain for domain, _ in self.authorized}))


@dataclass(frozen=True)
class CostVector:
    """The five published terms for one node, before weighting."""

    auth: float
    index: float
    verify: float
    sync: float
    queue: float

    def as_tuple(self) -> Tuple[float, float, float, float, float]:
        return (self.auth, self.index, self.verify, self.sync, self.queue)

    def score(self, weights: scheme_config.SchedulerWeights) -> float:
        """``SC_j`` for this (normalized) vector."""
        w = weights.as_tuple()
        return sum(term * weight for term, weight in zip(self.as_tuple(), w))


@dataclass(frozen=True)
class NodeCost:
    """One node's raw and normalized costs, and its resulting score."""

    node_id: str
    raw: CostVector
    normalized: CostVector
    score: float


@dataclass(frozen=True)
class Selection:
    """The scheduler's decision, with the evidence behind it.

    ``costs`` is retained so Exp. 7-8 can report *why* a node was chosen, not
    only which. A scheduler that cannot show its reasoning cannot be audited
    against the claim that it "predicts the expected cryptographic workload".
    """

    node: FogSearchNode
    variant: str
    costs: Tuple[NodeCost, ...]

    @property
    def node_id(self) -> str:
        return self.node.node_id

    def cost_for(self, node_id: str) -> NodeCost:
        for cost in self.costs:
            if cost.node_id == node_id:
                return cost
        raise KeyError(node_id)


def estimate_result_count(node: FogSearchNode, request: SearchRequest) -> int:
    """``|R_Q^(j)|`` — predicted matching ciphertexts, from statistics only.

    For a conjunctive query the match count cannot exceed the shortest posting
    list, so that length is the estimator: it is an upper bound, it costs one dict
    lookup per token, and it never evaluates the query.

    Using the true count would mean running the search to decide where to run it.
    """
    lengths = [
        len(node.index._postings.get(token, ())) for token in request.tokens
    ]
    return min(lengths) if lengths else 0


def estimate_candidate_count(node: FogSearchNode, request: SearchRequest) -> int:
    """``|Cand_Q^(j)|`` — authorized candidates, from the shard's bitmaps.

    Exact rather than estimated, because the bitmap union already answers it in
    one popcount over the shard — cheaper than any approximation would be.
    """
    return node.index.authorized_bitmap(request.authorized).count(1)


def estimate_costs(node: FogSearchNode, request: SearchRequest) -> CostVector:
    """The five raw terms of Phase VI Step 3 for one node."""
    entries = node.entry_count
    # log N_j: the base is a constant factor that normalization and lambda_3
    # absorb, so log2 is chosen for being the natural unit of a binary tree
    # (which is what the verification cost actually walks).
    log_entries = math.log2(entries) if entries > 1 else 0.0
    return CostVector(
        auth=float(request.policy_count),
        index=float(estimate_candidate_count(node, request)),
        verify=float(estimate_result_count(node, request)) * log_entries,
        sync=float(abs(request.vid_u - node.vid())),
        queue=float(node.queue_wait_ns()),
    )


def normalize(
    vectors: Sequence[CostVector],
    *,
    degenerate_value: float = 0.0,
    epsilon: float = 1e-9,
) -> Tuple[CostVector, ...]:
    """Map each term to [0,1] by its maximum across the candidate nodes.

    A term that is identical on every node is mapped to ``degenerate_value``
    (0.0): it cannot change ``arg min``, so scoring it would consume weight
    without informing the decision.
    """
    if not vectors:
        return ()
    columns = list(zip(*(vector.as_tuple() for vector in vectors)))
    scales: List[Optional[float]] = []
    for column in columns:
        high, low = max(column), min(column)
        # Degenerate when every node agrees — including when all are zero.
        scales.append(None if abs(high - low) <= epsilon else high)
    normalized: List[CostVector] = []
    for vector in vectors:
        terms = []
        for value, scale in zip(vector.as_tuple(), scales):
            if scale is None:
                terms.append(degenerate_value)
            else:
                # No epsilon in the divisor. Every cost term is non-negative, so a
                # non-degenerate column has high > low >= 0 and therefore
                # high > 0: the guard is unnecessary, and adding it would put the
                # maximum at 0.999... instead of exactly 1.0. `epsilon` has one
                # job here — deciding degeneracy — not two.
                terms.append(value / scale)
        normalized.append(CostVector(*terms))
    return tuple(normalized)


class Scheduler:
    """The Phase VI Step 3 scheduler, in one of the four ablation variants.

    ``no_lb``, ``round_robin`` and ``least_loaded`` are authorization-oblivious
    and never read ``C_j^sync`` — which is why the ``VID_j`` aggregation and the
    normalization rule affect only ``aass``, and why Exp. 7-8 is an ablation of
    the scheduling rule rather than of the whole scheme.
    """

    def __init__(
        self,
        variant: str = VARIANT_AASS,
        *,
        config: Optional[scheme_config.Configuration] = None,
        reportable: bool = False,
    ) -> None:
        if variant not in VARIANTS:
            raise SchedulerError(
                f"unknown variant {variant!r}; expected one of {list(VARIANTS)}"
            )
        self.variant = variant
        self.config = config or scheme_config.load()
        self.reportable = reportable
        self._cursor = 0

        if variant == VARIANT_AASS and reportable:
            # Live gate: raises while scheduler.yaml says pending_sweep, so
            # Exp. 7-8 cannot report the provisional uniform vector as AASS.
            self._weights = self.config.scheduler.require_fixed(
                context="Phase VI AASS scheduling (Exp. 7-8)"
            )
        else:
            self._weights = self.config.scheduler.weights

    @property
    def weights(self) -> scheme_config.SchedulerWeights:
        return self._weights

    @property
    def is_authorization_aware(self) -> bool:
        return self.variant in AUTHORIZATION_AWARE

    def _candidates(
        self, nodes: Sequence[FogSearchNode], request: SearchRequest
    ) -> Tuple[FogSearchNode, ...]:
        """Nodes that serve at least one domain the request is authorized for.

        Phase VI Step 4: "The selected Fog Search Node performs encrypted search
        only over the authorized searchable-index shards." Costing a node that
        holds none of them would let the scheduler pick a node guaranteed to
        return nothing.
        """
        wanted = set(request.domains)
        candidates = tuple(
            node for node in nodes if wanted & set(node.domains)
        )
        if not candidates:
            raise SchedulerError(
                f"no Fog Search Node serves any of the authorized domains "
                f"{sorted(wanted)}"
            )
        return candidates

    def select(
        self, nodes: Sequence[FogSearchNode], request: SearchRequest
    ) -> Selection:
        """``FSN* = arg min_j SC_j``, or the variant's own rule."""
        if not nodes:
            raise SchedulerError("no Fog Search Nodes to schedule across")
        candidates = self._candidates(nodes, request)

        raw = tuple(estimate_costs(node, request) for node in candidates)
        normalized = normalize(
            raw,
            degenerate_value=self.config.scheduler.degenerate_term_value,
            epsilon=self.config.scheduler.epsilon,
        )
        costs = tuple(
            NodeCost(
                node_id=node.node_id,
                raw=raw_vector,
                normalized=norm_vector,
                score=norm_vector.score(self._weights),
            )
            for node, raw_vector, norm_vector in zip(candidates, raw, normalized)
        )

        if self.variant == VARIANT_NO_LB:
            chosen = candidates[0]
        elif self.variant == VARIANT_ROUND_ROBIN:
            chosen = candidates[self._cursor % len(candidates)]
            self._cursor += 1
        elif self.variant == VARIANT_LEAST_LOADED:
            chosen = min(
                candidates, key=lambda node: (node.queue_length, node.node_id)
            )
        else:
            # arg min SC_j, node_id breaking ties so the choice is deterministic
            # and a rerun of one trace reproduces it.
            chosen = min(
                zip(candidates, costs),
                key=lambda pair: (pair[1].score, pair[1].node_id),
            )[0]

        return Selection(node=chosen, variant=self.variant, costs=costs)

    def __repr__(self) -> str:
        return (
            f"Scheduler(variant={self.variant!r}, "
            f"weights={self._weights.status!r}, reportable={self.reportable})"
        )


def score_nodes(
    nodes: Sequence[FogSearchNode],
    request: SearchRequest,
    weights: scheme_config.SchedulerWeights,
    *,
    degenerate_value: float = 0.0,
    epsilon: float = 1e-9,
) -> Tuple[NodeCost, ...]:
    """Cost every node without selecting — for inspecting the scoring directly."""
    raw = tuple(estimate_costs(node, request) for node in nodes)
    normalized = normalize(raw, degenerate_value=degenerate_value, epsilon=epsilon)
    return tuple(
        NodeCost(
            node_id=node.node_id,
            raw=raw_vector,
            normalized=norm_vector,
            score=norm_vector.score(weights),
        )
        for node, raw_vector, norm_vector in zip(nodes, raw, normalized)
    )


__all__ = [
    "VARIANTS",
    "VARIANT_NO_LB",
    "VARIANT_ROUND_ROBIN",
    "VARIANT_LEAST_LOADED",
    "VARIANT_AASS",
    "AUTHORIZATION_AWARE",
    "SchedulerError",
    "SearchRequest",
    "CostVector",
    "NodeCost",
    "Selection",
    "Scheduler",
    "estimate_costs",
    "estimate_candidate_count",
    "estimate_result_count",
    "normalize",
    "score_nodes",
]
