"""Ref[41] experiments 1, 2 and 3 (SCHEME.md).

Ref[41] does not participate in Exp. 4-8.

TWO CONSTRUCTION READINGS ARE FORCED HERE, BOTH RECORDED IN run_meta.json
------------------------------------------------------------------------
1. ``q`` keywords. Ref[41]'s trapdoor carries exactly one ``O_3(w_w)``
   (eq. 15, Ref[41].md:328) and its search tests one keyword (eq. 18, :344).
   The construction has no conjunctive form. A q-keyword query is therefore
   run as q independent trapdoors and q independent searches with client-side
   intersection — the same native-mode rule SCHEME.md already applies to
   Exp. 3's domains, for the same reason. ``trapdoors_issued`` is reported as
   a secondary metric so the mechanism is visible rather than buried in the
   latency.

   Note this diverges from the paper's OWN asymptotic claim: Ref[41] Table III
   (:485) gives trapdoor generation as ``(u+e)L_h + (u+e)L_m + L_e``, linear
   in u+e, which no construction in the paper produces. Per README §13 the
   published CONSTRUCTION is implemented; the table is an unsupported claim
   and the divergence is reported, not engineered away.

2. Attribute count ``u``. Neither Ref[41] nor the manuscript's §V fixes one
   for the benchmark (Ref[41]'s own figures fix u=30 for its plots only).
   ``crypto.yaml`` carries it as a benchmark parameter so it is hashed into
   run_meta.json rather than hidden in this file.

FEASIBILITY
-----------
Ref[41] has no index structure. Search is a linear scan in which every
candidate costs ``2u+1`` pairings, and there is no filtering step of any
kind. At the Exp. 2 sweep top of N=10^6 with u=10 that is ~2.1x10^7 pairings
per single run, before the 30 repetitions. This is not a bug and not a slow
implementation — it is what the construction says. ``max_seconds_per_run``
bounds each point and records over-budget points as ``status=failed`` with
the reason, rather than letting a sweep run for days or, worse, tempting an
analytical shortcut that README §13 forbids.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple

from Common.crypto.pairing import PairingBackend

from . import scheme
from .harness import ExperimentResult, Measurement, Run, Timer, measure_point
from .lsss import and_gate_policy

SCHEME_NAME = "thingom_pq_abse"


@dataclass
class Workload:
    """Everything an experiment needs that is not timed."""

    params: scheme.PublicParameters
    key: scheme.AttributeSecretKey
    policy_attributes: List[Tuple[str, str]]
    keywords: List[str]
    rng: random.Random


def build_workload(
    backend: PairingBackend,
    *,
    attribute_count: int,
    keywords: Sequence[str],
    seed: int,
) -> Workload:
    """Setup + key generation. Not timed (README §5: Exp. 1 is online only)."""
    params, msk = scheme.setup(backend)

    # One attribute category per policy row. Categories and values are drawn
    # from the benchmark's own namespace; Ref[41] does not specify an
    # attribute vocabulary, only the {Cate : Value} shape (:208).
    policy_attributes = [
        (f"cat{index}", f"val{index}") for index in range(attribute_count)
    ]
    key = scheme.keygen(params, msk, policy_attributes, global_identity="DU/exp")

    return Workload(
        params=params,
        key=key,
        policy_attributes=policy_attributes,
        keywords=list(keywords),
        rng=random.Random(seed),
    )


def build_index(
    workload: Workload, keyword: str, size: int
) -> List[scheme.KeywordIndex]:
    """Construct ``size`` keyword indexes over one policy.

    Offline per README §5 ("Index construction is offline"), so it is outside
    every timer. It is still the dominant wall-clock cost of Exp. 2 at large
    N: each entry is 2u exponentiations plus a pairing.
    """
    structure = and_gate_policy(workload.policy_attributes)
    return [
        scheme.encrypt_online(workload.params, keyword, structure)
        for _ in range(size)
    ]


# ---------------------------------------------------------------------------
# Experiment 1 — Trapdoor Generation Latency (q = 1..20)
# ---------------------------------------------------------------------------
def experiment_1(
    workload: Workload,
    *,
    q_values: Sequence[int],
    repetitions: int,
    warmups: int,
) -> ExperimentResult:
    """Online trapdoor generation only.

    ML-KEM is excluded — Ref[41] does not use a KEM at all, and README §5's
    Exp. 1 rule excludes session establishment from the curve regardless.

    primary      latency of generating the q trapdoors, ms
    secondary_1  total trapdoor size across the q trapdoors, bytes
    secondary_2  trapdoors issued (= q, the native-mode cost)
    """
    result = ExperimentResult(
        scheme=SCHEME_NAME,
        experiment="exp1",
        columns={
            "variable": "q (queried keywords)",
            "primary": "trapdoor_generation_ms",
            "secondary_1": "trapdoor_size_bytes",
            "secondary_2": "trapdoors_issued",
        },
    )

    for q in q_values:
        def operation(q: int = q) -> Measurement:
            selected = [
                workload.rng.choice(workload.keywords) for _ in range(q)
            ]
            with Timer() as timer:
                tokens = [
                    scheme.trapdoor(workload.params, workload.key, keyword)
                    for keyword in selected
                ]
            size = sum(
                token.size_bytes(workload.params.backend) for token in tokens
            )
            return Measurement(
                primary=timer.elapsed_ms,
                secondary_1=float(size),
                secondary_2=float(q),
            )

        result.runs.extend(
            measure_point(
                operation,
                variable_value=q,
                repetitions=repetitions,
                warmups=warmups,
            )
        )
    return result


# ---------------------------------------------------------------------------
# Experiment 2 — Search Latency (N = 10^4 .. 10^6)
# ---------------------------------------------------------------------------
def experiment_2(
    workload: Workload,
    *,
    index_sizes: Sequence[int],
    q: int,
    repetitions: int,
    warmups: int,
    max_seconds_per_run: float,
) -> ExperimentResult:
    """Full online search path over an index of N entries.

    Ref[41] has no authorization filter and no early termination, so every
    entry is evaluated. ``entries_traversed`` equals N by construction, which
    is exactly the point of reporting it: README §5 asks for it as the
    secondary that explains the latency curve.

    primary      search latency, ms
    secondary_1  entries traversed
    secondary_2  pairings computed
    """
    result = ExperimentResult(
        scheme=SCHEME_NAME,
        experiment="exp2",
        columns={
            "variable": "N (index size)",
            "primary": "search_latency_ms",
            "secondary_1": "entries_traversed",
            "secondary_2": "pairings_computed",
        },
    )

    for size in index_sizes:
        keyword = workload.keywords[0]
        estimate = _estimated_seconds(workload, size, q)
        if estimate > max_seconds_per_run:
            result.runs.extend(
                _budget_exceeded_runs(size, repetitions, estimate, max_seconds_per_run)
            )
            continue

        index = build_index(workload, keyword, size)
        selected = [workload.keywords[0]] + [
            workload.rng.choice(workload.keywords) for _ in range(q - 1)
        ]

        def operation(index: List[scheme.KeywordIndex] = index) -> Measurement:
            tokens = [
                scheme.trapdoor(workload.params, workload.key, word)
                for word in selected
            ]
            pairings = 0
            with Timer() as timer:
                # Native mode: q independent scans, client-side intersection.
                matches: Optional[set] = None
                for token in tokens:
                    # One plan per trapdoor: the satisfied rows and the LSSS
                    # coefficients do not vary across candidates under a
                    # shared policy. Still inside the timer — it is real
                    # per-query server work.
                    plan = scheme.prepare_query(
                        workload.params, index[0].structure, token
                    )
                    hits = set()
                    for position, entry in enumerate(index):
                        outcome = scheme.search_with_plan(
                            workload.params, entry, token, plan
                        )
                        pairings += outcome.pairings
                        if outcome.matched:
                            hits.add(position)
                    matches = hits if matches is None else (matches & hits)
            return Measurement(
                primary=timer.elapsed_ms,
                secondary_1=float(size),
                secondary_2=float(pairings),
            )

        result.runs.extend(
            measure_point(
                operation,
                variable_value=size,
                repetitions=repetitions,
                warmups=warmups,
            )
        )
    return result


# ---------------------------------------------------------------------------
# Experiment 3 — Cross-Domain Search Scalability (d = 2..10)
# ---------------------------------------------------------------------------
def experiment_3(
    workload: Workload,
    *,
    domain_counts: Sequence[int],
    total_index_size: int,
    q: int,
    repetitions: int,
    warmups: int,
    max_seconds_per_run: float,
) -> ExperimentResult:
    """Native mode: d independent trapdoors, d independent searches.

    SCHEME.md: "Does not natively support cross-domain search. Run d
    independent trapdoors and d independent searches, with client-side result
    aggregation." Ref[41] has no notion of a domain, so each domain is an
    independent shard searched with its own freshly generated trapdoor.

    ``total_index_size`` is held constant across the whole ``domain_counts``
    sweep and divided evenly across domains (``shard_size = total /
    domains``), so total pairings per run — and therefore latency — stays
    flat in d; only the number of independent trapdoor/search round-trips
    changes. This is the whole point of the experiment (README §5: "count
    trapdoors issued so the mechanism is visible"). An earlier version passed
    a pre-multiplied, domain-count-independent shard size, which made total
    work scale linearly with d instead of staying flat — fixed 2026-08-27.

    primary      end-to-end cross-domain latency, ms
    secondary_1  trapdoors issued (d x q)
    secondary_2  cross-node messages (d)
    """
    result = ExperimentResult(
        scheme=SCHEME_NAME,
        experiment="exp3",
        columns={
            "variable": "d (domains)",
            "primary": "crossdomain_latency_ms",
            "secondary_1": "trapdoors_issued",
            "secondary_2": "cross_node_messages",
        },
    )

    keyword = workload.keywords[0]
    for domains in domain_counts:
        shard_size = max(1, total_index_size // domains)
        estimate = _estimated_seconds(workload, shard_size * domains, q)
        if estimate > max_seconds_per_run:
            result.runs.extend(
                _budget_exceeded_runs(
                    domains, repetitions, estimate, max_seconds_per_run
                )
            )
            continue

        shards = [build_index(workload, keyword, shard_size) for _ in range(domains)]

        def operation(shards: List[List[scheme.KeywordIndex]] = shards) -> Measurement:
            with Timer() as timer:
                # Client-side aggregation across domains: per-domain hit sets
                # are unioned by the client, because no server here knows
                # about any other domain.
                aggregated: set = set()
                for domain, shard in enumerate(shards):
                    # A fresh trapdoor per domain — the baseline cannot reuse
                    # one, which is the cost Exp. 3 exists to expose.
                    tokens = [
                        scheme.trapdoor(workload.params, workload.key, keyword)
                        for _ in range(q)
                    ]
                    for token in tokens:
                        plan = scheme.prepare_query(
                            workload.params, shard[0].structure, token
                        )
                        for position, entry in enumerate(shard):
                            outcome = scheme.search_with_plan(
                                workload.params, entry, token, plan
                            )
                            if outcome.matched:
                                aggregated.add((domain, position))
            return Measurement(
                primary=timer.elapsed_ms,
                secondary_1=float(domains * q),
                secondary_2=float(domains),
            )

        result.runs.extend(
            measure_point(
                operation,
                variable_value=domains,
                repetitions=repetitions,
                warmups=warmups,
            )
        )
    return result


# ---------------------------------------------------------------------------
# Feasibility guard
# ---------------------------------------------------------------------------
def _estimated_seconds(workload: Workload, entries: int, q: int) -> float:
    """Rough wall-clock estimate for one run, from a measured unit pairing.

    Used ONLY to decide whether to attempt a point. It never becomes a
    reported number — README §13 forbids deriving measurements analytically,
    and a point that is attempted is measured end to end.
    """
    backend = workload.params.backend
    element = workload.params.i
    with Timer() as timer:
        for _ in range(10):
            backend.pair(element, element)
    unit_ms = timer.elapsed_ms / 10

    pairings_per_entry = 2 * len(workload.policy_attributes) + 1
    return (entries * q * pairings_per_entry * unit_ms) / 1000.0


def _budget_exceeded_runs(
    variable_value: Any, repetitions: int, estimate: float, budget: float
) -> List[Run]:
    status = f"failed:budget_exceeded_est{estimate:.0f}s_budget{budget:.0f}s"
    return [
        Run(
            variable_value=variable_value,
            run_id=run_id,
            primary=float("nan"),
            status=status,
        )
        for run_id in range(1, repetitions + 1)
    ]
