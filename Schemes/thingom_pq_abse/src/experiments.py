"""Ref[41] experiments 1, 2 and 3 (41.md).

Ref[41] does not participate in Exp. 4-8.

TWO CONSTRUCTION READINGS ARE FORCED HERE, BOTH RECORDED IN run_meta.json
------------------------------------------------------------------------
1. ``q`` keywords. Ref[41]'s trapdoor carries exactly one ``O_3(w_w)``
   (eq. 15, Ref[41].md:328) and its search tests one keyword (eq. 18, :344).
   The construction has no conjunctive form. A q-keyword query is therefore
   run as q independent trapdoors and q independent searches with client-side
   intersection — the same native-mode rule 41.md already applies to
   Exp. 3's domains, for the same reason. ``trapdoors_issued`` is reported as
   a secondary metric so the mechanism is visible rather than buried in the
   latency.

   Note this diverges from the paper's OWN asymptotic claim: Ref[41] Table III
   (:485) gives trapdoor generation as ``(u+e)L_h + (u+e)L_m + L_e``, linear
   in u+e, which no construction in the paper produces. Per skill.md the
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
per single run, before the 10 repetitions. This is not a bug and not a slow
implementation — it is what the construction says. ``max_seconds_per_run``
bounds each point and records over-budget points as ``status=failed`` with
the reason, rather than letting a sweep run for days or, worse, tempting an
analytical shortcut that skill.md forbids.
"""

from __future__ import annotations

import os

import multiprocessing as mp
import random
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from Common.crypto.pairing import PairingBackend

from . import scheme
from .harness import (
    CpuTimer, ExperimentResult, Measurement, Run, Timer, mean_ci95, measure_point,
)
from .lsss import and_gate_policy

SCHEME_NAME = "thingom_pq_abse"


# ---------------------------------------------------------------------------
# Parallel search — hardware-utilization detail, NOT an algorithmic change.
# ---------------------------------------------------------------------------
# Computes the exact same per-entry search_with_plan() calls a single-
# threaded loop would (same pairing count, same match set) across
# _SEARCH_PROCESSES forked workers instead of one. Disclosed in 41.md's
# Feasibility section: this changes Thingom's implicit deployment model from
# "one thread serves one query" to "one query gets ~2 cores" on the pinned
# host, which the published construction does not itself describe — that is
# a genuine judgment call, not something to apply silently.
#
# charm's Element/Pairing objects are not picklable, so they cannot cross
# Pool.map() as arguments. Only Linux's default fork() start method lets a
# worker *inherit* them via copy-on-write, snapshotted at Pool() creation —
# these globals must be set immediately before each Pool is created; already-
# forked workers do not see later changes to them.
_MP_PARAMS: Any = None
_MP_INDEX: Any = None
_MP_TOKEN: Any = None
_MP_PLAN: Any = None

# Measured 2026-08-28 on the pinned m6i.xlarge host (2 physical cores + SMT):
# 2-process 1.94-1.95x real speedup (verified against a single-threaded
# reference, exact pairing counts and match sets identical) vs. 4-process
# 1.90x -- *worse* than 2-process, because this is compute-bound work and the
# extra hyperthreads add pool overhead without adding real compute capacity.
# Overridable so the published N = 10^6 point is reachable. Ref[41]'s search is
# embarrassingly parallel over candidate records: the SAME q*N*(2u+1) pairings
# are computed, just spread across workers. No batching, no early termination,
# no index -- the construction is untouched, which is the line that must not be
# crossed (see scheme.py::search_with_plan).
#
# 2 is right on the pinned m6i.xlarge: its "4 vCPU" is 2 physical cores plus
# hyperthreading, and 4 processes measured SLOWER on this compute-bound work.
# On a wider host, set THINGOM_SEARCH_PROCESSES to the physical core count.
# Measured cost at N = 10^6, 35 runs: 380.8h at 2 procs. The 23.8h-at-32 and
# 11.9h-at-64 figures once recorded here were NOT reachable: chunksize was a
# constant 8 chunks, so those pools ran 8 workers and idled the rest. Fixed
# below. Exp. 2 now runs at n=1 for this scheme, which is what makes the full
# 10^4-10^6 sweep affordable at all (~4.7h on 8 workers vs ~165h at n=35).
#
# §V MUST STATE the process count: reported latency is aggregate work divided
# across P workers, not a single-core figure.
_SEARCH_PROCESSES = int(os.environ.get("THINGOM_SEARCH_PROCESSES", "2"))

# Used only by the feasibility guard, never in a reported number. Held below
# the 1.94-1.95x actually measured so the guard errs toward attempting a point
# rather than refusing one it could have finished.
_PARALLEL_SPEEDUP_FOR_ESTIMATES = 1.7


def _mp_search_worker(position: int) -> Tuple[bool, int]:
    """Runs in a forked worker process. Only a plain (bool, int) crosses back
    over IPC — no charm object is ever pickled."""
    outcome = scheme.search_with_plan(_MP_PARAMS, _MP_INDEX[position], _MP_TOKEN, _MP_PLAN)
    return (outcome.matched, outcome.pairings)


def _parallel_search(
    params: scheme.PublicParameters,
    index: List["scheme.KeywordIndex"],
    token: "scheme.Trapdoor",
    plan: Any,
) -> Tuple[set, int]:
    """Search every entry in ``index`` for ``token`` across a forked process
    pool. Returns (matched_positions, total_pairings) -- identical in content
    to what a single-threaded loop over search_with_plan() would return."""
    global _MP_PARAMS, _MP_INDEX, _MP_TOKEN, _MP_PLAN
    _MP_PARAMS, _MP_INDEX, _MP_TOKEN, _MP_PLAN = params, index, token, plan
    # Explicit fork context, never the platform default. The workers rely
    # ENTIRELY on inheriting the globals above through fork's copy-on-write —
    # charm's Element/Pairing objects cannot be pickled, so they can never be
    # passed as map() arguments. Under spawn (macOS default) or forkserver
    # (the Linux default from Python 3.14) a worker re-imports this module,
    # sees _MP_INDEX is None, and every entry raises TypeError. macOS is a
    # supported development path (MacOS/SETUP.md), so the default must not be
    # trusted here.
    if "fork" not in mp.get_all_start_methods():
        raise RuntimeError(
            "parallel search requires the 'fork' start method, which this "
            "platform does not provide. Set _SEARCH_PROCESSES = 1 to run "
            "single-threaded instead."
        )
    ctx = mp.get_context("fork")
    with ctx.Pool(processes=_SEARCH_PROCESSES) as pool:
        # Chunk count must follow the POOL, not a constant. This was
        # `len(index) // 8`, which yields exactly 8 chunks at any N >= 8
        # regardless of _SEARCH_PROCESSES -- so a 32- or 64-process pool handed
        # work to 8 workers and left the rest idle, capping speedup at 8x however
        # wide the host. Measured by counting distinct worker PIDs: 32 procs ->
        # 8 used, 24 idle; 64 procs -> 8 used, 56 idle. The 23.8h-at-32 and
        # 11.9h-at-64 figures in the comment above are not reachable by that
        # code, and the real floor was 380.8h/8 ~= 47.6h.
        #
        # Four chunks per worker rather than one: the scan is uniform, but an
        # exact 1:1 split makes the whole map wait on whichever worker draws the
        # slowest core, and finer chunks cost nothing here because the payload
        # is one int.
        chunks = max(1, _SEARCH_PROCESSES * 4)
        results = pool.map(
            _mp_search_worker, range(len(index)),
            chunksize=max(1, len(index) // chunks),
        )
    hits: set = set()
    pairings = 0
    for position, (matched, entry_pairings) in enumerate(results):
        pairings += entry_pairings
        if matched:
            hits.add(position)
    return hits, pairings


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
    """Setup + key generation. Not timed (skill.md: Exp. 1 is online only)."""
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

    Offline per skill.md ("Index construction is offline"), so it is outside
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

    ML-KEM is excluded — Ref[41] does not use a KEM at all, and skill.md's
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
    on_point_complete: Optional[Callable[[int, "ExperimentResult"], None]] = None,
) -> ExperimentResult:
    """Full online search path over an index of N entries.

    Ref[41] has no authorization filter and no early termination, so every
    entry is evaluated. ``entries_traversed`` equals N by construction, which
    is exactly the point of reporting it: skill.md asks for it as the
    secondary that explains the latency curve.

    primary      search latency, ms
    secondary_1  entries traversed
    secondary_1  wall-clock ms at P workers (primary is aggregate CPU ms)
    secondary_2  pairings computed
    """
    result = ExperimentResult(
        scheme=SCHEME_NAME,
        experiment="exp2",
        columns={
            "variable": "N (index size)",
            # CPU time, not wall-clock: the scan is parallelised, so wall-clock
            # would divide aggregate work by the worker count and make the
            # published figure a function of the host's core count. The other
            # four schemes run Exp. 2 single-process, where wall-clock and CPU
            # time coincide, so this is what makes the column comparable across
            # schemes rather than what makes it different.
            "primary": "search_cpu_time_ms",
            # Replaces `entries_traversed`, which restated the variable column
            # (a full scan traverses exactly N). Wall-clock is the useful thing
            # to carry here: it keeps the parallel speedup visible instead of
            # hiding it inside the primary.
            "secondary_1": "wall_clock_ms",
            "secondary_2": "pairings_computed",
        },
    )

    # Fired after each sweep point so the caller can persist what is finished.
    # The 10^6 point is most of this experiment's wall-clock, so without it a
    # crash or a stop late in the sweep discards every completed point before
    # it as well. Between points only -- never inside a CpuTimer span -- so the
    # flush I/O cannot land in a measurement.
    def _point_done(size: int) -> None:
        if on_point_complete is None:
            return
        try:
            on_point_complete(size, result)
        except Exception as exc:  # noqa: BLE001 - a failed flush is never fatal
            print(
                f"  [warn] partial-result flush failed at N={size}: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

    for size in index_sizes:
        keyword = workload.keywords[0]
        estimate = _estimated_seconds(workload, size, q, parallel=True)
        if estimate > max_seconds_per_run:
            result.runs.extend(
                _budget_exceeded_runs(size, repetitions, estimate, max_seconds_per_run)
            )
            # Flushed like any other point: a budget-exceeded row is a recorded
            # outcome, not an absence, and a reader needs to see it.
            _point_done(size)
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
            # CPU time, not wall-clock. The scan is spread across a fork pool,
            # so a wall-clock span would report aggregate work divided by the
            # worker count -- i.e. a number that moves with the core count of
            # whatever host was rented, for a BASELINE scheme. See
            # harness.CpuTimer. Wall-clock is still captured and reported as a
            # secondary so the parallel speedup stays visible rather than hidden.
            with CpuTimer() as timer:
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
                    hits, token_pairings = _parallel_search(
                        workload.params, index, token, plan
                    )
                    pairings += token_pairings
                    matches = hits if matches is None else (matches & hits)
            return Measurement(
                primary=timer.elapsed_ms,          # aggregate CPU ms
                secondary_1=timer.wall_ms,         # wall-clock at P workers
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
        _point_done(size)
    return result


# ---------------------------------------------------------------------------
# Experiment 2 by PROJECTION from a measured unit cost
# ---------------------------------------------------------------------------
# Ref[41]'s published sweep to N = 10^6 is not runnable: no index, no early
# termination, q*N*(2u+1) real pairings per query. So the curve is DERIVED from
# a measured per-candidate cost rather than measured at each N. That is the
# user's instruction and the paper's own assumption; what follows is what makes
# it honest rather than merely cheap.
#
# WHY NOT SIMPLY MEASURE ONE RECORD AND MULTIPLY. A query at N=1 costs
#     cost(1) = fixed + per_candidate
# where `fixed` is q trapdoor generations plus one prepare_query per trapdoor --
# work done ONCE per query whatever N is. Multiplying cost(1) by N charges that
# setup N times: at 10^6, a million trapdoor generations for a scan that does q.
# It does not merely add noise, it inflates thingom systematically. thingom is a
# BASELINE, so inflating it inflates the proposed scheme's apparent advantage --
# the same defect class as the Exp. 2 estimand asymmetry, and the reason this is
# worth thirty extra seconds of measurement.
#
# THREE anchors, not two: two points FIT a line and cannot TEST one. Linearity
# is the load-bearing assumption of the entire projection, so it is measured and
# reported as a residual rather than asserted.
#
# P=1 AT THE ANCHORS, forced. At N=1..1000 there is nothing to parallelise, but
# the pool still forks, and CpuTimer sums RUSAGE_CHILDREN -- so fork and
# teardown land inside the measurement and are attributed to `fixed`, the exact
# term being isolated. It inflates the small anchors more than a large N, which
# tilts the slope too. The primary is aggregate CPU and P-invariant by design,
# so forcing P=1 here costs nothing in comparability.
# Anchors are REAL searches. The user's instruction (2026-09-03) is to search
# for real up to 10,000 records and project the rest, so the top anchor is the
# 10^4 sweep point itself: that point is MEASURED, not projected, and the four
# larger points are derived from the fitted slope.
_PROJECTION_ANCHORS = (1_000, 5_000, 10_000)


def experiment_2_projected(
    workload: Workload,
    *,
    index_sizes: Sequence[int],
    q: int,
    repetitions: int,
    warmups: int,
    anchors: Sequence[int] = _PROJECTION_ANCHORS,
) -> Tuple[ExperimentResult, Dict[str, Any]]:
    """Measure a unit cost at small N, then project the published sweep.

    Returns (result, provenance). Every projected point is reconstructible from
    `provenance` without re-running anything: it carries the anchor means and
    CIs, the fitted slope and intercept, the linearity residual, and the worker
    count the anchors were measured at.
    """
    global _SEARCH_PROCESSES

    result = ExperimentResult(
        scheme=SCHEME_NAME,
        experiment="exp2",
        columns={
            "variable": "N (index size)",
            "primary": "search_cpu_time_ms",
            "secondary_1": "wall_clock_ms",
            "secondary_2": "pairings_computed",
        },
    )

    keyword = workload.keywords[0]
    # Drawn ONCE, before the anchor loop, and reused at every anchor -- the same
    # discipline guo's exp2 requires. Inside the loop it would vary per anchor
    # and contaminate the slope with query selectivity.
    selected = [keyword] + [
        workload.rng.choice(workload.keywords) for _ in range(q - 1)
    ]

    saved_procs = _SEARCH_PROCESSES
    _SEARCH_PROCESSES = 1
    anchor_stats: List[Dict[str, Any]] = []
    anchor_runs: Dict[int, List[Run]] = {}
    try:
        for n in anchors:
            index = build_index(workload, keyword, n)

            def operation(index: List[scheme.KeywordIndex] = index) -> Measurement:
                tokens = [
                    scheme.trapdoor(workload.params, workload.key, word)
                    for word in selected
                ]
                pairings = 0
                with CpuTimer() as timer:
                    matches: Optional[set] = None
                    for token in tokens:
                        plan = scheme.prepare_query(
                            workload.params, index[0].structure, token
                        )
                        hits, tp = _parallel_search(
                            workload.params, index, token, plan
                        )
                        pairings += tp
                        matches = hits if matches is None else (matches & hits)
                return Measurement(
                    primary=timer.elapsed_ms,
                    secondary_1=timer.wall_ms,
                    secondary_2=float(pairings),
                )

            runs = measure_point(
                operation, variable_value=n,
                repetitions=repetitions, warmups=warmups,
            )
            ok = [r for r in runs if r.status == "ok"]
            if not ok:
                raise RuntimeError(f"anchor N={n} produced no successful run")
            anchor_runs[n] = list(ok)
            mean, ci = mean_ci95([r.primary for r in ok])
            pv = [r.secondary_2 for r in ok if r.secondary_2 is not None]
            anchor_stats.append(
                {"n": n, "mean_ms": mean, "ci95_ms": ci, "n_runs": len(ok),
                 "pairings_mean": (sum(pv) / len(pv)) if pv else None}
            )
    finally:
        _SEARCH_PROCESSES = saved_procs

    # Pairings are q*N*(2u+1) by construction -- exactly linear, not a fit.
    # Taken from the largest anchor, where relative rounding error is smallest.
    biggest = max(anchor_stats, key=lambda a: a["n"])
    pairings_per_record = (
        biggest["pairings_mean"] / biggest["n"] if biggest.get("pairings_mean") else None
    )

    # Least squares on (n, mean). Three points, so the residual is meaningful.
    xs = [a["n"] for a in anchor_stats]
    ys = [a["mean_ms"] for a in anchor_stats]
    k = len(xs)
    mx = sum(xs) / k
    my = sum(ys) / k
    denom = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom if denom else 0.0
    intercept = my - slope * mx
    resid = [y - (intercept + slope * x) for x, y in zip(xs, ys)]
    rel_resid = [
        (r / y if y else 0.0) for r, y in zip(resid, ys)
    ]

    # A sweep point that IS an anchor was really measured -- emit its actual runs
    # rather than a value fitted through itself, so the figure carries a genuine
    # measurement with a genuine CI at that N and the projection starts above it.
    measured_at = {a["n"]: a for a in anchor_stats}
    for n in index_sizes:
        if n in measured_at:
            for r in anchor_runs.get(n, []):
                result.runs.append(
                    Run(
                        variable_value=n,
                        run_id=r.run_id,
                        primary=r.primary,
                        secondary_1=r.secondary_1,
                        secondary_2=r.secondary_2,
                        status=r.status,
                        measurement_type="measured",
                    )
                )
            continue
        result.runs.append(
            Run(
                variable_value=n,
                run_id=1,
                primary=intercept + slope * n,
                secondary_1=None,   # wall-clock is not projectable: it depends on P
                secondary_2=(pairings_per_record * n) if pairings_per_record else None,
                status="ok",
                measurement_type="projected",
            )
        )

    provenance = {
        "method": "projected from a measured unit cost",
        "anchors": anchor_stats,
        "anchor_search_processes": 1,
        "anchor_repetitions": repetitions,
        "anchor_warmups": warmups,
        "fit": {
            "slope_ms_per_record": slope,
            "intercept_ms": intercept,
            "model": "cost(N) = intercept + slope * N",
        },
        "linearity_residuals_ms": resid,
        "linearity_residuals_relative": rel_resid,
        "max_abs_relative_residual": max((abs(r) for r in rel_resid), default=0.0),
        "note": (
            "Points at the published sweep sizes are PROJECTED, not measured. "
            "The intercept is the per-query fixed cost (trapdoor generation and "
            "query planning); projecting from cost(1)*N would have charged it "
            "once per record and inflated this baseline."
        ),
    }
    return result, provenance


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

    41.md: "Does not natively support cross-domain search. Run d
    independent trapdoors and d independent searches, with client-side result
    aggregation." Ref[41] has no notion of a domain, so each domain is an
    independent shard searched with its own freshly generated trapdoor.

    NOT PARALLELIZED, unlike ``experiment_2`` — deliberate, and load-bearing.
    A fresh trapdoor is generated per (domain, token) *inside* the timer,
    which is the cost this experiment exists to expose, and the fork-inherited
    globals a worker pool depends on cannot be updated after the pool is
    forked. Pooling per (domain, token) therefore creates ``d * q`` pools per
    run — 10 at d=2 but 50 at d=10 — so pool startup cost lands *inside* the
    timer and scales with ``d``, the swept variable itself. Measured at
    ~66 ms/pool, that manufactured a ~2.6 s upward drift across d=2..10 and
    would have put a harness-induced slope into the published figure that
    looks like scheme behaviour. Single-threaded here is slower but honest;
    Exp. 2 keeps the pool because there ``q`` is fixed at 5, so the overhead
    is a constant ~0.08% rather than a slope in the measured variable.

    ``total_index_size`` is held constant across the whole ``domain_counts``
    sweep and divided evenly across domains (``shard_size = total /
    domains``), so the *search* work — total pairings per run — stays flat in
    d. Measured latency still rises with d, and legitimately so: the baseline
    must issue ``d * q`` independent trapdoors inside the timer because it
    cannot reuse one across domains, which is exactly the cost this experiment
    exists to expose. At ~20.7 ms/trapdoor that is ~829 ms of real growth from
    d=2 to d=10, and a clean run measures ~922 ms — i.e. the slope is the
    mechanism, not overhead. (An earlier parallelised version added ~1.8 s of
    pool-startup cost on top of that, inflating the slope with a harness
    artifact; see the note above.) This is the whole point of the experiment (skill.md: "count
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
        # parallel=False: experiment_3 runs single-threaded (see its docstring)
        estimate = _estimated_seconds(workload, shard_size * domains, q, parallel=False)
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
                        # DELIBERATELY SINGLE-THREADED — see note below.
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
def _estimated_seconds(
    workload: Workload, entries: int, q: int, *, parallel: bool = False
) -> float:
    """Rough wall-clock estimate for one run, from a measured unit pairing.

    Used ONLY to decide whether to attempt a point. It never becomes a
    reported number — skill.md forbids deriving measurements analytically,
    and a point that is attempted is measured end to end.

    ``parallel`` must match how the caller actually executes. The unit pairing
    below is timed single-threaded, so an unadjusted estimate over-states a
    parallelised point by ~2x and could record 30 ``failed:budget_exceeded``
    runs for a point that would in fact have finished in half the budget. The
    speedup applied is deliberately conservative (below the 1.94-1.95x
    measured) so the guard still errs toward attempting a point rather than
    refusing one it could have completed.
    """
    backend = workload.params.backend
    element = workload.params.i
    with Timer() as timer:
        for _ in range(10):
            backend.pair(element, element)
    unit_ms = timer.elapsed_ms / 10

    pairings_per_entry = 2 * len(workload.policy_attributes) + 1
    seconds = (entries * q * pairings_per_entry * unit_ms) / 1000.0
    if parallel and _SEARCH_PROCESSES > 1:
        seconds /= _PARALLEL_SPEEDUP_FOR_ESTIMATES
    return seconds


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
