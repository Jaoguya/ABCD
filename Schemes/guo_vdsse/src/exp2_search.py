"""Exp. 2 — Search Latency.

Variable:  index size ``N`` = 10^4 → 10^6 (log scale)
Primary:   latency (ms)
Secondary: entries traversed (n_eff), prune ratio

Measurement boundary (README §5, Exp. 2):
    Full online path: token generation → server inverted-index retrieval →
    forward-index filtering → client final eval → result assembly.
    Index construction is offline (not timed).

Defaults: q = 5 keywords, d = 4 domains (README §6).
"""

from __future__ import annotations

import gc

from pathlib import Path
from typing import Optional, Any, Dict, List

from Common.crypto.rng import DeterministicRNG
from Dataset.corpus import Record

from .harness import (
    RunResult,
    aggregate_results,
    measure_ns,
    run_experiment,
    write_raw_runs,
    write_results,
    write_run_meta,
)
from .scheme import GuoVDSSE

from infra import sweep


EXPERIMENT_NAME = "exp2"
SECONDARY_NAMES = ["n_eff", "entries_traversed", "prune_ratio"]

# Index sizes — log scale from 10^4 to 10^6 (README §5)
# CAPPED at 2*10^5 on 2026-08-29 -- a hardware limit, disclosed, not a choice.
#
# Guo's forward index stores a t-punctured GGM key per document, sized
# O(|W_id| * log|X|). At the configured 64-bit domain and corpus v4's 31.7
# keywords/document that is 50.5 KB per document, measured:
#
#     N = 10^5  ->  5.2 GB      N = 5*10^5  ->  25.9 GB
#     N = 2*10^5 -> 10.3 GB     N = 10^6    ->  51.7 GB
#
# global.yaml pins a 16 GiB host and the materialised corpus takes ~2 GB, so
# 2*10^5 is the largest point that fits. The 2026-08-28 campaign proved the
# rest: at the previous 128-bit domain every guo experiment was OOM-killed
# (rc=137, anon-rss 15.67 GB).
#
# This is not peculiar to our implementation. Ref[35]'s own evaluation ran on
# 112 GB of memory over a dataset averaging 3.85 keywords/document; corpus v4
# averages 31.70, and this index is linear in that. At our density N = 10^6
# needs 51.7 GB, which the paper's own machine could hold but the pinned
# benchmark host cannot.
#
# §V MUST STATE the cap and its reason -- hardware and corpus density, not an
# unfavourable result. Same treatment Ref[41]'s N = 10^4 cap already carries.
VARIABLE_RANGE = [10_000, 20_000, 50_000, 100_000, 200_000]

# Default query size (README §6: "each query contains five keywords")
DEFAULT_Q = 5


def _find_conjunctive_keywords(
    records: List[Record],
    rng: DeterministicRNG,
    q: int,
    attempts: int = 100,
) -> List[str]:
    """Select q keywords that have at least some matching documents.

    We pick keywords that actually appear in the corpus and try to find
    combinations where the least-frequent term has a reasonable number
    of matches, to avoid measuring empty-result queries.
    """
    from collections import Counter

    kw_counts: Counter[str] = Counter()
    for rec in records:
        kw_counts.update(rec.kw)

    # Exclude extremely frequent keywords (>50% of records) — they
    # dominate the scan and hide the scaling behaviour.
    eligible = [
        kw
        for kw, cnt in kw_counts.items()
        if cnt >= 10 and cnt <= len(records) * 0.5
    ]
    if len(eligible) < q:
        eligible = sorted(kw_counts.keys())

    for _ in range(attempts):
        selected = rng.choice(eligible, size=min(q, len(eligible)),
                              replace=False)
        if len(selected) == q:
            return selected
    return rng.choice(eligible, size=min(q, len(eligible)), replace=False)


def run(
    scheme: GuoVDSSE,
    records: List[Record],
    manifest: Dict[str, Any],
    output_dir: Path,
    *,
    runs: int = 30,
    warmup: int = 5,
    seed: int = 20260804,
    points: Optional[str] = None,
) -> None:
    """Run Experiment 2: Search Latency vs. Index Size."""
    rng = DeterministicRNG(seed).spawn("exp2_search")

    # Filter variable range to available records
    max_available = len(records)
    actual_range = [n for n in VARIABLE_RANGE if n <= max_available]
    if not actual_range:
        actual_range = [max_available]

    # Pre-select keyword queries — SAME keywords across all N values
    # so the difference is attributable to index size alone.
    query_sets: List[List[str]] = []

    # Build the EDB ONCE and GROW it through the sweep — not timed.
    #
    # Every sweep point is `records[:n]` — the points are nested prefixes, and
    # `run_experiment` walks them in ascending order. Rebuilding from scratch at
    # each point therefore re-inserted every record already indexed: the seven
    # points cost 1,880,000 inserts to produce a largest index of 1,000,000.
    # Growing one EDB costs exactly 1,000,000 — the same work the largest point
    # needs anyway, so six of the seven points become free.
    #
    # IDENTICAL, not merely similar. `update()` is called on the same records in
    # the same order either way (0..n-1 ascending), so after reaching n the EDB
    # is byte-for-byte what a fresh `records[:n]` build produces. This is a
    # harness change only: no scheme code, no call order, no parameter differs.
    # `test_exp2_incremental_build_matches_a_fresh_build` pins that.
    #
    # It also bounds memory at the LARGEST index rather than the largest plus
    # whatever is being built next — ~9.5 GB at N = 10^6, measured, against
    # global.yaml's 16 GiB host. The previous build-all-then-hold version needed
    # ~18 GB and could not complete at all.
    #
    # One deliberate consequence: a single `setup()` means one key set across
    # the whole sweep, where rebuilding drew fresh keys per point. That removes
    # a confound rather than adding one — search latency must not depend on
    # which keys were drawn, and now it demonstrably cannot.
    built_to = [0]
    state, edb = scheme.setup()

    def _ensure_built(n: int) -> None:
        if built_to[0] >= n:
            return
        for rec in records[built_to[0]:n]:
            scheme.update(state, edb, "add", rec.rid, rec.kw)
        built_to[0] = n

        # Query keywords are drawn ONCE, from the smallest sweep point, and
        # reused at every N: the same queries must be issued at every index size
        # or the curve mixes two variables. `records[:n]` is a prefix, so a
        # keyword present in the smallest subset is present in all of them.
        if not query_sets:
            for _ in range(warmup + runs):
                kws = _find_conjunctive_keywords(records[:n], rng, DEFAULT_Q)
                query_sets.append(kws)

    iteration_counter: Dict[int, int] = {n: 0 for n in actual_range}

    def runner(n: int) -> RunResult:
        _ensure_built(n)
        idx = iteration_counter[n]
        iteration_counter[n] += 1
        keywords = query_sets[idx % len(query_sets)]

        # `state` and `edb` are the single grown pair; at this point they hold
        # exactly records[:n].

        # Measure full search path — token gen through final result
        elapsed_ms, search_result = measure_ns(
            lambda: scheme.search(state, edb, keywords)
        )

        # Secondary metrics
        n_eff = (
            search_result.entries_traversed + search_result.forward_evals
        )
        single_count = search_result.single_keyword_result_count
        prune_ratio = (
            len(search_result.result_ids) / single_count
            if single_count > 0
            else 0.0
        )

        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "n_eff": n_eff,
                "entries_traversed": search_result.entries_traversed,
                "prune_ratio": round(prune_ratio, 6),
            },
        )

    sweep_values = sweep.select(actual_range, points)

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    # Write outputs
    exp_dir = sweep.shard_dir(output_dir / "exp2_search_latency", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    aggregated = aggregate_results(results, SECONDARY_NAMES)
    write_results(exp_dir / "results.csv", aggregated)
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
