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

from pathlib import Path
from typing import Any, Dict, List

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


EXPERIMENT_NAME = "exp2"
SECONDARY_NAMES = ["n_eff", "entries_traversed", "prune_ratio"]

# Index sizes — log scale from 10^4 to 10^6 (README §5)
VARIABLE_RANGE = [10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000]

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

    # Build EDBs of different sizes — not timed
    edbs: Dict[int, Any] = {}
    states: Dict[int, Any] = {}

    for n in actual_range:
        subset = records[:n]
        state, edb = scheme.setup()
        for rec in subset:
            scheme.update(state, edb, "add", rec.rid, rec.kw)
        edbs[n] = edb
        states[n] = state

        # Generate keyword sets from THIS subset's vocabulary
        if not query_sets:
            for _ in range(warmup + runs):
                kws = _find_conjunctive_keywords(subset, rng, DEFAULT_Q)
                query_sets.append(kws)

    # Ensure keywords exist in all subsets — use keywords from smallest
    # corpus that also exist in the larger ones (they will, since we
    # always use records[:n] with the same ordering).
    iteration_counter: Dict[int, int] = {n: 0 for n in actual_range}

    def runner(n: int) -> RunResult:
        idx = iteration_counter[n]
        iteration_counter[n] += 1
        keywords = query_sets[idx % len(query_sets)]

        state = states[n]
        edb = edbs[n]

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

    results = run_experiment(actual_range, runner, runs=runs, warmup=warmup)

    # Write outputs
    exp_dir = output_dir / "exp2_search_latency"
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    aggregated = aggregate_results(results, SECONDARY_NAMES)
    write_results(exp_dir / "results.csv", aggregated)
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
