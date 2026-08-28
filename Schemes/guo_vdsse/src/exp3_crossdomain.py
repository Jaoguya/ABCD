"""Exp. 3 — Cross-Domain Search Scalability.

Variable:  domains ``d`` = 2 → 10
Primary:   latency (ms)
Secondary: trapdoors issued, cross-node messages

Measurement boundary (README §5, Exp. 3):
    Baselines run in native mode: ``d`` independent trapdoors + ``d``
    independent searches, client-side result aggregation.

For Guo:
  - Does NOT natively support cross-domain search (SCHEME.md line 19).
  - Each of ``d`` independent EDB instances holds 1/d of the corpus
    (the domain's shard), so total data is constant as d varies.
  - Trapdoors issued = d (always).
  - Cross-node messages = 0 (no inter-node communication).

Defaults: N = 10^5, q = 5 (README §6).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

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

EXPERIMENT_NAME = "exp3"
SECONDARY_NAMES = ["trapdoors_issued", "cross_node_messages"]

VARIABLE_RANGE = list(range(2, 11))  # d = 2 → 10
DEFAULT_N = 100_000
DEFAULT_Q = 5


def _shard_records(
    records: List[Record], d: int
) -> List[List[Record]]:
    """Split records into d shards by domain assignment.

    Uses the record's ``dom`` field (0-based) modulo d, so that the
    first d domains each get approximately N/d records.
    """
    shards: List[List[Record]] = [[] for _ in range(d)]
    for rec in records:
        shard_idx = rec.dom % d
        shards[shard_idx].append(rec)
    return shards


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
    """Run Experiment 3: Cross-Domain Scalability."""
    rng = DeterministicRNG(seed).spawn("exp3_crossdomain")

    # Use at most DEFAULT_N records
    subset = records[:min(DEFAULT_N, len(records))]

    # Pre-build per-d sharded EDBs — not timed
    per_d_setups: Dict[int, List[Tuple[Any, Any]]] = {}
    for d in VARIABLE_RANGE:
        shards = _shard_records(subset, d)
        shard_setups = []
        for shard in shards:
            state, edb = scheme.setup()
            for rec in shard:
                scheme.update(state, edb, "add", rec.rid, rec.kw)
            shard_setups.append((state, edb))
        per_d_setups[d] = shard_setups

    # Pre-select keyword queries — same across all d values
    kw_universe = sorted({kw for rec in subset for kw in rec.kw})
    query_sets: List[List[str]] = []
    for _ in range(warmup + runs):
        selected = rng.choice(
            kw_universe,
            size=min(DEFAULT_Q, len(kw_universe)),
            replace=False,
        )
        query_sets.append(selected)

    iteration_counter: Dict[int, int] = {d: 0 for d in VARIABLE_RANGE}

    def runner(d: int) -> RunResult:
        idx = iteration_counter[d]
        iteration_counter[d] += 1
        keywords = query_sets[idx % len(query_sets)]
        shard_setups = per_d_setups[d]

        # Measure: d independent trapdoor generations + d independent
        # searches + client-side aggregation
        def full_cross_domain_search():
            all_results = set()
            for state, edb in shard_setups:
                sr = scheme.search(state, edb, keywords)
                all_results |= sr.result_ids
            return all_results

        elapsed_ms, combined = measure_ns(full_cross_domain_search)

        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "trapdoors_issued": d,
                "cross_node_messages": 0,
            },
        )

    sweep_values = sweep.select(VARIABLE_RANGE, points)

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    # Write outputs
    exp_dir = sweep.shard_dir(output_dir / "exp3_crossdomain_scalability", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    aggregated = aggregate_results(results, SECONDARY_NAMES)
    write_results(exp_dir / "results.csv", aggregated)
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
