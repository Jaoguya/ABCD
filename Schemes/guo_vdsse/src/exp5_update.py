"""Exp. 5 — Dynamic Keyword Update.

Variable:  (keyword, document) pairs ``k`` = 10^2 → 10^5
Primary:   latency (ms)
Secondary: entries rewritten (Ti insertions + Tf insertions)

Measurement boundary (README §5, Exp. 5):
    Incremental update only — NOT a full rebuild.

For Guo, each update(add, id, W_id) writes:
  - |W_id| inverted-index entries (one per keyword)
  - 1 forward-index entry (one per document, containing the punctured key)

Update is done via repeated calls to ``scheme.update()``.  We measure
the total time to add ``k`` new (keyword, document) pairs, starting
from a pre-built EDB.  The pre-build is NOT timed.

Merkle nodes recomputed: N/A for Guo (no Merkle tree in this scheme).
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

EXPERIMENT_NAME = "exp5"
SECONDARY_NAMES = ["entries_rewritten"]

# Variable range: total (keyword, document) pairs added
VARIABLE_RANGE = [100, 200, 500, 1_000, 2_000, 5_000, 10_000, 20_000,
                  50_000, 100_000]


def _generate_update_batch(
    records: List[Record],
    rng: DeterministicRNG,
    total_pairs: int,
) -> List[Tuple[int, List[str]]]:
    """Generate a batch of (doc_id, keywords) for incremental updates.

    Each tuple represents one document to add.  We create synthetic
    documents with keywords drawn from the corpus vocabulary, ensuring
    the total (keyword, document) pairs sum to ``total_pairs``.
    """
    kw_universe = sorted({kw for rec in records for kw in rec.kw})
    if not kw_universe:
        return []

    # Compute the average keywords per record from the corpus (not hardcoded)
    total_kw = sum(len(rec.kw) for rec in records)
    avg_kw = max(1, total_kw // len(records))

    batch: List[Tuple[int, List[str]]] = []
    pairs_added = 0
    base_id = max(rec.rid for rec in records) + 1

    while pairs_added < total_pairs:
        remaining = total_pairs - pairs_added
        n_kw = min(avg_kw, remaining, len(kw_universe))
        if n_kw <= 0:
            break
        kws = rng.choice(kw_universe, size=n_kw, replace=False)
        batch.append((base_id, kws))
        base_id += 1
        pairs_added += n_kw

    return batch


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
    """Run Experiment 5: Dynamic Keyword Update."""
    rng = DeterministicRNG(seed).spawn("exp5_update")

    # Filter variable range to feasible values
    actual_range = VARIABLE_RANGE

    # Pre-generate update batches for each k value — same batches across
    # all runs for consistency.  We generate warmup + runs batches per k.
    batches: Dict[int, List[List[Tuple[int, List[str]]]]] = {}
    for k in actual_range:
        run_batches = []
        for i in range(warmup + runs):
            child_rng = rng.spawn(f"k{k}_iter{i}")
            batch = _generate_update_batch(records, child_rng, k)
            run_batches.append(batch)
        batches[k] = run_batches

    iteration_counter: Dict[int, int] = {k: 0 for k in actual_range}

    def runner(k: int) -> RunResult:
        idx = iteration_counter[k]
        iteration_counter[k] += 1
        batch = batches[k][idx]

        # Pre-build a fresh EDB from the base corpus — not timed
        state, edb = scheme.setup()
        for rec in records:
            scheme.update(state, edb, "add", rec.rid, rec.kw)
        pre_count = edb.total_entry_count

        # Measure ONLY the incremental updates
        def do_updates():
            total_entries = 0
            for doc_id, kws in batch:
                total_entries += scheme.update(
                    state, edb, "add", doc_id, kws
                )
            return total_entries

        elapsed_ms, entries_written = measure_ns(do_updates)

        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "entries_rewritten": entries_written,
            },
        )

    results = run_experiment(actual_range, runner, runs=runs, warmup=warmup)

    # Write outputs
    exp_dir = output_dir / "exp5_keyword_update"
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    aggregated = aggregate_results(results, SECONDARY_NAMES)
    write_results(exp_dir / "results.csv", aggregated)
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
