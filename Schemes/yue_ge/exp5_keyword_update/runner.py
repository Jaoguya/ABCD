"""Exp. 5 — Dynamic Keyword Update. Ref[55] §VI-A ``Add`` / ``Delete``.

Variable:  (keyword, document) pairs ``k`` = 10^2 -> 10^5 (README §5)
Primary:   update latency (ms)
Secondary: entries rewritten, index growth (bytes)

INCREMENTAL, NOT A REBUILD
--------------------------
README §5 is explicit: "incremental update only. A global rebuild means Phase
VII is implemented wrong." Ref[55] satisfies this natively — ``Add`` writes a
NEW batch ``I_c = (A_c, T_c)`` and the server appends it (``I = I union I_c``,
Algorithm 1). Existing batches are never rewritten, which is precisely what
gives the scheme forward privacy. So what is timed here is one ``Add`` of ``k``
fresh (keyword, document) pairs against an already-populated index.

``k`` counts pairs, not distinct keywords — the corpus holds ~18.8M pairs
against a 2,102-word vocabulary (README §4), so 10^5 pairs is available while
10^5 distinct keywords would be impossible.

ADD AND DELETE ARE BOTH MEASURED
--------------------------------
The paper reports them separately (Tables VI and VII) because their costs differ
by orders of magnitude: ``Add`` writes ``h`` MSRE ciphertexts per pair, while
``Delete`` only sets Bloom bits locally and never contacts the server. Reporting
only the cheap half would misrepresent the scheme, so ``Add`` is the primary
metric and per-pair ``Delete`` cost is carried as a secondary.

WHY THE PAPER'S ADDITION TIME IS SO LOW
---------------------------------------
Table VI shows Peony at ~1.4e-6 ms/id and Peony++ at 0.05-0.21 ms/id. The gap is
MSRE: Peony writes one masked node, Peony++ additionally runs ``h`` AES
encryptions per entry (one per Bloom position). Running both variants makes that
visible; ``--variant peony`` measures the forward-only scheme.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Optional, Any, Dict, List, Sequence, Tuple

from Common.crypto.rng import DeterministicRNG
from Dataset.corpus import Record

from ..src import peony, peony_plus
from ..src.harness import (
    RunResult,
    aggregate_results,
    measure_ns,
    run_experiment,
    write_raw_runs,
    write_results,
    write_run_meta,
)
from ..src.params import SchemeParams
from ..src.workload import build_workload, index_workload

from infra import sweep

EXPERIMENT_NAME = "exp5"
SECONDARY_NAMES = ["entries_rewritten", "index_growth_bytes", "delete_ms"]

VARIABLE_RANGE = [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000]


def _pair_stream(
    records: Sequence[Record], params: SchemeParams
) -> List[Tuple[str, int, int]]:
    """Flatten the corpus into ``(keyword, record_id, level)`` triples."""
    from ..src.levels import assign_level

    out: List[Tuple[str, int, int]] = []
    for rec in records:
        lvl = assign_level(rec.pid, params.access_levels)
        for kw in rec.kw:
            out.append((kw, rec.rid, lvl))
    return out


def run(
    params: SchemeParams,
    records: Sequence[Record],
    manifest: Dict[str, Any],
    output_dir: Path,
    *,
    runs: int = 30,
    warmup: int = 5,
    seed: int = 20260828,
    points: Optional[str] = None,
    variant: str = "peony_plus",
) -> None:
    rng = DeterministicRNG(seed).spawn("exp5_update")

    pairs = _pair_stream(records, params)
    available = len(pairs)
    actual_range = [k for k in VARIABLE_RANGE if k <= available]
    if not actual_range:
        actual_range = [available]
    if actual_range != VARIABLE_RANGE:
        print(
            f"  NOTE: corpus supplies {available:,} (keyword, document) pairs; "
            f"sweep truncated to {actual_range}."
        )

    # ---- an already-populated index to update into. Untimed. ----
    seed_records = records[: max(1, len(records) // 2)]
    base_workload = build_workload(seed_records, params)
    state, index, prooflist = peony_plus.setup(params)
    index_workload(state, index, prooflist, base_workload, variant)
    print(f"  base index: {index.total_nodes:,} nodes, "
          f"{index.batch_count} batches")

    next_batch = [index.batch_count]
    counter: Dict[int, int] = {k: 0 for k in actual_range}

    def runner(k: int) -> RunResult:
        i = counter[k]
        counter[k] += 1

        # A fresh, non-overlapping slice each run so no run benefits from a
        # warm cache of the previous run's keys.
        start = (i * k) % max(1, available - k)
        chunk = pairs[start:start + k]

        per_keyword: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        for kw, rid, lvl in chunk:
            per_keyword[kw].append((rid, lvl))
        per_keyword = dict(per_keyword)

        next_batch[0] += 1
        batch_id = next_batch[0]
        before = index.size_bytes

        if variant == "peony":
            def do_add():
                return peony.update(
                    params, state.key, index, batch_id, per_keyword
                )
        else:
            def do_add():
                return peony_plus.add(
                    state, index, prooflist, batch_id, per_keyword
                )

        elapsed_ms, batch = measure_ns(do_add)
        growth = index.size_bytes - before

        # Deletion is a separate published metric (Table VII). Time the same
        # k pairs being deleted, which for Peony++ is purely local Bloom work.
        if variant == "peony_plus":
            del_ms, _ = measure_ns(
                lambda: [
                    peony_plus.delete(state, kw, entries)
                    for kw, entries in per_keyword.items()
                ]
            )
        else:
            del_ms = 0.0

        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "entries_rewritten": batch.node_count,
                "index_growth_bytes": growth,
                "delete_ms": round(del_ms, 6),
            },
        )

    sweep_values = actual_range

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    exp_dir = sweep.shard_dir(output_dir / "exp5_keyword_update", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    write_results(exp_dir / "results.csv",
                  aggregate_results(results, SECONDARY_NAMES))
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
