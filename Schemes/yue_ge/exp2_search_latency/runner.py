"""Exp. 2 — Search Latency. Ref[55] §V-D / §VI-A Search.

Variable:  index size ``N`` = 10^4 -> 10^6 (README §5)
Primary:   search latency (ms)
Secondary: ``n_eff`` (nodes traversed), entries traversed, prune ratio

Measurement boundary (README §5, Exp. 2): the full online path — token
generation, server table lookup, encrypted linked-list traversal, ``MSRE.Dec``
per node for Peony++, and result assembly. **Index construction is offline and
is not timed.**

A REAL INDEX OF EACH SWEPT SIZE
-------------------------------
For each ``N`` this builds a genuine index over ``records[:N]`` once, untimed,
then measures a real search against it — the same methodology ``guo_vdsse``,
``thingom_pq_abse`` and ``ma_lb_pq_vdse`` use.

This is called out explicitly because the retired Zhuang baseline did not do it:
it encrypted a single ciphertext and approximated an ``N``-record scan by
replaying ``search()`` on that one entry ``N`` times, which made ``n_eff``
constant and ``prune_ratio`` identically zero. See
``Schemes/perera_lv_pqabse/SCHEME.md`` for that history. Ref[55] has no such
excuse: it is a symmetric scheme whose per-record state is small, so a real
index of the swept size is affordable.

Where the corpus runs out
-------------------------
The sweep is filtered to sizes the loaded corpus can actually supply, and the
truncation is reported rather than silently padded. A point that cannot be built
from real records is simply not produced — inventing records to fill the x-axis
would be moving a benchmark number.

Search cost is ``O(n_w * l)`` per the paper's Table III, and ``O(c)`` in the
batch count because the server repeats its derivation per batch. Both show up
here: ``n_eff`` grows with the result set, and ``batches_scanned`` is fixed at
``c`` from crypto.yaml.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Sequence

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
from ..src.workload import build_workload, index_workload, seed_deletions, select_keywords

EXPERIMENT_NAME = "exp2"
SECONDARY_NAMES = ["n_eff", "entries_traversed", "prune_ratio"]

VARIABLE_RANGE = [10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000]


def run(
    params: SchemeParams,
    records: Sequence[Record],
    manifest: Dict[str, Any],
    output_dir: Path,
    *,
    runs: int = 30,
    warmup: int = 5,
    seed: int = 20260828,
    variant: str = "peony_plus",
) -> None:
    rng = DeterministicRNG(seed).spawn("exp2_search")

    available = len(records)
    actual_range = [n for n in VARIABLE_RANGE if n <= available]
    if not actual_range:
        actual_range = [available]
    if actual_range != VARIABLE_RANGE:
        print(
            f"  NOTE: corpus holds {available} records; sweep truncated to "
            f"{actual_range}. Points above the corpus size are NOT reported "
            f"(README §13: no synthetic padding to fill an axis)."
        )

    level = max(1, (params.access_levels + 1) // 2)

    # ---- build one real index per N. Untimed. ----
    built: Dict[int, Any] = {}
    for n in actual_range:
        workload = build_workload(records[:n], params)
        state, index, prooflist = peony_plus.setup(params)
        index_workload(state, index, prooflist, workload, variant)

        keywords = select_keywords(
            workload.keyword_freq, rng, warmup + runs,
            total_records=workload.record_count,
        )
        if not keywords:
            raise RuntimeError(f"no eligible query keywords at N={n}")

        if variant == "peony_plus":
            seed_deletions(state, workload, keywords, params)

        built[n] = {
            "state": state,
            "index": index,
            "prooflist": prooflist,
            "workload": workload,
            "keywords": keywords,
        }
        print(f"  built N={n:>9,}: {index.total_nodes:>9,} nodes, "
              f"{index.batch_count} batches")

    counter: Dict[int, int] = {n: 0 for n in actual_range}

    def runner(n: int) -> RunResult:
        ctx = built[n]
        i = counter[n]
        counter[n] += 1
        kw = ctx["keywords"][i % len(ctx["keywords"])]
        state = ctx["state"]
        index = ctx["index"]
        batch_count = ctx["workload"].batch_count

        if variant == "peony":
            def full_path():
                tok = peony.token_gen(state.key, kw, level, batch_count)
                return peony.search(tok, index)
        else:
            def full_path():
                tok = peony_plus.token_gen(state, kw, level, batch_count)
                return peony_plus.search(state, tok, index, kw)

        elapsed_ms, out = measure_ns(full_path)

        # prune_ratio: returned / traversed. Peony's linked list is walked from
        # the querying level downward, so a level-restricted or deleted node is
        # traversed but not returned; the ratio is exactly how much of the walk
        # survived filtering.
        prune = (
            len(out.result_ids) / out.nodes_traversed
            if out.nodes_traversed else 0.0
        )
        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "n_eff": out.nodes_traversed,
                "entries_traversed": out.nodes_traversed + out.table_lookups,
                "prune_ratio": round(prune, 6),
            },
        )

    results = run_experiment(actual_range, runner, runs=runs, warmup=warmup)

    exp_dir = output_dir / "exp2_search_latency"
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    write_results(exp_dir / "results.csv",
                  aggregate_results(results, SECONDARY_NAMES))
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
