"""Exp. 2 — Search Latency. Ref[54].

Variable:  index size ``N`` = 10^4 -> 10^6 (README §5)
Primary:   search latency (ms)
Secondary: n_eff (candidates examined), B+-tree descents, prune ratio

MEASUREMENT BOUNDARY
--------------------
README §5: "full online path ... Index construction is offline." Phase 3 index
construction is therefore built untimed, and the timer covers Phase 4
``SearchExec`` only — trapdoor signature verification, B+-tree lookups,
candidate intersection, and the ``AuditCommit``.

``tree_descents`` is reported because the paper's Table II claims ``O(log n)``
search. Latency alone cannot show whether the tree is being descended; the
descent count can, and it is the only secondary metric that can falsify the
claim.

Indexes are built ON DEMAND, one sweep point at a time, and released before the
next — the same lesson yue_ge's Exp. 2 recorded. ``run_experiment`` walks the
sweep in order, so only one index is ever needed.
"""

from __future__ import annotations

import gc
from pathlib import Path
from typing import Any, Dict, Sequence

from Common.crypto.rng import DeterministicRNG
from Dataset.corpus import Record

from ..src import scheme
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
from ..src.hybrid_index import HybridIndex
from ..src.workload import (
    grow_fog_node,
    keyword_frequency,
    select_keywords,
)

from infra import sweep

EXPERIMENT_NAME = "exp2"
SECONDARY_NAMES = ["n_eff", "tree_descents", "prune_ratio",
                   "matched_records"]

VARIABLE_RANGE = [10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000]

DEFAULT_Q = 5   # README §6: "each query contains five keywords"


def run(
    params: SchemeParams,
    records: Sequence[Record],
    manifest: Dict[str, Any],
    output_dir: Path,
    *,
    runs: int = 30,
    warmup: int = 5,
    seed: int = 20260829,
    points: Optional[str] = None,
) -> None:
    rng = DeterministicRNG(seed).spawn("exp2_search")

    available = len(records)
    actual_range = [n for n in VARIABLE_RANGE if n <= available] or [available]
    if actual_range != VARIABLE_RANGE:
        print(
            f"  NOTE: corpus holds {available:,} records; sweep truncated to "
            f"{actual_range}. Points above the corpus size are NOT reported "
            f"(README §13: no synthetic padding to fill an axis)."
        )

    keys = scheme.setup(params, with_abe=False)

    # Build the fog index ONCE and GROW it through the sweep.
    #
    # Every sweep point is `records[:n]` — nested prefixes, walked in ascending
    # order by `run_experiment`. Rebuilding per point re-ingests everything
    # already indexed: the seven points cost 1,880,000 ingests to produce a
    # largest index of 1,000,000. Growing one index costs exactly 1,000,000, so
    # six of the seven points become free. Ingest here is dominated by the
    # ML-DSA-65 sign/verify pair, so that saving is most of Exp. 2's wall-clock.
    #
    # Sound because Phase 3 ingestion is per-record and order-preserving: the
    # same records are ingested in the same order either way, so on reaching n
    # the index holds exactly `records[:n]`. Merkle partition roots are
    # recomputed by `finalize()` at each point, so they match the prefix too.
    state = {"built_to": 0,
             "node": scheme.FogNode(keys=keys,
                                    index=HybridIndex(ngram_size=params.ngram_size)),
             "queries": []}

    def context_for(n: int) -> Dict[str, Any]:
        if state["built_to"] >= n:
            return state
        chunk = list(records[state["built_to"]:n])
        grow_fog_node(keys, state["node"], chunk, params)
        state["built_to"] = n

        if not state["queries"]:
            freq = keyword_frequency(list(records[:n]))
            state["queries"] = [
                select_keywords(freq, rng, DEFAULT_Q)
                for _ in range(warmup + runs)
            ]
            if not state["queries"][0]:
                raise RuntimeError(f"no eligible query keywords at N={n}")
        node = state["node"]
        print(f"  built N={n:>9,}: {node.index.postings:>10,} postings, "
              f"B+-tree height {node.index.keywords.height}, "
              f"{node.index.size_bytes / 1e6:.1f} MB")
        return state

    counter = {n: 0 for n in actual_range}

    def runner(n: int) -> RunResult:
        ctx = context_for(n)
        i = counter[n]
        counter[n] += 1
        keywords = ctx["queries"][i % len(ctx["queries"])]
        node = ctx["node"]

        # Trapdoor generation is Exp. 1's measurement, not this one's; build it
        # outside the timer so Exp. 2 reports search cost alone.
        td = scheme.trapdoor(keys, keywords)
        elapsed_ms, out = measure_ns(lambda: node.search(td))

        prune = (
            len(out.rids) / out.candidates_examined
            if out.candidates_examined else 0.0
        )
        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "n_eff": out.candidates_examined,
                "tree_descents": out.tree_descents,
                "prune_ratio": round(prune, 6),
                # SVI Exp. 2 claims "query selectivity is kept constant",
                # and nothing in this repo recorded the quantity that claim is
                # about. `n_eff` means something DIFFERENT in every scheme --
                # matched entries here, traversal counters there -- so it could
                # not be used to check it. This is the match count, defined the
                # same way in all five schemes, so selectivity is finally
                # comparable across the shared axis of Fig. 2.
                "matched_records": len(out.rids),
            },
        )

    sweep_values = sweep.select(actual_range, points)

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    exp_dir = sweep.shard_dir(output_dir / "exp2_search_latency", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    write_results(exp_dir / "results.csv",
                  aggregate_results(results, SECONDARY_NAMES))
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
