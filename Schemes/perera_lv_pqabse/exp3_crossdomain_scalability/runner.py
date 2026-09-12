"""Exp. 3 — Cross-Domain Search Scalability. Ref[54], native mode.

Variable:  domains ``d`` = 2 -> 10 (skill.md)
Primary:   total latency (ms) across ``d`` domains
Secondary: trapdoors issued, cross-node messages, results returned

NATIVE MODE
-----------
Ref[54]'s system model is one Trusted Authority, one fog tier, no federation
and no inter-server protocol — there is no cross-domain notion in the paper at
all. crypto.yaml records the decision (``cross_domain.mode:
independent_trapdoors``, 2026-08-29): issue ``d`` independent trapdoors, run
``d`` independent searches, aggregate on the client. That is skill.md's
native-mode rule, already applied to ``guo_vdsse`` and ``thingom_pq_abse``.

Latency is therefore expected to grow roughly linearly in ``d``, and
``cross_node_msgs`` is identically 0 because no such message exists in the
construction. Counting trapdoors issued is what makes the mechanism visible
(skill.md, Exp. 3).

TOTAL INDEX IS HELD CONSTANT ACROSS d
-------------------------------------
``d`` is the only variable, so a fixed ``N = 10^5`` subset is sharded into ``d``
parts rather than each domain holding its own full record set. Otherwise the
``d = 10`` point would index five times the data of ``d = 2`` and the slope
would be mostly the growing corpus — the defect found in ``thingom_pq_abse``
(2026-08-27) and again in ``yue_ge`` (2026-08-29).
"""

from __future__ import annotations

import gc
from collections import defaultdict
from pathlib import Path
from typing import Optional, Any, Dict, List, Sequence

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
from ..src.workload import build_fog_node, keyword_frequency, select_keywords

from infra import sweep

EXPERIMENT_NAME = "exp3"
SECONDARY_NAMES = ["trapdoors_issued", "cross_node_msgs", "results_returned"]

VARIABLE_RANGE = list(range(2, 11))
TOTAL_INDEX_SIZE = 100_000
DEFAULT_Q = 5


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
    rng = DeterministicRNG(seed).spawn("exp3_crossdomain")
    actual_range = sweep.select(VARIABLE_RANGE, points)
    subset = list(records[: min(TOTAL_INDEX_SIZE, len(records))])
    if len(subset) < TOTAL_INDEX_SIZE:
        print(
            f"  NOTE: corpus holds {len(subset):,} records; total index is "
            f"that rather than the §6 default {TOTAL_INDEX_SIZE:,}."
        )

    keys = scheme.setup(params, with_abe=True)
    # Ref[54] L563-565 binds the trapdoor to SK_A, so the querying user
    # must be enrolled. One key per RUN -- a user's attribute key does not
    # change between queries. Enrolment is setup and is not timed.
    user_key = scheme.enrol_user(keys)
    built: Dict[int, List[Dict[str, Any]]] = {}

    def deployments_for(d: int) -> List[Dict[str, Any]]:
        if d in built:
            return built[d]
        built.clear()
        gc.collect()

        buckets: Dict[int, List[Record]] = defaultdict(list)
        for record in subset:
            buckets[record.dom % d].append(record)

        nodes: List[Dict[str, Any]] = []
        for shard_idx in range(d):
            shard = buckets.get(shard_idx, [])
            if not shard:
                continue
            node = build_fog_node(keys, shard, params)
            freq = keyword_frequency(shard)
            queries = [
                select_keywords(freq, rng, DEFAULT_Q)
                for _ in range(warmup + runs)
            ]
            nodes.append({"node": node, "queries": queries})
        built[d] = nodes
        postings = sum(x["node"].index.postings for x in nodes)
        print(f"  d={d:>2}: {len(nodes)} fog nodes, {len(subset):,} records "
              f"total, {postings:,} postings total")
        return nodes

    counter = {d: 0 for d in actual_range}

    def runner(d: int) -> RunResult:
        i = counter[d]
        counter[d] += 1
        targets = deployments_for(d)

        def federated():
            issued = 0
            merged: set = set()
            for ctx in targets:
                keywords = ctx["queries"][i % len(ctx["queries"])]
                if not keywords:
                    continue
                # One trapdoor PER DOMAIN: the scheme has no shared trapdoor,
                # and that cost is exactly what Exp. 3 exists to expose.
                td = scheme.trapdoor(keys, keywords, attribute_key=user_key)
                issued += 1
                merged |= ctx["node"].search(td).rids
            return issued, merged

        elapsed_ms, (issued, merged) = measure_ns(federated)
        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "trapdoors_issued": issued,
                "cross_node_msgs": 0,
                "results_returned": len(merged),
            },
        )
    sweep_values = actual_range

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    exp_dir = sweep.shard_dir(output_dir / "exp3_crossdomain_scalability", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    write_results(exp_dir / "results.csv",
                  aggregate_results(results, SECONDARY_NAMES))
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
