"""Exp. 3 — Cross-Domain Search Scalability. Ref[55], native mode.

Variable:  domains ``d`` = 2 -> 10
Primary:   total latency (ms) across ``d`` domains
Secondary: trapdoors issued, cross-node messages

NATIVE MODE
-----------
Ref[55] has no cross-domain notion at all. Its system model (§V) is a single
data owner, a single cloud server, and a hierarchy of users — there is no
federation, no inter-server protocol, and no shared index across administrative
boundaries. So the honest treatment is SystemConfiguration.md's native-mode rule, the same
one applied to ``guo_vdsse`` and ``thingom_pq_abse``:

    issue ``d`` independent tokens, run ``d`` independent searches, aggregate
    on the client.

Latency is therefore expected to grow linearly in ``d``, and ``cross_node_msgs``
is identically 0 because no such message exists in the construction. Counting
trapdoors issued is what makes the mechanism visible in the plot (global.yaml,
Exp. 3: "Count trapdoors issued so the mechanism is visible").

TOTAL INDEX IS HELD CONSTANT ACROSS d
-------------------------------------
``d`` is the only variable, so the total amount of indexed data must not move
with it. A fixed subset of ``N = 10^5`` records (global.yaml's default index size)
is sharded into ``d`` parts, exactly as ``guo_vdsse``'s Exp. 3 does
("each of ``d`` independent EDB instances holds 1/d of the corpus ... so total
data is constant as d varies").

This runner previously built one deployment per REAL corpus domain and indexed
that domain's entire record set, so the ``d = 10`` point indexed five times the
data of the ``d = 2`` point. The resulting slope would have been mostly the
growing corpus, not the growing domain count — the identical defect found and
fixed in ``thingom_pq_abse``'s Exp. 3 on 2026-08-27, where a shard size computed
from a constant instead of the swept ``d`` made ``d = 10`` cost ~5x ``d = 2``.
It also made the sweep unaffordable in memory: ten full-domain Peony++
deployments are ~12 GB against a 16 GiB host.

Sharding by ``rec.dom % d`` keeps shards aligned to real institutional
boundaries wherever ``d`` divides the corpus's 10 domains, and never invents a
domain the corpus does not have — dataset.yaml's constraint is about not
FABRICATING domains, which sharding a fixed subset does not do.
"""

from __future__ import annotations

import gc

from collections import defaultdict
from pathlib import Path
from typing import Optional, Any, Dict, List, Sequence

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
from ..src.workload import build_workload, index_workload, select_keywords

from infra import sweep

EXPERIMENT_NAME = "exp3"
SECONDARY_NAMES = ["trapdoors_issued", "cross_node_msgs", "results_returned"]

VARIABLE_RANGE = list(range(2, 11))

# global.yaml default index size. Held constant across the whole d sweep so
# that d is the only variable — see the module docstring.
TOTAL_INDEX_SIZE = 100_000

# §VI Exp. 3 fixes the PER-DOMAIN index size, not the total:
# "The query size and per-domain index size are fixed to isolate cross-domain
# search overhead." This fixed the TOTAL at 100,000 and sharded it by `d`, so
# each domain's shard SHRANK from 50,000 at d=2 to 10,000 at d=10 — which is
# why this scheme's Exp. 3 latency FELL across a sweep that is supposed to show
# cross-domain cost rising. The proposed scheme meanwhile fixed per-domain at 4
# records, so at d=10 the two sat on one axis with a 2,500x data disparity and
# curve directions set by the two designs rather than by the schemes.
#
# All five now hold per-domain fixed at this value; total grows with `d`.
# RESULTS-AFFECTING for this baseline's Exp. 3. (2026-09-10)
PER_DOMAIN_INDEX_SIZE = 10_000



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
    rng = DeterministicRNG(seed).spawn("exp3_crossdomain")

    # The fixed total index, held constant across every d.
    # Per-domain fixed (§VI): `PER_DOMAIN_INDEX_SIZE * d` records, so each of
    # the `d` shards holds the same number at every sweep point.
    _wanted = PER_DOMAIN_INDEX_SIZE * max(actual_range)
    subset = list(records[: min(_wanted, len(records))])
    if len(subset) < TOTAL_INDEX_SIZE:
        print(
            f"  NOTE: corpus holds {len(subset):,} records; total index is "
            f"that rather than the §6 default {TOTAL_INDEX_SIZE:,}."
        )

    # --points must FILTER the sweep, not merely name the output directory --
    # see the note in this scheme's exp2 runner. This built every d from 2..10
    # regardless of --points and wrote them all to a directory named for one.
    actual_range = sweep.select(VARIABLE_RANGE, points)
    level = max(1, (params.access_levels + 1) // 2)

    # ---- d independent deployments over d shards of ONE fixed subset.
    # Built on demand and released before the next d: each set is ~1.0 GB of
    # A_c slots, and holding all nine sweep points at once does not fit the
    # 16 GiB host. run_experiment walks the sweep in order, so one is enough.
    built: Dict[int, List[Dict[str, Any]]] = {}

    def shards_for(d: int) -> List[Dict[str, Any]]:
        if d in built:
            return built[d]
        built.clear()
        gc.collect()

        buckets: Dict[int, List[Record]] = defaultdict(list)
        for rec in subset:
            buckets[rec.dom % d].append(rec)

        deployments: List[Dict[str, Any]] = []
        for shard_idx in range(d):
            shard = buckets.get(shard_idx, [])
            if not shard:
                continue
            wl = build_workload(shard, params)
            state, index, prooflist = peony_plus.setup(params)
            index_workload(state, index, prooflist, wl, variant)
            kws = select_keywords(
                wl.keyword_freq, rng, warmup + runs,
                total_records=wl.record_count,
            )
            deployments.append(
                {"state": state, "index": index, "workload": wl,
                 "keywords": kws}
            )
        built[d] = deployments
        total_nodes = sum(x["index"].total_nodes for x in deployments)
        print(f"  d={d:>2}: {len(deployments)} shards, {len(subset):,} records "
              f"total, {total_nodes:,} nodes total")
        return deployments

    counter = {d: 0 for d in actual_range}

    def runner(d: int) -> RunResult:
        i = counter[d]
        counter[d] += 1
        targets = shards_for(d)

        def federated():
            issued = 0
            merged: set = set()
            for ctx in targets:
                if not ctx["keywords"]:
                    continue
                kw = ctx["keywords"][i % len(ctx["keywords"])]
                bc = ctx["workload"].batch_count
                if variant == "peony":
                    tok = peony.token_gen(ctx["state"].key, kw, level, bc)
                    out = peony.search(tok, ctx["index"])
                else:
                    tok = peony_plus.token_gen(ctx["state"], kw, level, bc)
                    out = peony_plus.search(
                        ctx["state"], tok, ctx["index"], kw
                    )
                issued += 1
                merged |= out.result_ids  # client-side aggregation
            return issued, merged

        elapsed_ms, (issued, merged) = measure_ns(federated)
        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "trapdoors_issued": issued,
                # No inter-server protocol exists in this construction.
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
