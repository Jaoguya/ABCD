"""Exp. 3 — Cross-Domain Search Scalability. Ref[55], native mode.

Variable:  domains ``d`` = 2 -> 10 (README §5)
Primary:   total latency (ms) across ``d`` domains
Secondary: trapdoors issued, cross-node messages

NATIVE MODE
-----------
Ref[55] has no cross-domain notion at all. Its system model (§V) is a single
data owner, a single cloud server, and a hierarchy of users — there is no
federation, no inter-server protocol, and no shared index across administrative
boundaries. So the honest treatment is README §3's native-mode rule, the same
one applied to ``guo_vdsse`` and ``thingom_pq_abse``:

    issue ``d`` independent tokens, run ``d`` independent searches, aggregate
    on the client.

Latency is therefore expected to grow linearly in ``d``, and ``cross_node_msgs``
is identically 0 because no such message exists in the construction. Counting
trapdoors issued is what makes the mechanism visible in the plot (README §5,
Exp. 3: "Count trapdoors issued so the mechanism is visible").

DOMAIN COUNT IS A HARD CORPUS LIMIT
-----------------------------------
The corpus carries exactly 4 real administrative domains (README §4:
"``CorpusRecordSource`` refuses ``d > 4`` rather than re-bucketing records into
a synthetic split"). This runner honours that: it sweeps only the ``d`` values
the corpus can actually supply and reports the truncation, rather than inventing
domains to reach ``d = 10``. That is an open item in README §14, not something
to paper over here.
"""

from __future__ import annotations

from collections import defaultdict
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
from ..src.workload import build_workload, index_workload, select_keywords

EXPERIMENT_NAME = "exp3"
SECONDARY_NAMES = ["trapdoors_issued", "cross_node_msgs", "results_returned"]

VARIABLE_RANGE = list(range(2, 11))


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
    rng = DeterministicRNG(seed).spawn("exp3_crossdomain")

    # Partition by the corpus's own domain field — real institutional
    # boundaries, not a synthetic split.
    by_domain: Dict[int, List[Record]] = defaultdict(list)
    for rec in records:
        by_domain[rec.dom].append(rec)
    available_domains = sorted(by_domain)

    actual_range = [d for d in VARIABLE_RANGE if d <= len(available_domains)]
    if not actual_range:
        actual_range = [len(available_domains)]
    if actual_range != VARIABLE_RANGE:
        print(
            f"  NOTE: corpus carries {len(available_domains)} domains; sweep "
            f"truncated to {actual_range}. README §4 forbids re-bucketing "
            f"records into a synthetic split to reach d=10 (open item, §14)."
        )

    level = max(1, (params.access_levels + 1) // 2)

    # ---- one independent deployment per domain. Untimed. ----
    domains: Dict[int, Dict[str, Any]] = {}
    for dom in available_domains:
        wl = build_workload(by_domain[dom], params)
        state, index, prooflist = peony_plus.setup(params)
        index_workload(state, index, prooflist, wl, variant)
        kws = select_keywords(
            wl.keyword_freq, rng, warmup + runs, total_records=wl.record_count
        )
        domains[dom] = {
            "state": state, "index": index, "workload": wl, "keywords": kws,
        }
        print(f"  domain {dom}: {len(by_domain[dom]):,} records, "
              f"{index.total_nodes:,} nodes")

    counter = {d: 0 for d in actual_range}

    def runner(d: int) -> RunResult:
        i = counter[d]
        counter[d] += 1
        targets = available_domains[:d]

        def federated():
            issued = 0
            merged: set = set()
            for dom in targets:
                ctx = domains[dom]
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

    results = run_experiment(actual_range, runner, runs=runs, warmup=warmup)

    exp_dir = output_dir / "exp3_crossdomain_scalability"
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    write_results(exp_dir / "results.csv",
                  aggregate_results(results, SECONDARY_NAMES))
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
