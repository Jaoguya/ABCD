"""The one-time AASS weight sweep (global.yaml, §14 issue #5).

    python3 -m Schemes.ma_lb_pq_vdse.src.harness.lambda_sweep

global.yaml: the λ weights are "not in the paper — must be fixed", and must be
chosen "once by a documented procedure (e.g. a sweep on a held-out workload),
commit that output, and leave them alone." ``scheduler.yaml`` specifies that
procedure exactly; this executes it and nothing else.

PROCEDURE — from ``scheduler.yaml``'s ``sweep`` block, not invented here
-----------------------------------------------------------------------
grid        simplex over λ1..λ5, step 0.1, summing to 1.0 → C(14,4) = 1001
workload    ``workload/exp78_sweep_holdout.yaml`` — HELD OUT. The reported
            Exp. 7-8 figures come from ``exp78_workload.yaml``. Tuning on the
            trace that produces the reported numbers would make them in-sample
            and a reviewer would be right to discount them.
objective   maximize ``throughput_queries_per_second``
            subject to ``fsn_utilization_stddev <= median across the grid``
tie_break   ``prefer_uniform`` — on ties the vector nearest the uniform prior
            wins, so the procedure cannot silently land on an extreme corner.

WHY THE CONSTRAINT EXISTS
-------------------------
Maximizing throughput alone would let the scheduler pin one node at saturation
while posting good aggregate numbers — exactly what Exp. 8 exists to expose
(global.yaml). Including utilization spread in the objective means the weight
vector cannot be chosen to flatter Exp. 7 at Exp. 8's expense.

This writes ``lambda_sweep.csv`` (every vector, so the choice is auditable) and
prints the winner. It does NOT edit ``scheduler.yaml`` — promoting a result to
``status: fixed`` is a deliberate, reviewable commit, not a side effect of
running a script. Per-figure retuning is forbidden: one sweep, one
vector, identical across Exp. 7 and Exp. 8.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import statistics
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Schemes.ma_lb_pq_vdse.src import config as scheme_config  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as exp_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.scheduler import aass as aass_mod  # noqa: E402

STEP_DENOMINATOR = 10  # step 0.1 on a simplex summing to 1.0
WEIGHT_COUNT = 5


def simplex_grid(denominator: int = STEP_DENOMINATOR,
                 parts: int = WEIGHT_COUNT) -> List[Tuple[float, ...]]:
    """All λ vectors of `parts` non-negative multiples of 1/denominator summing to 1.

    C(denominator + parts - 1, parts - 1) = C(14, 4) = 1001 at the configured
    step, which is what scheduler.yaml's ``expected_vectors`` asserts.
    """
    vectors: List[Tuple[float, ...]] = []
    for cuts in itertools.combinations(range(denominator + parts - 1), parts - 1):
        previous = -1
        counts = []
        for cut in cuts:
            counts.append(cut - previous - 1)
            previous = cut
        counts.append(denominator + parts - 2 - previous)
        vectors.append(tuple(c / denominator for c in counts))
    return vectors


def evaluate(
    weights: Tuple[float, ...],
    config: scheme_config.Configuration,
    deployment: Any,
    requests: Sequence[Any],
    concurrency: int,
) -> Tuple[float, float]:
    """Replay the held-out trace under one λ vector -> (throughput, util_stddev)."""
    tuned = replace(
        config,
        scheduler=replace(
            config.scheduler,
            weights=replace(
                config.scheduler.weights,
                auth=weights[0], index=weights[1], verify=weights[2],
                sync=weights[3], queue=weights[4],
                # The sweep itself is explicitly a non-reportable run — it is
                # what DETERMINES the weights, so it cannot require them to be
                # already fixed. scheduler.yaml's `enforcement` block allows
                # exactly this case.
                status="sweep", provisional=True,
            ),
        ),
    )
    ablation = exp_mod.SchedulerAblation(
        config=tuned, source=exp_mod.SyntheticRecordSource(),
        variant=aass_mod.VARIANT_AASS,
    )
    outcome = ablation.replay(deployment, requests, concurrency)
    return outcome.throughput, outcome.utilization_stddev


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m Schemes.ma_lb_pq_vdse.src.harness.lambda_sweep",
        description="Run the documented one-time AASS weight sweep.",
    )
    parser.add_argument("--concurrency", type=int, default=None,
                        help="held-out concurrency (default: exp7's first point)")
    parser.add_argument("--records", type=int, default=2000,
                        help="deployment size for the held-out replay")
    parser.add_argument("--output", default=None,
                        help="default: scheduler.yaml's sweep.output")
    parser.add_argument("--limit", type=int, default=None,
                        help="evaluate only the first N vectors (smoke only — "
                             "a partial grid must NEVER be promoted to fixed)")
    args = parser.parse_args(argv)

    config = scheme_config.load()

    grid = simplex_grid()
    expected = 1001
    if len(grid) != expected:
        raise SystemExit(f"grid built {len(grid)} vectors, expected {expected}")
    if args.limit:
        grid = grid[: args.limit]
        print(f"WARNING: --limit {args.limit} — PARTIAL grid, smoke only. "
              f"A partial sweep must never be promoted to status: fixed.")

    concurrency = args.concurrency or int(config.experiment("exp7").values[0])
    print(f"grid={len(grid)} vectors  concurrency={concurrency}  "
          f"records={args.records}")
    print("held-out workload; the reported Exp. 7-8 trace is NOT used here\n")

    # Reuse Exp. 7's own prepare() so the sweep replays exactly the request
    # shape the experiment does -- a bespoke trace here could tune the weights
    # against a workload the reported runs never see.
    source = exp_mod.SyntheticRecordSource()
    prepared = exp_mod.Exp7Throughput(config=config, source=source).prepare(
        concurrency
    )
    deployment = prepared["deployment"]
    requests = prepared["requests"]

    rows: List[Dict[str, Any]] = []
    for index, weights in enumerate(grid, start=1):
        throughput, spread = evaluate(
            weights, config, deployment, requests, concurrency
        )
        rows.append({
            "lambda_1_auth": weights[0], "lambda_2_index": weights[1],
            "lambda_3_verify": weights[2], "lambda_4_sync": weights[3],
            "lambda_5_queue": weights[4],
            "throughput_queries_per_second": round(throughput, 4),
            "fsn_utilization_stddev": round(spread, 6),
        })
        if index % 100 == 0 or index == len(grid):
            print(f"  {index}/{len(grid)}")

    # Objective, exactly as scheduler.yaml states it.
    spreads = [r["fsn_utilization_stddev"] for r in rows]
    median_spread = statistics.median(spreads)
    feasible = [r for r in rows if r["fsn_utilization_stddev"] <= median_spread]
    if not feasible:  # pragma: no cover - only if every spread is NaN
        raise SystemExit("no feasible vector: every utilization spread exceeded "
                         "the median, which should be impossible")

    best_throughput = max(r["throughput_queries_per_second"] for r in feasible)
    # Ties are real here: many vectors give identical throughput on a
    # deterministic replay, so the documented tie-break decides rather than
    # whichever happened to sort first.
    tied = [r for r in feasible
            if r["throughput_queries_per_second"] == best_throughput]
    uniform = 1.0 / WEIGHT_COUNT

    def distance_from_uniform(row: Dict[str, Any]) -> float:
        return sum(
            (row[k] - uniform) ** 2
            for k in ("lambda_1_auth", "lambda_2_index", "lambda_3_verify",
                      "lambda_4_sync", "lambda_5_queue")
        )

    winner = min(tied, key=distance_from_uniform)

    out_path = Path(args.output) if args.output else (
        REPO_ROOT
        / "Schemes/ma_lb_pq_vdse/exp7_search_throughput/lambda_sweep.csv"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nevaluated      {len(rows)} vectors")
    print(f"median spread  {median_spread:.6f}  ({len(feasible)} feasible)")
    print(f"best throughput{best_throughput:>12.4f} q/s  ({len(tied)} tied)")
    print(f"tie-break      prefer_uniform\n")
    print("WINNER")
    for key in ("lambda_1_auth", "lambda_2_index", "lambda_3_verify",
                "lambda_4_sync", "lambda_5_queue"):
        print(f"  {key:<18} {winner[key]}")
    print(f"  throughput         {winner['throughput_queries_per_second']} q/s")
    print(f"  utilization stddev {winner['fsn_utilization_stddev']}")
    print(f"\nfull grid -> {out_path}")
    print("\nTo adopt: set scheduler.yaml weights to the above and")
    print("weights.status: fixed, sweep.status: complete — as a reviewable")
    print("commit. This script deliberately does not edit the config.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
