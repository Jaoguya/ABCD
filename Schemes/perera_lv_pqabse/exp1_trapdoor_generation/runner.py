"""Exp. 1 — Trapdoor Generation Latency. Ref[54].

Variable:  keywords per query ``q`` = 1 -> 20 (README §5)
Primary:   trapdoor generation latency (ms)
Secondary: trapdoor size (B), PRF evaluations

WHAT IS TIMED, AND WHY THE SIGNATURE IS IN IT
---------------------------------------------
Ref[54]'s trapdoor is a *signed* PRF token set (Phase 4): ``q`` PRF evaluations
plus one Dilithium3 signature. Both are timed, because ``FogNode.search``
verifies that signature and refuses an unsigned trapdoor — reporting only the
PRF half would report a trapdoor the scheme itself would reject.

That shape is the paper's own headline claim (Table II: ``O(n + T_PRF)``, "no
lattice sampling at query time"), so the expected curve is a shallow line in
``q`` sitting on a constant signature cost, not a lattice-dominated one.

ML-KEM encapsulation is EXCLUDED, per README §5's Exp. 1 boundary: it happens
once at session establishment, not per query. ``main.py`` reports it separately.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Any, Dict, Sequence

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
from ..src.workload import keyword_frequency, select_keywords

from infra import sweep

EXPERIMENT_NAME = "exp1"
SECONDARY_NAMES = ["trapdoor_size_bytes", "prf_evaluations"]

# Superset of global.yaml's [1, 5, 10, 15, 20], matching guo_vdsse and yue_ge.
VARIABLE_RANGE = list(range(1, 21))

# README §6 default index size. Exp. 1 does not search, so this only has to be
# large enough to draw realistic query keywords from.
INDEX_SIZE = 100_000


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
    rng = DeterministicRNG(seed).spawn("exp1_trapdoor")
    subset = list(records[: min(INDEX_SIZE, len(records))])

    keys = scheme.setup(params, with_abe=False)
    freq = keyword_frequency(subset)

    pools: Dict[int, list] = {}
    for q in VARIABLE_RANGE:
        pools[q] = [
            select_keywords(freq, rng, q) for _ in range(warmup + runs)
        ]
        if not pools[q][0]:
            raise RuntimeError(f"no eligible query keywords at q={q}")

    counter = {q: 0 for q in VARIABLE_RANGE}

    def runner(q: int) -> RunResult:
        i = counter[q]
        counter[q] += 1
        keywords = pools[q][i % len(pools[q])]

        elapsed_ms, td = measure_ns(lambda: scheme.trapdoor(keys, keywords))
        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "trapdoor_size_bytes": td.size_bytes,
                "prf_evaluations": len(td.tokens),
            },
        )

    sweep_values = sweep.select(VARIABLE_RANGE, points)

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    exp_dir = sweep.shard_dir(output_dir / "exp1_trapdoor_generation", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    write_results(exp_dir / "results.csv",
                  aggregate_results(results, SECONDARY_NAMES))
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
