"""Exp. 1 — Trapdoor Generation Latency.

Variable:  keywords per query ``q`` = 1 → 20
Primary:   latency (ms)
Secondary: trapdoor size (bytes)

Measurement boundary (README §5, Exp. 1):
    Online trapdoor generation only.  Index construction and corpus
    loading are excluded.

For Guo, the "trapdoor" is the search token st = (st1, st2):
  st1 = (k_x_{v-1}, k_x_v, lcnt_x) — two F1 evaluations + Dict lookup
  st2 = 1 (conjunctive flag)

The token is generated for the LEAST FREQUENT keyword only; the other
keywords are resolved in the forward-index stage.  So the actual PRF
work is O(1) in q, but the Dict lookup to find the least-frequent term
is O(q).  Both are included because the entire client-side Algorithm 3
lines 1-13 constitute the trapdoor generation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

from Common.crypto.rng import DeterministicRNG
from Dataset.corpus import Record

from .harness import RunResult, measure_ns, run_experiment, write_raw_runs, aggregate_results, write_results, write_run_meta
from .scheme import GuoVDSSE

from infra import sweep


EXPERIMENT_NAME = "exp1"
SECONDARY_NAMES = ["trapdoor_size_bytes"]

# Records indexed to build the client keyword state. Not a sweep variable —
# trapdoor cost is independent of it (see run()). Matches
# exp3_crossdomain.DEFAULT_N.
DEFAULT_N = 100_000


def _build_keyword_universe(records: List[Record]) -> List[str]:
    """Collect all keywords from the corpus, sorted for reproducibility."""
    universe: set[str] = set()
    for rec in records:
        universe.update(rec.kw)
    return sorted(universe)


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
    """Run Experiment 1: Trapdoor Generation Latency."""
    # Setup — not timed, but it still has to FINISH.
    #
    # This indexed every record it was handed. Against the frozen corpus
    # (1.14M records) that is the same work as exp2's largest nested build —
    # measured at ~7.5h — for an experiment whose own runtime estimate is ~0h.
    # A campaign run against the real corpus never got past it (killed at 40
    # minutes with no output).
    #
    # Scoping it is sound rather than a shortcut: the measured operation is
    # `generate_search_token` (Alg. 3 lines 1-13), which is O(q) dictionary
    # lookups over the client's keyword state plus O(1) PRF work — the cost
    # does not depend on how many records are in the EDB, only on q, the swept
    # variable. The subset must merely be large enough to give a representative
    # keyword universe and non-empty `lcnt_w`. DEFAULT_N matches the convention
    # exp3_crossdomain.py already uses for the same reason.
    subset = records[: min(DEFAULT_N, len(records))]
    state, edb = scheme.setup()
    for rec in subset:
        scheme.update(state, edb, "add", rec.rid, rec.kw)

    # Build a pool of keywords to sample from
    kw_universe = _build_keyword_universe(subset)
    rng = DeterministicRNG(seed).spawn("exp1_trapdoor")

    # Variable: q = 1 to 20 (README §5)
    variable_range = list(range(1, 21))

    # Pre-select keyword sets for each q value — same set across all runs
    # to reduce variance from keyword selection.
    keyword_sets: Dict[int, List[List[str]]] = {}
    for q in variable_range:
        sets = []
        for _ in range(warmup + runs):
            selected = rng.choice(kw_universe, size=min(q, len(kw_universe)),
                                  replace=False)
            sets.append(selected)
        keyword_sets[q] = sets

    # Counters for which iteration we're on per q value
    iteration_counter: Dict[int, int] = {q: 0 for q in variable_range}

    def runner(q: int) -> RunResult:
        idx = iteration_counter[q]
        iteration_counter[q] += 1
        keywords = keyword_sets[q][idx]

        # Measure ONLY token generation (Alg. 3 lines 1-13)
        elapsed_ms, token = measure_ns(
            lambda: scheme.generate_search_token(state, keywords)
        )

        trapdoor_size = token.size_bytes if token is not None else 0

        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={"trapdoor_size_bytes": trapdoor_size},
        )

    sweep_values = sweep.select(variable_range, points)

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    # Write outputs
    exp_dir = sweep.shard_dir(output_dir / "exp1_trapdoor_generation", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    aggregated = aggregate_results(results, SECONDARY_NAMES)
    write_results(exp_dir / "results.csv", aggregated)
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
