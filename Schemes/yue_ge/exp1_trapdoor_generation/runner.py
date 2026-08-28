"""Exp. 1 — Trapdoor Generation Latency. Ref[55] §V-D / §VI-A Search.

Variable:  keywords per query ``q`` = 1 -> 20 (README §5)
Primary:   token generation latency (ms)
Secondary: token size (bytes), tokens issued

What is being measured
----------------------
Everything that must happen before a query can be sent to the server:

  Peony      ``tk_{w,a(u)} <- F.Cons(k_{a(u)}, w)`` plus the state list ``ST``
             (Algorithm 1, Search lines 1-2). One constrained-PRF evaluation.

  Peony++    the same, plus the data owner's assistance: ``MSRE.KLRev`` to
             produce the revoked key ``sk_{R_l}`` and the deletion filter
             ``B_{w,a(u)}`` (§VI-A Search). The paper is explicit that the owner
             is in this path and lists removing it as future work (§IX), so
             excluding it would measure a scheme the paper does not describe.

NATIVE MODE — why q tokens
--------------------------
Peony and Peony++ are **single-keyword**: ``Search(k_{a(u)}, w, c; I)`` takes
one ``w``, and the paper never defines a conjunctive form. A ``q``-keyword query
therefore runs as ``q`` independent tokens with client-side intersection — the
same native-mode rule README §3 applies to Exp. 3, and the treatment
``thingom_pq_abse`` already uses for Ref[41].

So the curve is expected to rise linearly in ``q``, unlike a scheme with native
conjunctive trapdoors. That linearity is the finding, not an artifact.

The paper's own figure for the data user alone is 0.95 us, constant (§VII-B);
our number is larger because it includes the owner-side revocation work that
0.95 us excludes.
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

EXPERIMENT_NAME = "exp1"
SECONDARY_NAMES = ["token_size_bytes", "tokens_issued"]

# README §5: keywords per query q = 1 -> 20
VARIABLE_RANGE = list(range(1, 21))

# Index size held at the README §6 default. Exp. 1 sweeps q and holds every
# other parameter at its default (README §5), and global.yaml declares
# defaults.index_size: 100000 -- so this is the specified value for a
# non-swept parameter, not a convenience cut. guo_vdsse/exp1_trapdoor.py
# pins the same 10^5 for the same reason.
DEFAULT_N = 100_000

# README §6 default: queries are issued by a mid-level user. Level |L| would see
# every file and level 1 almost none; the middle level exercises the linked-list
# walk without degenerating either way.
def _query_level(params: SchemeParams) -> int:
    return max(1, (params.access_levels + 1) // 2)


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
    rng = DeterministicRNG(seed).spawn("exp1_trapdoor")

    # ---- setup, not timed, but it still has to FINISH ----
    #
    # Scoped to DEFAULT_N (README §6 default index size) rather than the whole
    # corpus. Indexing every record makes index_workload() run MSRE.enc -- a
    # PRF evaluation per (keyword, document) pair -- across all 1.14M records,
    # the same work as exp2's largest nested build, in an experiment that does
    # not sweep index size. Measured: a --runs 2 invocation sat at 100% CPU for
    # 13 minutes without emitting a point, stuck in prf.eval under
    # peony_plus.add.
    #
    # This does NOT weaken the baseline. token_gen() (peony.py:315) costs one
    # f_cons() plus batch_count state derivations, and batch_count is
    # params.update_batches_c = 4 from crypto.yaml -- a fixed constant, NOT a
    # function of len(records) (workload.py:59). So the measured quantity is
    # invariant to this scoping; only the untimed setup shrinks. The subset
    # still has to supply max(VARIABLE_RANGE) distinct keywords with genuine
    # matches, which select_keywords() enforces against workload.keyword_freq.
    # Same fix as guo_vdsse/exp1_trapdoor.py, for the identical defect.
    workload = build_workload(records[: min(DEFAULT_N, len(records))], params)
    state, index, prooflist = peony_plus.setup(params)
    index_workload(state, index, prooflist, workload, variant)

    level = _query_level(params)
    batch_count = workload.batch_count

    # Enough distinct keywords for the widest query, drawn from the real corpus.
    pool = select_keywords(
        workload.keyword_freq, rng, max(VARIABLE_RANGE),
        total_records=workload.record_count,
    )
    if not pool:
        raise RuntimeError("corpus produced no eligible query keywords")

    # Deletions must exist before MSRE.KLRev does any real work — otherwise the
    # revocation filter is empty and the owner-side cost is not representative
    # of a scheme that has been running. Delete the configured d entries.
    if variant == "peony_plus":
        n_del = seed_deletions(state, workload, pool, params)
        print(f"  seeded {n_del:,} deletions across {len(pool)} keywords "
              f"(BF still sized at published d={params.deletions_between_searches})")

    def runner(q: int) -> RunResult:
        keywords = [pool[i % len(pool)] for i in range(q)]

        if variant == "peony":
            def gen() -> List[Any]:
                return [
                    peony.token_gen(state.key, kw, level, batch_count)
                    for kw in keywords
                ]
        else:
            def gen() -> List[Any]:
                return [
                    peony_plus.token_gen(state, kw, level, batch_count)
                    for kw in keywords
                ]

        elapsed_ms, tokens = measure_ns(gen)
        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "token_size_bytes": sum(t.size_bytes for t in tokens),
                "tokens_issued": len(tokens),
            },
        )

    results = run_experiment(VARIABLE_RANGE, runner, runs=runs, warmup=warmup)

    exp_dir = output_dir / "exp1_trapdoor_generation"
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    write_results(exp_dir / "results.csv",
                  aggregate_results(results, SECONDARY_NAMES))
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
