"""Exp. 9 — Verification Granularity under Tampering. Ref[55]/Peony++ arm.

Variable:  tampered records ``t`` = 1 -> 1000, at a PINNED result-set size
Primary:   records the client must discard
Secondary: usable records recovered, tampered records localised, latency (ms)

WHAT THIS MEASURES, AND WHY IT IS NOT A STRAWMAN
------------------------------------------------
Peony++'s ``Verify`` (§VI-A) recombines the published per-batch digests, folds in
the deletion digest, hashes the returned result set, and compares:

    XOR_c prooflist[pt^c_{w,l}]  (+)  proof_del   ==   XOR_{C_id in R} H(1, C_id)

That is multiset hashing, and it is exactly what makes the proof a single 32-byte
digest regardless of ``r`` -- the property Exp. 4 reports as an advantage. The
same property is what denies it granularity: the comparison is between two
digests, so a mismatch says the returned SET is wrong and nothing more. No
returned record can be named, and no subset can be re-verified, because a
prooflist entry commits to every file added at that level in that batch.

This is already stated in this scheme's own Exp. 4 runner: "verifying a truncated
subset is *supposed* to fail -- the XOR would not cancel". Exp. 9 does not
introduce that constraint; it measures what it costs.

MEASUREMENT BOUNDARY
--------------------
Identical to Exp. 4: the verification COMPUTATION, off-chain. The paper runs
``Verify`` in a Solidity contract on Ganache, the benchmark host runs no Ethereum
node, and gas is not latency. See ``References/Ref[55]/Ref[55].md`` §6.

BATCH COUNT
-----------
``c = 1``, for the same reason Exp. 4 pins it: with ``c > 1`` a keyword whose
files miss a level in some batch produces a prooflist entry covering files the
search cannot return, and Verify then fails for the CONSTRUCTION's reason rather
than the tamper's. Exp. 9 asks what a detected tamper costs, so it must be the
tamper that causes the failure.

THE TAMPER
----------
``t`` returned identifiers are replaced with identifiers outside the result set.
The digest folds ``H(1, C_id)`` per returned record, so the substitution is
caught by the algebra itself, not by any wrapper check.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Any, Dict, Sequence

from Dataset.corpus import Record

from ..src import peony_plus
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

EXPERIMENT_NAME = "exp9"
SECONDARY_NAMES = ["usable_recovered", "tampered_localised", "latency_ms"]

VARIABLE_RANGE = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000]

#: Pinned result-set size. Mirrors global.yaml's exp9 `held_constant` block --
#: all three schemes must discard from the same denominator or the figure
#: compares nothing.
RETURNED_RESULTS = 20_000


def run(
    params: SchemeParams,
    records: Sequence[Record],
    manifest: Dict[str, Any],
    output_dir: Path,
    *,
    runs: int = 10,
    warmup: int = 5,
    seed: int = 20260903,
    points: Optional[str] = None,
    variant: str = "peony_plus",
) -> None:
    if variant != "peony_plus":
        raise ValueError(
            "Exp. 9 requires peony_plus: Peony (§V) has no verification "
            "algorithm. Public verification is introduced by Peony++ (§VI-A)."
        )

    probe = build_workload(records, params)
    candidates = [
        kw for kw, n in probe.keyword_freq.most_common(50) if n >= 10
    ]
    if not candidates:
        raise RuntimeError("corpus produced no keyword with >= 10 matches")
    keyword = min(
        candidates,
        key=lambda kw: (abs(probe.keyword_freq[kw] - RETURNED_RESULTS), kw),
    )
    matching = [rec for rec in records if keyword in rec.kw]

    # The result set is GENUINE, never a slice: Peony++'s prooflist entry
    # commits to every file added at that level in that batch, so a truncated
    # set fails Verify with no tamper present. Building an index that actually
    # holds the records is the only honest way to fix the denominator.
    subset_records = matching[:RETURNED_RESULTS]
    wl = build_workload(subset_records, params, batch_count=1)
    state, index, prooflist = peony_plus.setup(params)
    index_workload(state, index, prooflist, wl, variant)

    present = {wl.level_of[rec.rid] for rec in subset_records}
    query_level = max(present)
    tok = peony_plus.token_gen(state, keyword, query_level, wl.batch_count)
    result_ids = sorted(peony_plus.search(state, tok, index, keyword).result_ids)
    returned = len(result_ids)
    batch_ids = state.keyword_batches.get(keyword, [])

    if returned != RETURNED_RESULTS:
        print(
            f"  NOTE: keyword {keyword!r} yields {returned} verified records "
            f"(nearest available to the pinned {RETURNED_RESULTS}). This arm "
            f"reports over {returned}; Section V must state the denominator "
            f"each arm actually used."
        )

    # Sanity: the untampered set must verify, or every number below is noise.
    clean = peony_plus.verify(
        state, prooflist, keyword, query_level, result_ids, batch_ids
    )
    if not clean.accepted:
        raise RuntimeError(
            "the untampered result set does not verify; the index, the level "
            "or the batch count is wrong and no tamper measurement is "
            "meaningful until it does"
        )

    outside = max(result_ids) + 1
    actual_range = [t for t in VARIABLE_RANGE if t <= returned]
    actual_range = sweep.select(actual_range, points)
    if not actual_range:
        actual_range = [min(VARIABLE_RANGE)]

    tampered_for_t: Dict[int, Any] = {}
    for t in actual_range:
        marked = sorted({(i * returned) // t for i in range(t)})
        ids = list(result_ids)
        for offset, position in enumerate(marked):
            # Substitute an identifier the result set does not contain, so the
            # multiset genuinely differs rather than two flips cancelling.
            ids[position] = outside + offset
        tampered_for_t[t] = (ids, len(marked))

    def runner(t: int) -> RunResult:
        ids, marked = tampered_for_t[t]
        elapsed_ms, outcome = measure_ns(
            lambda: peony_plus.verify(
                state, prooflist, keyword, query_level, ids, batch_ids
            )
        )
        if outcome.accepted:
            raise RuntimeError(
                f"t={t}: Verify accepted a result set with {marked} substituted "
                f"identifiers; the digest algebra is not detecting the tamper "
                f"and no number from this run means anything"
            )
        # All-or-nothing: a rejected response yields no usable record and names
        # none of the bad ones. Both are recorded as measurements rather than
        # asserted in prose.
        return RunResult(
            primary_metric=float(returned),
            secondary_metrics={
                "usable_recovered": 0.0,
                "tampered_localised": 0.0,
                "latency_ms": round(elapsed_ms, 6),
            },
        )

    results = run_experiment(actual_range, runner, runs=runs, warmup=warmup)

    exp_dir = sweep.shard_dir(
        output_dir / "exp9_verification_granularity", points
    )
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    aggregated = aggregate_results(results, SECONDARY_NAMES)
    write_results(exp_dir / "results.csv", aggregated)
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
