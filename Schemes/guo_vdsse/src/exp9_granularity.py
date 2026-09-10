"""Exp. 9 — Verification Granularity under Tampering. Ref[35] arm.

Variable:  tampered records ``t`` = 1 -> 1000, at a PINNED result-set size
           (``global.yaml``: ``exp9_verification_granularity.held_constant.
           returned_results``)
Primary:   records the client must discard
Secondary: usable records recovered, tampered records localised, latency (ms)

WHAT THIS MEASURES, AND WHY IT IS NOT A STRAWMAN
------------------------------------------------
Alg. 4 (`Ref[35].txt:1152-1173`) checks TWO XOR-accumulated tags computed over
the COMPLETE result set:

    proof1 = F3(w||0) (+) F3(w||lcnt_w) (+) XOR_{id in R''} F3(id)
    proof2 =                              XOR_{(id,data') in R''} F3(id||data')

and returns ONE boolean. Nothing in the construction identifies WHICH returned
document broke the accumulator, and a subset of ``R''`` does not balance against
the published tags -- the ``F3(w||0) (+) F3(w||lcnt_w)`` prefix cancels only once
every id in the set has been folded in. So a client that detects tampering can
only reject the whole response.

That is a property of the PUBLISHED scheme, not of this implementation, and it
is not a weakness the paper hides -- Ref[35] never claims per-record
identification. Bisecting to localise the fault would need the server to issue
fresh proofs per sub-batch, which Alg. 3 does not define. `scheme.py` is used
here EXACTLY as Exp. 4 uses it; the only thing this experiment adds is the
tamper and the accounting of what a failure costs.

Exp. 4 rule: use this scheme's own verification mechanism as published.
The same rule governs here.

THE TAMPER
----------
One returned document identifier is altered in ``forward_data``. The id is what
both accumulators fold in, so the alteration is detected by ``verify`` rather
than by a parse error -- the same class of tamper the proposed scheme's arm
applies to an index entry.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Any, Dict, List

from Dataset.corpus import Record

from .harness import (
    RunResult,
    aggregate_results,
    measure_ns,
    run_experiment,
    write_raw_runs,
    write_results,
    write_run_meta,
)
from .scheme import GuoVDSSE

from infra import sweep

EXPERIMENT_NAME = "exp9"
SECONDARY_NAMES = ["usable_recovered", "tampered_localised", "latency_ms"]

VARIABLE_RANGE = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000]

#: Pinned result-set size. Mirrors global.yaml's exp9 `held_constant` block --
#: all three schemes must discard from the same denominator or the figure
#: compares nothing.
RETURNED_RESULTS = 20_000

#: Index size. HELD at exp4's 10^5 and not raised, for a hard memory reason:
#: Guo's forward index stores a t-punctured GGM key per document -- ~50.5 KB at
#: the configured 64-bit domain and corpus v4's 31.7 keywords/document. That is
#: ~5 GB at 10^5 and ~15 GB at 3x10^5, against 16 GiB on m6i.xlarge; indexing
#: the full corpus was OOM-killed (rc=137) twice for exactly this reason, and
#: exp4_verify.py carries the same cap and the same note.
#:
#: The cost is that the pinned RETURNED_RESULTS may not be reachable here. That
#: is reported, never papered over -- see the NOTE in `run`. If this arm cannot
#: reach the pinned size, the honest fix is to re-pin all three schemes to the
#: smallest denominator any of them can reach, not to raise this number.
DEFAULT_N = 100_000


def _keyword_nearest(records: List[Record], target: int) -> tuple[str, int]:
    """The keyword whose result set is closest to ``target``, and its size.

    The GENUINE size is returned and used as the denominator. It is never
    truncated to ``target``: proof1 folds in ``F3(w||0) (+) F3(w||lcnt_w)``,
    which cancels only once EVERY id in the result set has been XORed, so a
    truncated set fails Alg. 4 with no tamper present at all. Verifying a slice
    would measure that artefact instead of the tamper, and would look like
    evidence for exactly the claim this experiment makes.
    """
    from collections import Counter

    counts: Counter[str] = Counter()
    for rec in records:
        counts.update(rec.kw)
    keyword = min(
        counts, key=lambda kw: (abs(counts[kw] - target), kw)
    )
    return keyword, counts[keyword]


def run(
    scheme: GuoVDSSE,
    records: List[Record],
    manifest: Dict[str, Any],
    output_dir: Path,
    *,
    runs: int = 10,
    warmup: int = 5,
    seed: int = 20260903,
    points: Optional[str] = None,
) -> None:
    """Run Experiment 9: verification granularity under tampering."""
    import copy

    subset = records[: min(DEFAULT_N, len(records))]
    state, edb = scheme.setup()
    for rec in subset:
        scheme.update(state, edb, "add", rec.rid, rec.kw)

    keyword, available = _keyword_nearest(subset, RETURNED_RESULTS)

    # The state that RAN the search is the state that must VERIFY it: search
    # advances v_w, and Alg. 4 reads lcnt_w from the client state.
    search_state = copy.deepcopy(state)
    search_result = scheme.search(search_state, copy.deepcopy(edb), [keyword])
    forward = list(search_result.forward_data)
    returned = len(forward)
    if returned != RETURNED_RESULTS:
        # The denominator IS the headline number, so a different one travels
        # with the result rather than being quietly normalised away.
        print(
            f"  NOTE: keyword {keyword!r} returns {returned} documents at "
            f"N={len(subset)} (nearest available to the pinned "
            f"{RETURNED_RESULTS}). This arm reports over {returned}; Section V "
            f"must state the denominator each arm actually used."
        )

    actual_range = [t for t in VARIABLE_RANGE if t <= returned]
    actual_range = sweep.select(actual_range, points)
    if not actual_range:
        actual_range = [min(VARIABLE_RANGE)]

    # One tampered result set per sweep point, built once and reused across
    # runs: constructing it is the adversary's work, not the client's.
    tampered_for_t: Dict[int, Any] = {}
    for t in actual_range:
        marked = sorted({(i * returned) // t for i in range(t)})
        rows = list(forward)
        for index in marked:
            doc_id, data_fwd = rows[index]
            # Flip the identifier. Both accumulators fold F3(id), so this is
            # detected by Alg. 4 itself rather than by any wrapper check.
            rows[index] = (doc_id ^ 0x1, data_fwd)
        result = copy.copy(search_result)
        result.forward_data = rows
        tampered_for_t[t] = (result, len(marked))

    def runner(t: int) -> RunResult:
        result, marked = tampered_for_t[t]
        elapsed_ms, accepted = measure_ns(
            lambda: scheme.verify(search_state, keyword, result)
        )
        if accepted:
            raise RuntimeError(
                f"t={t}: Alg. 4 accepted a result set with {marked} tampered "
                f"identifiers; the accumulator is not detecting the tamper and "
                f"no number from this run means anything"
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
