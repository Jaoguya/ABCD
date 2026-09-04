"""Exp. 4 — Verification Overhead.

Variable:  returned records ``r`` = 10 → 1000
Primary:   latency (ms)
Secondary: proof size (KB), proof elements

Measurement boundary (README §5, Exp. 4):
    Client-side verification only.

For Guo, verification is the XOR-accumulated tag check from Algorithm 4
(Ref[35].txt:1152-1173), NOT Merkle proofs.  This is the scheme's OWN
verification mechanism as published:

  1. Recompute proof1 = F3(w||0) ⊕ F3(w||lcnt_w), then XOR in F3(id)
     for each returned id.
  2. Recompute proof2 = XOR of F3(id||data') for each forward-index entry.
  3. Compare with the proofs the server returned.

Verification is O(r): one F3 (HMAC-SHA256) evaluation per returned
document per proof.  Proof size is constant (two XOR tags sized by
crypto.yaml verification_tag_bits) and does NOT grow with r.

SCHEME.md Exp. 4: "Use this scheme's own verification mechanism as published."
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Any, Dict, List

from Common.crypto.rng import DeterministicRNG
from Common.timing import measure_ns_quiesced
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

EXPERIMENT_NAME = "exp4"
SECONDARY_NAMES = ["proof_size_kb", "proof_elements"]

# Variable range: returned records
VARIABLE_RANGE = [10, 20, 50, 100, 200, 500, 1000]

# README §6 default index size, matching exp3_crossdomain.DEFAULT_N.
DEFAULT_N = 100_000


def _find_keyword_with_count(
    records: List[Record], target_count: int
) -> str:
    """Find a keyword whose document frequency is closest to target_count.

    For Exp. 4 we need to control r (number of returned records) without
    artificially constructing the corpus.  We pick the keyword whose
    single-keyword result set is closest to the target.
    """
    from collections import Counter

    kw_counts: Counter[str] = Counter()
    for rec in records:
        kw_counts.update(rec.kw)

    # Sort by absolute distance to target, break ties by keyword name
    return min(
        kw_counts.keys(),
        key=lambda kw: (abs(kw_counts[kw] - target_count), kw),
    )


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
    """Run Experiment 4: Verification Overhead."""
    # Setup — not timed, and SCOPED to the README §6 default index size.
    #
    # This indexed the ENTIRE corpus (1,143,792 records). Guo's forward index
    # holds a t-punctured GGM key per document — 50.5 KB at the configured
    # 64-bit domain and corpus v4's 31.7 keywords/document — so the full corpus
    # is ~57.8 GB and was OOM-killed (rc=137) on the pinned 16 GiB host in both
    # the 2026-08-28 and 2026-08-29 campaigns.
    #
    # Exp. 4's variable is r, the number of RETURNED results (10..1000), not the
    # index size; §6 fixes index_size at 10^5 for every experiment that does not
    # sweep it. The subset only has to be large enough to contain a keyword
    # matching ~1000 documents, which it is by a wide margin — corpus v4
    # averages 31.7 keywords per record over a 2,023-keyword universe, so at
    # N = 10^5 the frequent keywords match tens of thousands of records.
    #
    # Same scoping `exp3_crossdomain` already applies via its own DEFAULT_N.
    subset = records[: min(DEFAULT_N, len(records))]
    state, edb = scheme.setup()
    for rec in subset:
        scheme.update(state, edb, "add", rec.rid, rec.kw)

    # For each target r, find a keyword that produces approximately r
    # results for a single-keyword search, then measure verification.
    records = subset          # keyword frequencies must match the index
    rng = DeterministicRNG(seed).spawn("exp4_verify")

    actual_range = [
        r for r in VARIABLE_RANGE if r <= len(records)
    ]
    actual_range = sweep.select(actual_range, points)
    if not actual_range:
        actual_range = [min(VARIABLE_RANGE)]

    # Pre-select keywords per target r — use single-keyword search so
    # r = |R'| (no conjunctive pruning).
    keywords_for_r: Dict[int, str] = {}
    for r in actual_range:
        keywords_for_r[r] = _find_keyword_with_count(records, r)

    # Pre-run each search to populate cache and get SearchResults
    # The search itself is NOT timed in Exp. 4.
    import copy
    search_results_for_r: Dict[int, Any] = {}
    # We need separate states for each r to avoid v_w interference
    states_for_r: Dict[int, Any] = {}

    # Build EDB once, then deepcopy for each r — avoids rebuilding 7x
    base_state, base_edb = state, edb
    for r in actual_range:
        kw = keywords_for_r[r]
        s = copy.deepcopy(base_state)
        e = copy.deepcopy(base_edb)
        sr = scheme.search(s, e, [kw])
        search_results_for_r[r] = sr
        states_for_r[r] = s

    iteration_counter: Dict[int, int] = {r: 0 for r in actual_range}

    def runner(r: int) -> RunResult:
        iteration_counter[r] += 1
        kw = keywords_for_r[r]
        sr = search_results_for_r[r]
        s = states_for_r[r]

        # Measure ONLY verify() — Alg. 4
        # Collector paused across the region (Common/timing.py): a gen-2 pause
        # landing inside one run of an Exp. 4 point is ~17 ms against a
        # single-digit-ms measurement. Exp. 4's four call sites use this; the
        # shared measure_ns does NOT, so Exp. 1/2/3/5 are unaffected.
        elapsed_ms, accept = measure_ns_quiesced(
            lambda: scheme.verify(s, kw, sr)
        )

        # Proof size: two vtag-byte tags (from crypto.yaml verification_tag_bits)
        proof_size_bytes = len(sr.proof_inverted)
        zero_proof = b"\x00" * len(sr.proof_forward)
        if sr.proof_forward and sr.proof_forward != zero_proof:
            proof_size_bytes += len(sr.proof_forward)
        proof_size_kb = proof_size_bytes / 1024.0

        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "proof_size_kb": round(proof_size_kb, 6),
                "proof_elements": len(sr.forward_data),
            },
        )

    sweep_values = actual_range

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    # Write outputs
    exp_dir = sweep.shard_dir(output_dir / "exp4_verification_overhead", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    aggregated = aggregate_results(results, SECONDARY_NAMES)
    write_results(exp_dir / "results.csv", aggregated)
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
