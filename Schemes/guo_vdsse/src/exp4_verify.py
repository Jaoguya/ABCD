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
    # Setup — not timed
    state, edb = scheme.setup()
    for rec in records:
        scheme.update(state, edb, "add", rec.rid, rec.kw)

    # For each target r, find a keyword that produces approximately r
    # results for a single-keyword search, then measure verification.
    rng = DeterministicRNG(seed).spawn("exp4_verify")

    actual_range = [
        r for r in VARIABLE_RANGE if r <= len(records)
    ]
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
        elapsed_ms, accept = measure_ns(
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

    sweep_values = sweep.select(actual_range, points)

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    # Write outputs
    exp_dir = sweep.shard_dir(output_dir / "exp4_verification_overhead", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    aggregated = aggregate_results(results, SECONDARY_NAMES)
    write_results(exp_dir / "results.csv", aggregated)
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
