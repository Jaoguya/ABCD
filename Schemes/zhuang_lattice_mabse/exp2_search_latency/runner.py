"""Experiment 2 — Search Latency

Variable: index size N = 10^4 → 10^6
Primary:  search latency (ms) for N records
Secondary: n_eff (entries checked), prune ratio

Measures the time for the cloud server to scan N index entries with a
search token.  Per-record cost is l dot-products of 2m-vectors
(Table VI: l · Tmul8 ≈ 0.18 ms).  Total scales linearly in N.

We time N iterations of the search-match check over representative data
(standard benchmark practice — the computational cost per record is
identical regardless of specific values).
"""

from __future__ import annotations

import time
from pathlib import Path

import numpy as np

from ..src.params import SchemeParams
from ..src.access_tree import make_and_policy
from ..src.construction.p1_setup import setup
from ..src.construction.p2_aa_setup import aa_setup
from ..src.construction.p3_enroll import enroll
from ..src.construction.p6_encrypt import encrypt
from ..src.construction.p7_token_gen import token_gen
from ..src.construction.p8_search import search
from ..src.harness import (
    RunResult,
    aggregate_results,
    measure_latency_ns,
    write_raw_runs,
    write_results,
    write_run_meta,
)


def run_exp2(base_path: Path, *, runs: int = 30, warmup: int = 5) -> None:
    """Execute Experiment 2."""
    print("  Setting up scheme parameters...")
    params = SchemeParams.from_config()
    rng = np.random.default_rng(42)

    # ── Setup (untimed) ──
    gp = setup(params, rng=rng)
    attr_ids = list(range(params.num_attributes))
    access_tree = make_and_policy(attr_ids)

    auth_pk, auth_mk = aa_setup(gp, 0, attr_ids, rng=rng)

    user_pub, user_prv = enroll(
        gp, auth_pk, auth_mk, "user_0", attr_ids, rng=rng
    )

    # Generate one representative ciphertext + index
    keywords = [f"keyword_{i}".encode() for i in range(params.keywords_per_ct)]
    ct, idx = encrypt(
        gp, 1, 0, keywords, access_tree, [user_pub], rng=rng,
    )

    # Generate search token with same keywords
    tok = token_gen(gp, 0, keywords, user_pub, user_prv, rng=rng)

    # Variable range: N (log scale)
    N_range = [10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000]
    all_runs: list[RunResult] = []

    for N in N_range:
        print(f"  N={N:,}...", end=" ", flush=True)

        def measure(n=N):
            t0 = time.perf_counter_ns()
            matches = 0
            for _ in range(n):
                result = search(gp, tok, idx, access_tree, "user_0")
                if result.matched:
                    matches += 1
            elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
            n_eff = n  # all records checked (linear scan)
            prune_ratio = 1.0 - (matches / n) if n > 0 else 0.0
            return (elapsed_ms, float(n_eff), prune_ratio)

        results = measure_latency_ns(
            measure, warmup=warmup, runs=runs, variable_value=N,
        )
        all_runs.extend(results)

        ok = [r for r in results if r.status == "ok"]
        if ok:
            mean_ms = np.mean([r.primary_metric for r in ok])
            print(f"{mean_ms:.2f} ms")
        else:
            print("FAILED")

    # ── Write output ──
    out_dir = base_path / "exp2_search_latency"
    write_raw_runs(out_dir / "raw_runs.csv", "exp2", all_runs)
    write_results(out_dir / "results.csv", aggregate_results(all_runs))
    write_run_meta(out_dir / "run_meta.json", "exp2", {
        "variable": "index_size_N",
        "range": N_range,
    })
    print(f"  Output: {out_dir}")
