"""Experiment 5 — Dynamic Keyword Update

Variable: (keyword, document) pairs k = 10^2 → 10^5
Primary:  update latency (ms)
Secondary: entries rewritten

Measures the time for incremental keyword updates.  For this scheme,
updating a keyword index entry requires re-encrypting the affected
index components (Eq. 3 and 4 from §III.F) for the updated keywords.

Per SCHEME.md: "Incremental keyword update" — the scheme re-encrypts
only the changed (keyword, document) pairs rather than rebuilding the
entire index.
"""

from __future__ import annotations

import time
from pathlib import Path

import numpy as np

from Common.crypto.bloom import BloomFilter
from Common.crypto.lattice import mod_q, sample_discrete_gaussian, sample_uniform_zq

from ..src.params import SchemeParams, H0_cached
from ..src.access_tree import make_and_policy
from ..src.construction.p1_setup import setup
from ..src.construction.p2_aa_setup import aa_setup
from ..src.construction.p3_enroll import enroll
from ..src.harness import (
    RunResult,
    aggregate_results,
    measure_latency_ns,
    write_raw_runs,
    write_results,
    write_run_meta,
)


def run_exp5(base_path: Path, *, runs: int = 30, warmup: int = 5) -> None:
    """Execute Experiment 5."""
    print("  Setting up scheme parameters...")
    params = SchemeParams.from_config()
    rng = np.random.default_rng(42)

    # ── Setup (untimed) ──
    gp = setup(params, rng=rng)
    attr_ids = list(range(params.num_attributes))

    auth_pk, auth_mk = aa_setup(gp, 0, attr_ids, rng=rng)
    user_pub, user_prv = enroll(
        gp, auth_pk, auth_mk, "user_0", attr_ids, rng=rng
    )

    lp = params.lattice
    q, n, m = lp.q, lp.n, lp.m
    sigma = lp.sigma
    half_q = q // 2

    # Pre-compute K = H_0(0)
    K = H0_cached(0, lp)

    # Variable range: k (log scale)
    k_range = [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000]
    all_runs: list[RunResult] = []

    for k_val in k_range:
        print(f"  k={k_val:,}...", end=" ", flush=True)

        def measure(num_pairs=k_val):
            """Time incremental update of num_pairs (keyword, doc) entries.

            Each update re-encrypts one index entry:
                • Rebuild the Bloom filter for the updated keyword set
                • Recompute I_{1,θ} scalars (Eq. 3)
                • Recompute I^ID_{d,i} vectors for one (user, attr) pair (Eq. 4)

            This is the per-entry incremental cost, multiplied by num_pairs.
            """
            local_rng = np.random.default_rng()

            # Pre-generate representative data for one update
            s2 = sample_uniform_zq((n,), q, rng=local_rng)
            r = int(local_rng.integers(0, q))
            u_dot_s2 = int(np.sum(gp.u_vector * s2) % q)

            # One B matrix for the update computation
            B_sample = user_pub.B_matrices.get((0, 0))
            if B_sample is None:
                return (0.0, 0.0)

            t0 = time.perf_counter_ns()

            entries_rewritten = 0
            for _ in range(num_pairs):
                # Bloom filter rebuild for one keyword change
                bf = BloomFilter(
                    array_bits=params.bloom_array_bits,
                    num_hashes=params.bloom_num_hashes,
                )
                bf.add(b"updated_keyword")
                w = np.array(
                    [(bf.bits >> i) & 1 for i in range(params.bloom_array_bits)],
                    dtype=np.int64,
                )

                # Eq. 3: I_{1,θ} = u^T s2 · r + w_θ⌊q/2⌋ + x_l
                x_l = int(sample_discrete_gaussian(1, sigma, rng=local_rng)[0])
                bloom_scalars = mod_q(
                    np.full(params.bloom_array_bits, u_dot_s2 * r, dtype=np.int64)
                    + w * half_q + x_l,
                    q,
                )

                # Eq. 4: one I^ID_{d,i} = [B|K]^T s2 · r_i + x2
                x2 = sample_discrete_gaussian(2 * m, sigma, rng=local_rng)
                BK_t_s2 = mod_q(
                    np.concatenate([B_sample.T @ s2, K.T @ s2]) * r,
                    q,
                )
                idx_vec = mod_q(BK_t_s2 + x2, q)

                entries_rewritten += 1

            elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
            return (elapsed_ms, float(entries_rewritten))

        results = measure_latency_ns(
            measure, warmup=warmup, runs=runs, variable_value=k_val,
        )
        all_runs.extend(results)

        ok = [r for r in results if r.status == "ok"]
        if ok:
            mean_ms = np.mean([r.primary_metric for r in ok])
            print(f"{mean_ms:.2f} ms")
        else:
            print("FAILED")

    # ── Write output ──
    out_dir = base_path / "exp5_keyword_update"
    write_raw_runs(out_dir / "raw_runs.csv", "exp5", all_runs)
    write_results(out_dir / "results.csv", aggregate_results(all_runs))
    write_run_meta(out_dir / "run_meta.json", "exp5", {
        "variable": "keyword_doc_pairs_k",
        "range": k_range,
    })
    print(f"  Output: {out_dir}")
