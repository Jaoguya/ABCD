"""Experiment 1 — Trapdoor Generation Latency

Variable: keywords per query q = 1 → 20
Primary:  TokenGen latency (ms)
Secondary: token size (bytes)

Measures the time to generate a search token (TokenGen, §III.G) as the
number of search keywords varies.  TokenGen involves:
    • Bloom filter construction over q keywords
    • l SampleLeft calls (one per held attribute)

The SampleLeft cost dominates and is independent of q, so the curve should
be roughly flat — this scheme's token generation does not scale with keyword
count.  The Bloom filter hashing is O(q) but negligible.
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
from ..src.construction.p7_token_gen import token_gen
from ..src.harness import (
    RunResult,
    aggregate_results,
    measure_latency_ns,
    write_raw_runs,
    write_results,
    write_run_meta,
)


def run_exp1(base_path: Path, *, runs: int = 30, warmup: int = 5) -> None:
    """Execute Experiment 1."""
    print("  Setting up scheme parameters...")
    params = SchemeParams.from_config()
    rng = np.random.default_rng(42)

    # ── Setup (untimed) ──
    gp = setup(params, rng=rng)
    attr_ids = list(range(params.num_attributes))
    access_tree = make_and_policy(attr_ids)

    # One authority managing all attributes
    auth_pk, auth_mk = aa_setup(gp, 0, attr_ids, rng=rng)

    # Enroll one user with all attributes
    user_pub, user_prv = enroll(
        gp, auth_pk, auth_mk, "user_0", attr_ids, rng=rng
    )

    # Variable range: q = 1..20
    q_range = list(range(1, 21))
    all_runs: list[RunResult] = []

    for q_val in q_range:
        print(f"  q={q_val}...", end=" ", flush=True)

        # Generate q keywords
        keywords = [f"keyword_{i}".encode() for i in range(q_val)]

        def measure():
            t0 = time.perf_counter_ns()
            tok = token_gen(
                gp, 0, keywords, user_pub, user_prv,
                rng=np.random.default_rng(),
            )
            elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
            return (elapsed_ms, tok.size_bytes)

        results = measure_latency_ns(
            measure, warmup=warmup, runs=runs, variable_value=q_val,
        )
        all_runs.extend(results)

        ok = [r for r in results if r.status == "ok"]
        if ok:
            mean_ms = np.mean([r.primary_metric for r in ok])
            print(f"{mean_ms:.2f} ms")
        else:
            print("FAILED")

    # ── Write output ──
    out_dir = base_path / "exp1_trapdoor_generation"
    write_raw_runs(out_dir / "raw_runs.csv", "exp1", all_runs)
    write_results(out_dir / "results.csv", aggregate_results(all_runs))
    write_run_meta(out_dir / "run_meta.json", "exp1", {
        "variable": "keywords_per_query",
        "range": q_range,
        "perturbation_mode": "spherical",
    })
    print(f"  Output: {out_dir}")
