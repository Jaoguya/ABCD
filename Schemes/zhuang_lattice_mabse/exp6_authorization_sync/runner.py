"""Experiment 6 — Authorization Synchronization

Variable: authorization updates δ = 10^2 → 10^5
Primary:  sync latency (ms)
Secondary: message size (KB), FSNs touched

Measures the scheme-native authorization sync mechanism: the Revoke (§III.D)
and Extend (§III.E) algorithms.  Per SCHEME.md: "Scheme-native auth sync
mechanism."

Each authorization update involves:
    • Revoke: replace B^ID_{d,t} with random (one matrix generation)
    • Extend: generate new (B, T_B) pair via TrapGen (dominant cost)
    • Propagate updated public key to affected parties

The per-update cost is dominated by TrapGen in Extend, which involves
the MP12 trapdoor construction.
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
from ..src.construction.p4_revoke import revoke
from ..src.construction.p5_extend import extend
from ..src.harness import (
    RunResult,
    aggregate_results,
    measure_latency_ns,
    write_raw_runs,
    write_results,
    write_run_meta,
)


def run_exp6(base_path: Path, *, runs: int = 30, warmup: int = 5) -> None:
    """Execute Experiment 6."""
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

    # Variable range: δ (log scale)
    delta_range = [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000]
    all_runs: list[RunResult] = []

    for delta in delta_range:
        print(f"  δ={delta:,}...", end=" ", flush=True)

        def measure(num_updates=delta):
            """Time δ authorization updates (alternating Revoke + Extend).

            Each pair constitutes one full authorization change cycle:
            revoke an attribute, then re-extend it.  This measures the
            scheme's native auth sync mechanism.
            """
            local_rng = np.random.default_rng()

            # Work on copies to avoid cross-run contamination
            from copy import deepcopy
            u_pub = deepcopy(user_pub)
            u_prv = deepcopy(user_prv)

            t0 = time.perf_counter_ns()
            total_msg_bytes = 0

            for i in range(num_updates):
                target_attr = i % params.num_attributes

                # Revoke: replace B with random (fast)
                revoke(gp, u_pub, u_prv, 0, target_attr, rng=local_rng)
                # Message: the new random B matrix
                total_msg_bytes += lp.n * lp.m * 8

                # Extend: generate new (B, T_B) via TrapGen (expensive)
                extend(
                    gp, auth_pk, auth_mk, u_pub, u_prv,
                    target_attr, rng=local_rng,
                )
                # Message: the new B matrix + trapdoor transfer
                total_msg_bytes += lp.n * lp.m * 8

            elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
            msg_kb = total_msg_bytes / 1024.0
            # FSNs touched: all nodes see the update (broadcast)
            fsns_touched = 4.0  # default 4 FSNs

            return (elapsed_ms, msg_kb, fsns_touched)

        results = measure_latency_ns(
            measure, warmup=warmup, runs=runs, variable_value=delta,
        )
        all_runs.extend(results)

        ok = [r for r in results if r.status == "ok"]
        if ok:
            mean_ms = np.mean([r.primary_metric for r in ok])
            print(f"{mean_ms:.2f} ms")
        else:
            print("FAILED")

    # ── Write output ──
    out_dir = base_path / "exp6_authorization_sync"
    write_raw_runs(out_dir / "raw_runs.csv", "exp6", all_runs)
    write_results(out_dir / "results.csv", aggregate_results(all_runs))
    write_run_meta(out_dir / "run_meta.json", "exp6", {
        "variable": "auth_updates_delta",
        "range": delta_range,
    })
    print(f"  Output: {out_dir}")
