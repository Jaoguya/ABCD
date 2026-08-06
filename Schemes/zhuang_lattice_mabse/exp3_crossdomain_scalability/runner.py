"""Experiment 3 — Cross-Domain Search Scalability

Variable: domains d = 2 → 10
Primary:  total search latency (ms) across d domains
Secondary: trapdoors issued, cross-node messages

Per SCHEME.md: "Native mode: d independent trapdoors + d independent
searches, client-side result aggregation."

This scheme does NOT support native cross-domain search.  For d domains:
    1. Client generates d independent search tokens (one per domain)
    2. Cloud runs d independent searches (one per domain's index)
    3. Client aggregates results

Total latency = d × (TokenGen + Search).
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


def run_exp3(base_path: Path, *, runs: int = 30, warmup: int = 5) -> None:
    """Execute Experiment 3."""
    print("  Setting up scheme parameters...")
    params = SchemeParams.from_config()
    rng = np.random.default_rng(42)

    # Variable range: d = 2..10
    d_range = list(range(2, 11))
    all_runs: list[RunResult] = []

    # Pre-build domain setups for max d=10
    print("  Building domain setups...")
    domain_setups = []
    for domain_id in range(10):
        gp = setup(params, rng=rng)
        attr_ids = list(range(params.num_attributes))
        access_tree = make_and_policy(attr_ids)

        auth_pk, auth_mk = aa_setup(gp, 0, attr_ids, rng=rng)
        user_pub, user_prv = enroll(
            gp, auth_pk, auth_mk, "user_0", attr_ids, rng=rng
        )

        keywords = [f"keyword_{i}".encode() for i in range(params.keywords_per_ct)]
        ct, idx = encrypt(gp, 1, 0, keywords, access_tree, [user_pub], rng=rng)

        domain_setups.append({
            "gp": gp,
            "tree": access_tree,
            "user_pub": user_pub,
            "user_prv": user_prv,
            "keywords": keywords,
            "ct": ct,
            "idx": idx,
        })

    for d in d_range:
        print(f"  d={d}...", end=" ", flush=True)

        def measure(num_domains=d):
            t0 = time.perf_counter_ns()
            trapdoors_issued = 0
            for i in range(num_domains):
                ds = domain_setups[i]
                # Generate token for this domain
                tok = token_gen(
                    ds["gp"], 0, ds["keywords"],
                    ds["user_pub"], ds["user_prv"],
                    rng=np.random.default_rng(),
                )
                trapdoors_issued += 1
                # Search this domain's index
                search(ds["gp"], tok, ds["idx"], ds["tree"], "user_0")
            elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
            # Cross-node messages = 0 (no native cross-domain support)
            return (elapsed_ms, float(trapdoors_issued), 0.0)

        results = measure_latency_ns(
            measure, warmup=warmup, runs=runs, variable_value=d,
        )
        all_runs.extend(results)

        ok = [r for r in results if r.status == "ok"]
        if ok:
            mean_ms = np.mean([r.primary_metric for r in ok])
            print(f"{mean_ms:.2f} ms")
        else:
            print("FAILED")

    # ── Write output ──
    out_dir = base_path / "exp3_crossdomain_scalability"
    write_raw_runs(out_dir / "raw_runs.csv", "exp3", all_runs)
    write_results(out_dir / "results.csv", aggregate_results(all_runs))
    write_run_meta(out_dir / "run_meta.json", "exp3", {
        "variable": "domains_d",
        "range": d_range,
        "mode": "native (d independent trapdoors + d independent searches)",
    })
    print(f"  Output: {out_dir}")
