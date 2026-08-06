"""CLI entry point for the Zhuang lattice MA-BSE benchmark.

Usage:
    python -m Schemes.zhuang_lattice_mabse.src.main \\
        --experiment 1,2,3,5,6 \\
        --config "Experiment Configuration/global.yaml" \\
        --dataset Dataset/derived \\
        --runs 30
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Zhuang et al. Ref[52] — Lattice MA-BSE Benchmark",
    )
    parser.add_argument(
        "--experiment",
        type=str,
        default="1,2,3,5,6",
        help="Comma-separated experiment numbers (default: 1,2,3,5,6)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="Experiment Configuration/global.yaml",
        help="Path to global config",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="Dataset/derived",
        help="Path to dataset directory",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=30,
        help="Number of measured runs per point (default: 30)",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=5,
        help="Number of warm-up runs to discard (default: 5)",
    )

    args = parser.parse_args()
    experiments = [int(x.strip()) for x in args.experiment.split(",")]
    valid = {1, 2, 3, 5, 6}

    for exp in experiments:
        if exp not in valid:
            print(f"ERROR: Experiment {exp} not valid for this scheme. Valid: {sorted(valid)}")
            sys.exit(1)

    print(f"=== Zhuang Lattice MA-BSE (Ref[52]) ===")
    print(f"Experiments: {experiments}")
    print(f"Runs: {args.runs}  |  Warmup: {args.warmup}")
    print()

    # Base path for output
    base = Path(__file__).resolve().parents[1]

    for exp in experiments:
        print(f"─── Experiment {exp} ───")
        t0 = time.perf_counter()

        if exp == 1:
            from ..exp1_trapdoor_generation.runner import run_exp1
            run_exp1(base, runs=args.runs, warmup=args.warmup)
        elif exp == 2:
            from ..exp2_search_latency.runner import run_exp2
            run_exp2(base, runs=args.runs, warmup=args.warmup)
        elif exp == 3:
            from ..exp3_crossdomain_scalability.runner import run_exp3
            run_exp3(base, runs=args.runs, warmup=args.warmup)
        elif exp == 5:
            from ..exp5_keyword_update.runner import run_exp5
            run_exp5(base, runs=args.runs, warmup=args.warmup)
        elif exp == 6:
            from ..exp6_authorization_sync.runner import run_exp6
            run_exp6(base, runs=args.runs, warmup=args.warmup)

        elapsed = time.perf_counter() - t0
        print(f"  Done in {elapsed:.1f}s")
        print()

    print("All experiments complete.")


if __name__ == "__main__":
    main()
