"""CLI entry point for Ref[55] (Ge et al., Peony / Peony++) experiments.

Usage:

    python3 -m Schemes.yue_ge.src.main \\
        --experiment 1,2,3,4,5 \\
        --runs 30 \\
        --warmup 5 \\
        [--variant peony_plus|peony] \\
        [--bloom-hashes 5|13] \\
        [--output-dir Schemes/yue_ge]

The script:
  1. Loads and verifies the corpus (``Dataset.corpus.load_verified_corpus``).
  2. Dispatches to the requested experiment runners.
  3. Writes results to ``<output-dir>/expN_*/``.

All cryptographic parameters come from ``crypto.yaml`` — nothing is hardcoded.
Both published Bloom settings (``h = 5`` and ``h = 13``, Ref[55] Tables V-VII)
are reachable via ``--bloom-hashes`` without editing config, because the paper
declares no default between them.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path
from typing import List

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from Dataset.corpus import load_verified_corpus

from Schemes.yue_ge.exp1_trapdoor_generation import runner as exp1
from Schemes.yue_ge.exp2_search_latency import runner as exp2
from Schemes.yue_ge.exp3_crossdomain_scalability import runner as exp3
from Schemes.yue_ge.exp4_verification_overhead import runner as exp4
from Schemes.yue_ge.exp5_keyword_update import runner as exp5
from Schemes.yue_ge.src.params import SchemeParams

EXPERIMENT_MAP = {
    "1": ("exp1_trapdoor_generation", exp1),
    "2": ("exp2_search_latency", exp2),
    "3": ("exp3_crossdomain_scalability", exp3),
    "4": ("exp4_verification_overhead", exp4),
    "5": ("exp5_keyword_update", exp5),
}


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ref[55] Ge et al. (Peony / Peony++) — Experiment Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--experiment", type=str, default="1,2,3,4,5",
                        help="Comma-separated experiment numbers (default: all).")
    parser.add_argument("--runs", type=int, default=10,
                        help="Measured runs per data point (default: 30).")
    parser.add_argument("--warmup", type=int, default=5,
                        help="Warm-up runs to discard (default: 5).")
    parser.add_argument("--output-dir", type=Path,
                        default=_REPO_ROOT / "Schemes" / "yue_ge",
                        help="Base output directory.")
    parser.add_argument(
        "--variant", choices=["peony_plus", "peony"], default="peony_plus",
        help=(
            "Which construction to measure. Default peony_plus: it is the "
            "paper's flagship (forward + Type-II backward private + "
            "verifiable) and the only one supporting Exp. 4. 'peony' is the "
            "forward-only scheme, for the search-cost comparison the paper "
            "itself draws between them."
        ),
    )
    parser.add_argument(
        "--bloom-hashes", type=int, default=None, choices=[5, 13],
        help=(
            "Override h. Ref[55] publishes BOTH h=5 and h=13 (Tables V-VII) "
            "and declares no default; crypto.yaml takes h=5 as primary."
        ),
    )
    parser.add_argument("--require-reportable", action=argparse.BooleanOptionalAction,
                        default=None,
                        help="Require a reportable corpus. Default: from dataset.yaml.")
    parser.add_argument("--seed", type=int, default=20260828,
                        help="RNG seed for reproducible keyword selection.")
    parser.add_argument("--points", default=None,
                        help="run only these sweep values so one experiment can be split across instances (e.g. '2-5' or '100,1000'); each shard writes to its own directory and infra/merge_points.py reassembles them")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv)

    exp_ids = [e.strip() for e in args.experiment.split(",")]
    for eid in exp_ids:
        if eid not in EXPERIMENT_MAP:
            print(f"Unknown experiment: {eid!r}. "
                  f"Valid: {', '.join(sorted(EXPERIMENT_MAP))}", file=sys.stderr)
            sys.exit(1)

    if args.variant == "peony" and "4" in exp_ids:
        print(
            "Exp. 4 requires --variant peony_plus: Peony (§V) has no "
            "verification algorithm; public verification is introduced by "
            "Peony++ (§VI-A). Refusing rather than measuring something else "
            "and labelling it verification.",
            file=sys.stderr,
        )
        sys.exit(1)

    params = SchemeParams.from_config()
    if args.bloom_hashes is not None:
        params = replace(params, bloom_num_hashes=args.bloom_hashes)

    print(f"Loading corpus (require_reportable={args.require_reportable})...")
    records, manifest = load_verified_corpus(
        require_reportable=args.require_reportable
    )
    print(f"  Loaded {len(records)} records, "
          f"corpus_type={manifest.get('corpus_type')!r}")
    print(f"  Variant: {args.variant}   Bloom h = {params.bloom_num_hashes}   "
          f"|L| = {params.access_levels}   c = {params.update_batches_c}")

    for eid in exp_ids:
        exp_name, exp_module = EXPERIMENT_MAP[eid]
        print(f"\n{'=' * 60}")
        print(f"Running Exp. {eid}: {exp_name}")
        print(f"  runs={args.runs}, warmup={args.warmup}")
        print(f"{'=' * 60}")

        exp_module.run(
            points=args.points,
            params=params,
            records=records,
            manifest=manifest,
            output_dir=args.output_dir,
            runs=args.runs,
            warmup=args.warmup,
            seed=args.seed,
            variant=args.variant,
        )
        print(f"  Done — results in {args.output_dir / exp_name}/")

    print("\nAll experiments complete.")


def _force_utf8_stdout() -> None:
    """Make console output encoding-independent (see guo_vdsse/src/main.py)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass


if __name__ == "__main__":
    _force_utf8_stdout()
    main()
