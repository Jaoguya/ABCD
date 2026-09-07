"""CLI entry point for Guo VDSSE experiments.

Usage:

    python3 -m Schemes.guo_vdsse.src.main \\
        --experiment 1,2,3,4,5 \\
        --runs 30 \\
        --warmup 5 \\
        [--require-reportable / --no-require-reportable] \\
        [--output-dir Schemes/guo_vdsse]

The script:
  1. Loads and verifies the corpus (Dataset.corpus.load_verified_corpus).
  2. Dispatches to the requested experiment modules.
  3. Writes results to ``<output-dir>/expN_*/``.

All cryptographic and dataset parameters come from crypto.yaml and
dataset.yaml — nothing is hardcoded.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

# Ensure repo root is importable
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from Dataset.corpus import load_verified_corpus

from . import (exp1_trapdoor, exp2_search, exp3_crossdomain, exp4_verify,
               exp5_update, exp9_granularity)
from .scheme import GuoVDSSE


EXPERIMENT_MAP = {
    "1": ("exp1_trapdoor_generation", exp1_trapdoor),
    "2": ("exp2_search_latency", exp2_search),
    "3": ("exp3_crossdomain_scalability", exp3_crossdomain),
    "4": ("exp4_verification_overhead", exp4_verify),
    "9": ("exp9_verification_granularity", exp9_granularity),
    "5": ("exp5_keyword_update", exp5_update),
}


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Guo VDSSE (Ref[35]) — Experiment Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--experiment",
        type=str,
        default="1,2,3,4,5",
        help="Comma-separated experiment numbers to run (default: all).",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of measured runs per data point (default: 10).",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=5,
        help="Number of warm-up runs to discard (default: 5).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "Schemes" / "guo_vdsse",
        help="Base output directory (default: Schemes/guo_vdsse/).",
    )
    parser.add_argument(
        "--require-reportable",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Require a reportable (Synthea) corpus. Default: from dataset.yaml.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20260804,
        help="RNG seed for reproducible keyword selection (default: 20260804).",
    )
    parser.add_argument("--points", default=None,
                        help="run only these sweep values so one experiment can be split across instances (e.g. '2-5' or '100,1000'); each shard writes to its own directory and infra/merge_points.py reassembles them")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv)

    # Freeze the configuration this run is measured under, before anything is
    # measured. assert_config_unchanged() re-checks at every sweep-point
    # boundary and aborts if it moved, so a multi-hour sweep cannot end up with
    # its early and late points measured under different parameters.
    from Common.crypto.config import snapshot_config_state
    snapshot_config_state()

    # Parse experiment list
    exp_ids = [e.strip() for e in args.experiment.split(",")]
    for eid in exp_ids:
        if eid not in EXPERIMENT_MAP:
            print(f"Unknown experiment: {eid!r}. "
                  f"Valid: {', '.join(sorted(EXPERIMENT_MAP))}", file=sys.stderr)
            sys.exit(1)

    # Load and verify corpus
    print(f"Loading corpus (require_reportable={args.require_reportable})...")
    require_reportable = args.require_reportable
    records, manifest = load_verified_corpus(
        require_reportable=require_reportable,
    )
    print(f"  Loaded {len(records)} records, "
          f"corpus_type={manifest.get('corpus_type')!r}")

    # Instantiate the scheme
    scheme = GuoVDSSE()

    # Run each experiment
    for eid in exp_ids:
        exp_name, exp_module = EXPERIMENT_MAP[eid]
        print(f"\n{'=' * 60}")
        print(f"Running Exp. {eid}: {exp_name}")
        print(f"  runs={args.runs}, warmup={args.warmup}")
        print(f"{'=' * 60}")

        exp_module.run(
            points=args.points,
            scheme=scheme,
            records=records,
            manifest=manifest,
            output_dir=args.output_dir,
            runs=args.runs,
            warmup=args.warmup,
            seed=args.seed,
        )

        print(f"  ✓ Exp. {eid} complete — results in {args.output_dir / exp_name}/")

    print(f"\nAll experiments complete.")


def _force_utf8_stdout() -> None:
    """Make console output encoding-independent.

    The runners print check marks, box-drawing characters and Greek letters.
    On Linux stdout is UTF-8 and these are fine; a Windows console defaults to
    cp1252 and the first such character raises UnicodeEncodeError mid-run —
    which killed a guo run after Exp. 1 had already completed and written its
    results. Reconfiguring leaves Linux output byte-identical.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass  # already-wrapped or non-reconfigurable stream


if __name__ == "__main__":
    _force_utf8_stdout()
    main()
