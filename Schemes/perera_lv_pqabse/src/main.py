"""CLI for Ref[54] LV-PQ-ABSE.

    python3 -m Schemes.perera_lv_pqabse.src.main --experiment all

Covers Exp. 1, 2, 3 only. Exp. 4 is not claimed (this repo's Exp. 4 boundary is
defined against the proposed scheme's verification path), and Exp. 5 and 6 are
excluded because the paper has no incremental-update primitive and explicitly
disclaims fine-grained revocation — see SCHEME.md for both.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Dataset.corpus import load_verified_corpus  # noqa: E402
from Schemes.perera_lv_pqabse.exp1_trapdoor_generation import (  # noqa: E402
    runner as exp1,
)
from Schemes.perera_lv_pqabse.exp2_search_latency import runner as exp2  # noqa: E402
from Schemes.perera_lv_pqabse.exp3_crossdomain_scalability import (  # noqa: E402
    runner as exp3,
)
from Schemes.perera_lv_pqabse.src.params import SchemeParams  # noqa: E402

EXPERIMENT_MAP = {
    "1": ("exp1_trapdoor_generation", exp1),
    "2": ("exp2_search_latency", exp2),
    "3": ("exp3_crossdomain_scalability", exp3),
}


def _report_setup_cost() -> None:
    """README §5, Exp. 1: session establishment is reported separately.

    ML-KEM-768 encapsulation is excluded from the trapdoor curve because it
    happens once per session, not per query. Excluding it silently would make
    the exclusion invisible, so it is measured and printed here.
    """
    from Common.crypto.kem import KEMUnavailableError, measure_setup_cost

    try:
        cost = measure_setup_cost(repetitions=30)
    except KEMUnavailableError as exc:
        print(f"  session establishment: UNAVAILABLE ({exc})")
        return
    print(
        f"  session establishment (EXCLUDED from Exp. 1, README §5): "
        f"keygen {cost['keygen_ms']:.3f} ms, "
        f"encapsulate {cost['encapsulate_ms']:.3f} ms, "
        f"decapsulate {cost['decapsulate_ms']:.3f} ms "
        f"[backend: {cost['backend']}]"
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m Schemes.perera_lv_pqabse.src.main",
        description="Run the LV-PQ-ABSE (Ref[54]) experiments — Exp. 1, 2, 3.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--experiment", default="all", help="all, or 1,2,3")
    parser.add_argument("--runs", type=int, default=30,
                        help="retained runs per point (README §7 fixes 30)")
    parser.add_argument("--warmup", type=int, default=5,
                        help="discarded warm-ups (README §7 fixes 5)")
    parser.add_argument("--seed", type=int, default=20260829)
    parser.add_argument("--output", type=Path,
                        default=REPO_ROOT / "Schemes" / "perera_lv_pqabse")
    parser.add_argument("--require-reportable", action="store_true",
                        help="refuse to run unless the corpus is the frozen one")
    parser.add_argument("--points", default=None,
                        help="run only these sweep values so one experiment can be split across instances (e.g. '2-5' or '100,1000'); each shard writes to its own directory and infra/merge_points.py reassembles them")
    args = parser.parse_args(argv)

    exp_ids = (
        sorted(EXPERIMENT_MAP) if args.experiment == "all"
        else [e.strip() for e in args.experiment.split(",")]
    )
    for eid in exp_ids:
        if eid not in EXPERIMENT_MAP:
            print(f"Unknown experiment: {eid!r}. "
                  f"Valid: {', '.join(sorted(EXPERIMENT_MAP))}", file=sys.stderr)
            return 1

    params = SchemeParams.from_config()

    print(f"Loading corpus (require_reportable={args.require_reportable})...")
    records, manifest = load_verified_corpus(
        require_reportable=args.require_reportable
    )
    print(f"  Loaded {len(records):,} records, "
          f"corpus_type={manifest.get('corpus_type')!r}")
    print(f"  lambda={params.security_parameter_lambda}  "
          f"n={params.lattice.n}  q=2^{params.lattice.log_q}  "
          f"|U|={params.attribute_universe}  "
          f"KEM={params.kem}  SIG={params.signature}")
    _report_setup_cost()

    for eid in exp_ids:
        exp_name, module = EXPERIMENT_MAP[eid]
        print(f"\n{'=' * 60}")
        print(f"Running Exp. {eid}: {exp_name}")
        print(f"  runs={args.runs}, warmup={args.warmup}")
        print(f"{'=' * 60}")
        module.run(
            points=args.points,
            params=params, records=records, manifest=manifest,
            output_dir=args.output, runs=args.runs, warmup=args.warmup,
            seed=args.seed,
        )
        print(f"  Done — results in {args.output / exp_name}/")

    print("\nAll experiments complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
