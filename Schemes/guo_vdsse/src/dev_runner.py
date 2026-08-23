#!/usr/bin/env python3
"""Development-only experiment runner — bypasses the frozen corpus pin.

This script loads the synthetic corpus directly (skipping verify_against_pin)
so experiments can be validated locally without the Synthea corpus.

NOT FOR REPORTABLE RESULTS — development validation only.
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from Dataset.corpus import read_corpus, verify_corpus

from Schemes.guo_vdsse.src.scheme import GuoVDSSE
from Schemes.guo_vdsse.src import (
    exp1_trapdoor,
    exp2_search,
    exp3_crossdomain,
    exp4_verify,
    exp5_update,
)

CORPUS_PATH = _REPO_ROOT / "Dataset" / "derived" / "corpus.jsonl"
MANIFEST_PATH = _REPO_ROOT / "Dataset" / "dataset_manifest.json"
OUTPUT_DIR = _REPO_ROOT / "Schemes" / "guo_vdsse"


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Dev runner for Guo VDSSE")
    parser.add_argument("--experiment", type=str, default="1")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--max-records", type=int, default=1000,
                        help="Limit records for fast dev runs")
    args = parser.parse_args()

    print(f"Loading corpus (dev mode, max {args.max_records} records)...")
    # Load without pin check
    manifest = verify_corpus(CORPUS_PATH, MANIFEST_PATH, require_reportable=False)
    records = list(read_corpus(CORPUS_PATH))
    if args.max_records and len(records) > args.max_records:
        records = records[: args.max_records]
    print(f"  Loaded {len(records)} records")

    scheme = GuoVDSSE()
    exp_map = {
        "1": ("Exp. 1: Trapdoor Generation", exp1_trapdoor),
        "2": ("Exp. 2: Search Latency", exp2_search),
        "3": ("Exp. 3: Cross-Domain", exp3_crossdomain),
        "4": ("Exp. 4: Verification", exp4_verify),
        "5": ("Exp. 5: Update", exp5_update),
    }

    for eid in args.experiment.split(","):
        eid = eid.strip()
        name, mod = exp_map[eid]
        print(f"\n{'=' * 50}")
        print(f"Running {name} (runs={args.runs}, warmup={args.warmup})")
        print(f"{'=' * 50}")
        mod.run(
            scheme=scheme,
            records=records,
            manifest=manifest,
            output_dir=OUTPUT_DIR,
            runs=args.runs,
            warmup=args.warmup,
        )
        print(f"  ✓ {name} complete")

    print("\nDone.")


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
