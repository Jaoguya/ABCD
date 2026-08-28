#!/usr/bin/env python3
"""Development-only experiment runner — bypasses the frozen corpus pin.

Same role as ``guo_vdsse/src/dev_runner.py``: validate that the experiment
plumbing runs end to end without needing the pinned Synthea corpus, which lives
on the benchmark AMI rather than on a dev box.

**NOT FOR REPORTABLE RESULTS.** Anything produced here is written to a scratch
directory and carries a synthetic corpus manifest, so it can never be mistaken
for a measured figure. Reportable runs go through ``src/main.py``, which calls
``load_verified_corpus`` and fails if the corpus hash does not match.

    python -m Schemes.yue_ge.src.dev_runner --experiment 1,2,3,4,5
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from Common.crypto.rng import DeterministicRNG
from Dataset.corpus import Record, read_corpus

from Schemes.yue_ge.exp1_trapdoor_generation import runner as exp1
from Schemes.yue_ge.exp2_search_latency import runner as exp2
from Schemes.yue_ge.exp3_crossdomain_scalability import runner as exp3
from Schemes.yue_ge.exp4_verification_overhead import runner as exp4
from Schemes.yue_ge.exp5_keyword_update import runner as exp5
from Schemes.yue_ge.src.params import SchemeParams

CORPUS_PATH = _REPO_ROOT / "Dataset" / "derived" / "corpus.jsonl"

EXPERIMENTS = {
    "1": exp1, "2": exp2, "3": exp3, "4": exp4, "5": exp5,
}


def _synthetic_records(n: int, seed: int = 7) -> List[Record]:
    """Stand-in corpus with the shape of the real one.

    Vocabulary and keyword-count distribution are chosen to resemble README §4's
    description (2,102-word vocabulary, median |W_i| = 4, 4 domains) so the
    plumbing is exercised realistically. The VALUES are meaningless — this
    exists to prove the code runs, not to produce a number.
    """
    rng = DeterministicRNG(seed).numpy
    vocab = [f"kw{i:04d}" for i in range(2102)]
    out: List[Record] = []
    for rid in range(n):
        n_kw = int(min(64, max(1, rng.poisson(5))))
        kws = sorted({vocab[int(rng.zipf(1.4) % len(vocab))] for _ in range(n_kw)})
        out.append(Record(
            rid=rid,
            pid=f"P{rid % max(1, n // 3):06d}",
            vid=1,
            dom=rid % 4,
            ts="2026-01-01T00:00:00Z",
            kw=kws,
        ))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Dev runner for Ref[55] (yue_ge)")
    ap.add_argument("--experiment", type=str, default="1,2,3,4,5")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--max-records", type=int, default=400)
    ap.add_argument("--variant", choices=["peony_plus", "peony"],
                    default="peony_plus")
    ap.add_argument("--output-dir", type=Path, default=None,
                    help="Default: a _dev_output/ scratch dir, never the real "
                         "experiment folders.")
    args = ap.parse_args()

    out_dir = args.output_dir or (_REPO_ROOT / "Schemes" / "yue_ge" / "_dev_output")

    if CORPUS_PATH.exists():
        records = list(read_corpus(CORPUS_PATH))[: args.max_records]
        source = f"real corpus (first {len(records)})"
    else:
        records = _synthetic_records(args.max_records)
        source = f"SYNTHETIC ({len(records)} records) — corpus.jsonl absent"

    manifest: Dict[str, object] = {
        "corpus_sha256": "DEV-RUN-NOT-REPORTABLE",
        "corpus_type": "synthetic-dev",
    }

    params = SchemeParams.from_config()
    print(f"Dev run — {source}")
    print(f"  variant={args.variant}  h={params.bloom_num_hashes}  "
          f"|L|={params.access_levels}  c={params.update_batches_c}")
    print(f"  output -> {out_dir}  (NOT REPORTABLE)\n")

    for eid in [e.strip() for e in args.experiment.split(",")]:
        mod = EXPERIMENTS[eid]
        print(f"--- Exp. {eid} ---")
        mod.run(
            params=params,
            records=records,
            manifest=manifest,
            output_dir=out_dir,
            runs=args.runs,
            warmup=args.warmup,
            seed=20260828,
            variant=args.variant,
        )
        print(f"    ok\n")

    print("Dev run complete. Results are NOT reportable.")


def _force_utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass


if __name__ == "__main__":
    _force_utf8_stdout()
    main()
