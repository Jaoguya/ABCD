#!/usr/bin/env python3
"""Generate a statistically-matched synthetic corpus.

DEVELOPMENT ONLY. README §4: "Results produced from the synthetic corpus are
for development only and must not be reported in the paper." Every corpus
this script writes is stamped ``corpus_type: synthetic`` and
``reportable: false`` in its manifest.

The corpus exists so that collaborators without MIMIC-IV credentials — and
CI — can exercise the full pipeline against a corpus with the right SHAPE:
the same heavy-tailed keyword-frequency law, the same records-per-domain
split, the same keyword-set sizes.

Matching a real corpus
----------------------
Until MIMIC-IV has been processed once, the shape comes from the placeholder
values in ``Experiment Configuration/dataset.yaml``. After
``prepare_dataset.py`` has run, point this script at the manifest it wrote::

    python3 Dataset/synthetic_generator.py --match-profile Dataset/derived/dataset_manifest.json

and the fitted Zipf exponent, keyword-universe size, and keyword-set length
distribution are taken from the REAL corpus instead of the placeholders.

Usage
-----
    # Linux
    python3 Dataset/synthetic_generator.py --records 100000 --domains 4 \\
        --output Dataset/derived

    # Windows (PowerShell)
    python Dataset/synthetic_generator.py --records 100000 --domains 4 `
        --output Dataset/derived
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Common.crypto.config import DATASET_CONFIG_PATH, config_hashes, load  # noqa: E402
from Dataset.corpus import (  # noqa: E402
    Record,
    assign_domain,
    load_manifest,
    pseudonymize,
    write_corpus,
    write_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

# Namespace split for the synthetic keyword universe, mirroring the three
# MIMIC-IV keyword sources in dataset.yaml so that the synthetic corpus has
# the same structural shape as the real one.
_NAMESPACES: Tuple[Tuple[str, float], ...] = (
    ("dx:", 0.45),  # diagnoses
    ("px:", 0.15),  # procedures
    ("rx:", 0.40),  # prescriptions
)


def build_keyword_universe(size: int) -> List[str]:
    """Synthetic keyword vocabulary, split across the three namespaces."""
    universe: List[str] = []
    for prefix, share in _NAMESPACES:
        count = max(1, int(round(size * share)))
        universe.extend(f"{prefix}{i:06d}" for i in range(count))
    return universe[:size] if len(universe) >= size else universe


def zipf_probabilities(size: int, exponent: float) -> np.ndarray:
    """Normalised Zipf weights over ``size`` ranks.

    Built explicitly rather than via ``rng.zipf``: numpy's zipf samples from
    an unbounded support and would produce ranks beyond the vocabulary, which
    then have to be discarded — distorting the very distribution being
    matched.
    """
    ranks = np.arange(1, size + 1, dtype=np.float64)
    weights = ranks ** (-exponent)
    return weights / weights.sum()


def sample_keyword_counts(
    records: int, rng: np.random.Generator, spec: Dict[str, Any]
) -> np.ndarray:
    """Per-record keyword-set sizes |W_i|, from a clipped lognormal."""
    mean = float(spec.get("mean", 12.0))
    sigma = float(spec.get("sigma", 0.5))
    low = int(spec.get("min", 1))
    high = int(spec.get("max", 32))

    # Solve for the underlying normal's mu so the lognormal MEAN is `mean`,
    # rather than its median. Using log(mean) directly is the common slip and
    # would systematically undershoot the target keyword-set size.
    mu = np.log(mean) - (sigma**2) / 2
    draws = rng.lognormal(mean=mu, sigma=sigma, size=records)
    return np.clip(np.round(draws), low, high).astype(np.int64)


def generate_records(
    *,
    records: int,
    domains: int,
    universe: List[str],
    probabilities: np.ndarray,
    counts: np.ndarray,
    records_per_patient: float,
    rng: np.random.Generator,
    start_time: datetime,
) -> Iterator[Record]:
    """Yield synthetic records with Zipf-distributed keywords."""
    patient_pool = max(1, int(records / max(records_per_patient, 1.0)))
    cdf = np.cumsum(probabilities)

    # Draw all keyword picks in one vectorised pass. Oversample by 30% so that
    # de-duplicating within a record rarely leaves it short.
    total_draws = int(counts.sum() * 1.3) + len(counts)
    picks = np.searchsorted(cdf, rng.random(total_draws))
    picks = np.clip(picks, 0, len(universe) - 1)

    patient_ids = rng.integers(0, patient_pool, size=records)
    offsets = rng.integers(0, 86_400 * 365 * 5, size=records)

    cursor = 0
    for rid in range(records):
        want = int(counts[rid])
        window = int(want * 1.3) + 1
        if cursor + window > len(picks):  # pragma: no cover - oversampling
            # Top up BEFORE slicing; refilling afterwards would leave this
            # record short of its sampled keyword count.
            picks = np.concatenate(
                [picks, np.searchsorted(cdf, rng.random(max(window, 1024) * 8))]
            )
        chunk = picks[cursor : cursor + window]
        cursor += window

        # dict.fromkeys de-duplicates while preserving order, so the keyword
        # set stays deterministic for a given seed.
        keywords = list(dict.fromkeys(universe[int(i)] for i in chunk))[:want]

        pid = pseudonymize(f"synthetic-patient-{int(patient_ids[rid])}")
        yield Record(
            rid=rid,
            pid=pid,
            vid=1,
            dom=assign_domain(pid, domains),
            ts=(start_time + timedelta(seconds=int(offsets[rid]))).isoformat(
                timespec="seconds"
            ),
            kw=keywords,
        )


def resolve_profile(args: argparse.Namespace, config: Dict[str, Any]) -> Dict[str, Any]:
    """Decide the corpus shape: matched to a real manifest, or placeholders."""
    synthetic_cfg = config["synthetic"]
    profile: Dict[str, Any] = {
        "source": "dataset.yaml placeholders",
        "zipf_exponent": float(synthetic_cfg["zipf_exponent"]),
        "keyword_universe_size": int(synthetic_cfg["keyword_universe_size"]),
        "keywords_per_record": dict(synthetic_cfg["keywords_per_record"]),
    }

    if args.match_profile:
        manifest = load_manifest(Path(args.match_profile))
        if manifest.get("corpus_type") != "mimic":
            raise SystemExit(
                f"--match-profile expects a manifest from a MIMIC corpus, got "
                f"corpus_type={manifest.get('corpus_type')!r}. Matching a "
                f"synthetic manifest would just copy the placeholders."
            )
        freq = manifest.get("frequency_profile", {})
        lengths = manifest.get("keywords_per_record", {})
        profile.update(
            source=f"matched to {Path(args.match_profile).name}",
            zipf_exponent=float(freq.get("fitted_exponent", profile["zipf_exponent"])),
            keyword_universe_size=int(
                manifest.get("keyword_universe_size", profile["keyword_universe_size"])
            ),
            keywords_per_record={
                "distribution": "lognormal",
                "mean": float(lengths.get("mean", 12.0)),
                "sigma": float(profile["keywords_per_record"].get("sigma", 0.5)),
                "min": int(lengths.get("min", 1)),
                "max": int(lengths.get("max", 32)),
            },
            matched_corpus_sha256=manifest.get("corpus_sha256"),
        )
    return profile


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic development corpus (NOT reportable).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--records", type=int, default=None,
                        help="number of records (default: dataset.yaml)")
    parser.add_argument("--domains", type=int, default=None,
                        help="administrative domains (default: dataset.yaml)")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "Dataset" / "derived",
                        help="output directory")
    parser.add_argument("--seed", type=int, default=None,
                        help="PRNG seed (default: dataset.yaml)")
    parser.add_argument("--manifest", type=Path,
                        default=REPO_ROOT / "Dataset" / "dataset_manifest.json",
                        help="manifest path; README §4 keeps it in Dataset/ "
                             "(committed provenance) while the corpus itself "
                             "stays git-ignored under derived/")
    parser.add_argument("--match-profile", type=Path, default=None,
                        help="a MIMIC dataset_manifest.json whose distribution to match")
    parser.add_argument("--records-per-patient", type=float, default=2.5,
                        help="mean records per patient, controls the patient pool")
    args = parser.parse_args(argv)

    config = load(DATASET_CONFIG_PATH)
    corpus_cfg = config["corpus"]
    output_cfg = config["output"]

    records = args.records or int(corpus_cfg["default_records"])
    domains = args.domains or int(corpus_cfg["domains"])
    seed = args.seed if args.seed is not None else int(config["synthetic"]["seed"])

    if records <= 0:
        raise SystemExit(f"--records must be positive, got {records}")
    if domains <= 0:
        raise SystemExit(f"--domains must be positive, got {domains}")

    profile = resolve_profile(args, config)
    rng = np.random.default_rng(seed)

    universe = build_keyword_universe(int(profile["keyword_universe_size"]))
    probabilities = zipf_probabilities(len(universe), float(profile["zipf_exponent"]))
    counts = sample_keyword_counts(records, rng, profile["keywords_per_record"])

    print(
        f"Generating {records:,} synthetic records across {domains} domains\n"
        f"  vocabulary : {len(universe):,} keywords\n"
        f"  zipf s     : {profile['zipf_exponent']}\n"
        f"  profile    : {profile['source']}\n"
        f"  seed       : {seed}",
        file=sys.stderr,
    )

    corpus_path = Path(args.output) / output_cfg["corpus_filename"]
    stats = write_corpus(
        corpus_path,
        generate_records(
            records=records,
            domains=domains,
            universe=universe,
            probabilities=probabilities,
            counts=counts,
            records_per_patient=args.records_per_patient,
            rng=rng,
            start_time=datetime(2180, 1, 1, tzinfo=timezone.utc),
        ),
    )

    manifest = write_manifest(
        Path(args.manifest),
        corpus_type="synthetic",
        corpus_filename=output_cfg["corpus_filename"],
        stats=stats,
        params={
            "records": records,
            "domains": domains,
            "seed": seed,
            "records_per_patient": args.records_per_patient,
            "profile": profile,
            "generator": "synthetic_generator.py",
        },
        config_hashes=config_hashes(),
        repo_root=REPO_ROOT,
    )

    print(
        f"\nWrote {corpus_path}\n"
        f"  records     : {manifest['records']:,}\n"
        f"  keywords    : {manifest['keyword_universe_size']:,} distinct, "
        f"{manifest['keyword_document_pairs']:,} pairs\n"
        f"  per domain  : {manifest['per_domain_counts']}\n"
        f"  |W_i| mean  : {manifest['keywords_per_record']['mean']:.2f}\n"
        f"  fitted zipf : {manifest['frequency_profile']['fitted_exponent']}\n"
        f"  sha256      : {manifest['corpus_sha256']}\n"
        f"\n  NOT REPORTABLE — development corpus (README §4).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
