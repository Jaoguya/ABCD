#!/usr/bin/env python3
"""Derive the searchable corpus from a Synthea CSV export.

Synthea (MITRE) generates synthetic patient records from epidemiologically
grounded disease modules. Apache 2.0, no credentialing, and the generator is
peer-reviewed and citable:

    Walonoski et al., "Synthea: An approach, method, and software mechanism
    for generating synthetic patients and the synthetic electronic health
    care record", JAMIA 25(3), 2018. doi:10.1093/jamia/ocx079

Emits the derived artefact README §4 describes — keyword set ``W_i`` plus
metadata ``(PID_i, VID_i, Dom_i, TS_i)`` per record.

NOT THE SAME AS ``synthetic_generator.py``
------------------------------------------
Both produce records without real patients, but they are different kinds of
thing. ``synthetic_generator.py`` draws keywords from a fitted Zipf law with
no clinical structure and is barred from reportable results (README §4).
Synthea produces module-driven co-occurrence — a diabetes condition really
does pull metformin — and is a citable instrument, so ``corpus_type:
synthea`` IS reportable. Keep the distinction when reading a manifest.

RECORD UNIT AND DOMAINS
-----------------------
One record per clinical encounter. The administrative domain comes from
``encounters.ORGANIZATION``, a genuine institutional boundary — so one
patient seen at two organisations really does have records in two domains,
which is what Exp. 3's cross-domain search is meant to exercise.

CORPUS SIZE
-----------
Synthea has no size ceiling: regenerate with more patients to move the top of
the Exp. 2 sweep. Roughly 2-3 encounters per patient, so ~400k patients
clears 10^6 encounters.

Usage
-----
    # Generate first:
    #   git clone https://github.com/synthetichealth/synthea && cd synthea
    #   ./run_synthea -p 400000

    # Linux
    python3 Dataset/prepare_dataset.py \\
        --input /path/to/synthea/output/csv --output Dataset/derived

    # Windows (PowerShell)
    python Dataset/prepare_dataset.py `
        --input C:\\path\\to\\synthea\\output\\csv --output Dataset/derived
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Common.crypto.config import DATASET_CONFIG_PATH, config_hashes, load  # noqa: E402
from Dataset.corpus import (  # noqa: E402
    Record,
    assign_domain,
    pseudonymize,
    write_corpus,
    write_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CHUNK_ROWS = 1_000_000


class SyntheaNotFoundError(SystemExit):
    pass


def _resolve(root: Path, relative: str) -> Path:
    """Locate a Synthea table, tolerating gzipped exports."""
    candidate = root / relative
    if candidate.is_file():
        return candidate
    gzipped = candidate.with_suffix(candidate.suffix + ".gz")
    if gzipped.is_file():
        return gzipped
    raise SyntheaNotFoundError(
        f"Synthea table not found: {candidate}\n"
        f"Expected Synthea's CSV export directory (usually output/csv/).\n"
        f"Checked both .csv and .csv.gz."
    )


def _normalize(value: Any, mode: str) -> Optional[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    text = str(value).strip()
    if not text or text.lower() == "nan":
        return None
    return text.lower() if mode == "lowercase_strip" else text


def _key(value: Any) -> str:
    """Normalise the encounter join key. Synthea uses UUID strings."""
    return str(value).strip()


# ---------------------------------------------------------------------------
# Keyword collection
# ---------------------------------------------------------------------------
def collect_keywords(root: Path, cfg: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Gather namespaced keywords per encounter from the code tables.

    Codes rather than free-text DESCRIPTION: codes are the controlled
    vocabulary a real searchable index would be built over, and using them
    avoids a keyword universe inflated by wording variants of the same
    concept.
    """
    tables = cfg["tables"]
    join_key = cfg["join_key"]
    normalize = cfg["keyword_filter"]["normalize"]

    per_record: Dict[str, Set[str]] = defaultdict(set)
    for source in cfg["keyword_sources"]:
        if not source.get("enabled", True):
            continue
        path = _resolve(root, tables[source["table"]])
        field, prefix = source["field"], source["prefix"]
        print(f"  reading {path.name} ({field} -> {prefix}*)", file=sys.stderr)

        reader = pd.read_csv(
            path, usecols=[join_key, field], chunksize=CHUNK_ROWS, low_memory=False
        )
        for chunk in reader:
            chunk = chunk.dropna(subset=[join_key, field])
            for key, value in zip(chunk[join_key], chunk[field]):
                token = _normalize(value, normalize)
                if token:
                    per_record[_key(key)].add(prefix + token)
    return per_record


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------
def filter_keywords(
    per_record: Dict[str, Set[str]], cfg: Dict[str, Any]
) -> Dict[str, Any]:
    """Drop keywords that are too rare or too common to affect search.

    Rare keywords inflate the keyword universe without ever being queried;
    ubiquitous ones match nearly everything and carry no selectivity. Both
    distort Exp. 2, whose whole claim is that latency tracks the candidate
    set ``n_eff`` rather than total index size.
    """
    rules = cfg["keyword_filter"]
    min_df = int(rules["min_document_frequency"])
    max_ratio = float(rules["max_document_frequency_ratio"])
    cap = int(rules["max_keywords_per_record"])

    document_frequency: Counter[str] = Counter()
    for keywords in per_record.values():
        document_frequency.update(keywords)

    total = len(per_record)
    max_df = max_ratio * total
    keep = {kw for kw, df in document_frequency.items() if min_df <= df <= max_df}

    dropped_rare = sum(1 for kw, df in document_frequency.items() if df < min_df)
    dropped_common = sum(1 for kw, df in document_frequency.items() if df > max_df)

    filtered: Dict[str, List[str]] = {}
    truncated = 0
    for key, keywords in per_record.items():
        surviving = sorted(keywords & keep)
        if len(surviving) > cap:
            # Keep the RAREST keywords: they are the selective ones, and
            # keeping the most common instead would flatten n_eff.
            surviving = sorted(surviving, key=lambda k: document_frequency[k])[:cap]
            truncated += 1
        if surviving:
            filtered[key] = sorted(surviving)

    return {
        "keywords": filtered,
        "stats": {
            "keywords_before_filter": len(document_frequency),
            "keywords_after_filter": len(keep),
            "dropped_rare": dropped_rare,
            "dropped_common": dropped_common,
            "records_truncated_at_cap": truncated,
            "records_with_no_keywords": len(per_record) - len(filtered),
        },
    }


# ---------------------------------------------------------------------------
# Record assembly
# ---------------------------------------------------------------------------
def build_records(
    root: Path,
    cfg: Dict[str, Any],
    keywords: Dict[str, List[str]],
    *,
    domains: int,
    limit: Optional[int],
) -> Iterator[Record]:
    """Join keywords to their patient, organisation, and timestamp."""
    path = _resolve(root, cfg["tables"]["encounters"])
    time_column = cfg["timestamp_field"]
    columns = ["Id", "PATIENT", "ORGANIZATION", time_column]

    frame = pd.read_csv(path, usecols=columns, low_memory=False)
    frame = frame.dropna(subset=["Id", "PATIENT"])
    frame = frame.sort_values("Id")

    emitted = 0
    for row in frame.itertuples(index=False):
        values = dict(zip(frame.columns, row))
        record_keywords = keywords.get(_key(values["Id"]))
        if not record_keywords:
            continue
        if limit is not None and emitted >= limit:
            break
        yield Record(
            rid=emitted,
            pid=pseudonymize(values["PATIENT"]),
            vid=1,
            dom=assign_domain(str(values["ORGANIZATION"]), domains),
            ts=str(values[time_column]),
            kw=record_keywords,
        )
        emitted += 1


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive the searchable corpus from a Synthea CSV export.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", type=Path, required=True,
                        help="Synthea CSV export directory (usually output/csv)")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "Dataset" / "derived",
                        help="output directory")
    parser.add_argument("--manifest", type=Path,
                        default=REPO_ROOT / "Dataset" / "dataset_manifest.json",
                        help="manifest path; README §4 keeps it in Dataset/ "
                             "(committed provenance) while the corpus itself "
                             "stays git-ignored under derived/")
    parser.add_argument("--domains", type=int, default=None, help="default: dataset.yaml")
    parser.add_argument("--limit", type=int, default=None,
                        help="cap the number of records emitted")
    args = parser.parse_args(argv)

    config = load(DATASET_CONFIG_PATH)
    cfg = config["synthea"]
    output_cfg = config["output"]
    domains = args.domains or int(config["corpus"]["domains"])

    root = Path(args.input)
    if not root.is_dir():
        raise SyntheaNotFoundError(f"--input is not a directory: {root}")

    print(f"Reading Synthea CSV export from {root}", file=sys.stderr)
    per_record = collect_keywords(root, cfg)
    if not per_record:
        raise SystemExit("no keywords extracted — check --input and dataset.yaml")

    print(f"  {len(per_record):,} encounters; filtering keywords", file=sys.stderr)
    filtered = filter_keywords(per_record, cfg)
    per_record.clear()  # free before assembling records

    corpus_path = Path(args.output) / output_cfg["corpus_filename"]
    stats = write_corpus(
        corpus_path,
        build_records(
            root, cfg, filtered["keywords"], domains=domains, limit=args.limit
        ),
    )

    manifest = write_manifest(
        Path(args.manifest),
        corpus_type="synthea",
        corpus_filename=output_cfg["corpus_filename"],
        stats=stats,
        params={
            "source": "synthea",
            "export_format": cfg["export_format"],
            "record_unit": cfg["record_unit"],
            "domain_assignment": cfg["domain_assignment"],
            "domains": domains,
            "limit": args.limit,
            "keyword_filter": cfg["keyword_filter"],
            "extraction_stats": filtered["stats"],
            "generator": "prepare_dataset.py",
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
        f"  sha256      : {manifest['corpus_sha256']}",
        file=sys.stderr,
    )

    ceiling = manifest["records"]
    if ceiling < 1_000_000:
        print(
            f"\n  NOTE: {ceiling:,} records, below the 10^6 top of README §4's\n"
            f"  range. Not a hard ceiling — regenerate with more patients:\n"
            f"    ./run_synthea -p 400000\n"
            f"  (~2-3 encounters per patient, so ~400k patients clears 10^6).",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
