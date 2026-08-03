#!/usr/bin/env python3
"""Derive the searchable corpus from a local MIMIC-IV v3.1 copy.

MIMIC-IV is credentialed-access data under a DUA. This script reads a copy
you already hold and emits ONLY the derived artefact README §4 describes —
keyword set ``W_i`` plus metadata ``(PID_i, VID_i, Dom_i, TS_i)``. Patient
identifiers are hashed, no clinical values are carried through, and nothing
it writes may be committed (README §14).

RECORD UNIT
-----------
``--record-unit admission`` (default)
    One record per hospital admission. Keywords are ICD diagnosis codes, ICD
    procedure codes, and drug names from the ``hosp/`` module.

``--record-unit icu_stay``
    One record per ICU stay. Keywords are derived from ``icu/chartevents`` —
    bedside-monitor observations captured from CONNECTED DEVICES, which is
    the closest thing in MIMIC-IV to Internet-of-Medical-Things telemetry.
    Slower: chartevents is the largest table in the dataset.

    This unit exists because MIMIC-IV is a hospital EHR database, not an IoMT
    dataset. If the manuscript's IoMT framing needs the data to be
    device-sourced rather than administrative, this is the unit that gets
    closest. See the note in the README discussion of §4.

CORPUS SIZE CEILING
-------------------
MIMIC-IV v3.1 contains on the order of 5x10^5 hospital admissions and far
fewer ICU stays. README §4's stated range of 10^4-10^6 RECORDS is therefore
not reachable at one record per admission — the top of the Exp. 2 sweep
cannot be populated from this corpus without a finer record unit. This
script reports the ceiling it actually found rather than silently capping.

Usage
-----
    # Linux
    python3 Dataset/prepare_dataset.py --input /path/to/mimic-iv-3.1 \\
        --output Dataset/derived

    # Windows (PowerShell)
    python Dataset/prepare_dataset.py --input C:\\path\\to\\mimic-iv-3.1 `
        --output Dataset/derived
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


class MimicNotFoundError(SystemExit):
    pass


def _resolve(root: Path, relative: str) -> Path:
    """Locate a MIMIC table, tolerating gzipped and plain variants."""
    candidate = root / relative
    if candidate.is_file():
        return candidate
    if candidate.suffix == ".gz":
        plain = candidate.with_suffix("")
        if plain.is_file():
            return plain
    else:
        gzipped = candidate.with_suffix(candidate.suffix + ".gz")
        if gzipped.is_file():
            return gzipped
    raise MimicNotFoundError(
        f"MIMIC-IV table not found: {candidate}\n"
        f"Expected a MIMIC-IV v3.1 root containing hosp/ and icu/.\n"
        f"Checked both .csv and .csv.gz."
    )


def _normalize(value: Any, mode: str) -> Optional[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    text = str(value).strip()
    if not text or text.lower() == "nan":
        return None
    return text.lower() if mode == "lowercase_strip" else text


# ---------------------------------------------------------------------------
# Keyword collection
# ---------------------------------------------------------------------------
def collect_keywords_admission(
    root: Path, config: Dict[str, Any], key_column: str = "hadm_id"
) -> Dict[int, Set[str]]:
    """Gather namespaced keywords per admission from the hosp/ tables."""
    mimic_cfg = config["mimic"]
    tables = mimic_cfg["tables"]
    normalize = mimic_cfg["keyword_filter"]["normalize"]

    per_record: Dict[int, Set[str]] = defaultdict(set)
    for source in mimic_cfg["keyword_sources"]:
        if not source.get("enabled", True):
            continue
        path = _resolve(root, tables[source["table"]])
        field, prefix = source["field"], source["prefix"]
        print(f"  reading {path.name} ({field} -> {prefix}*)", file=sys.stderr)

        reader = pd.read_csv(
            path,
            usecols=[key_column, field],
            chunksize=CHUNK_ROWS,
            low_memory=False,
        )
        for chunk in reader:
            chunk = chunk.dropna(subset=[key_column, field])
            for key, value in zip(chunk[key_column], chunk[field]):
                token = _normalize(value, normalize)
                if token:
                    per_record[int(key)].add(prefix + token)
    return per_record


def collect_keywords_icu(root: Path, config: Dict[str, Any]) -> Dict[int, Set[str]]:
    """Gather keywords per ICU stay from device-sourced chartevents.

    Each observation becomes a keyword of the form ``ce:<itemid>:<band>``
    where the band is the value's decile within that itemid. Binning is what
    turns a continuous sensor reading into something searchable — a raw float
    would give every record a unique keyword and no index would be exercised.
    """
    per_record: Dict[int, Set[str]] = defaultdict(set)
    path = _resolve(root, "icu/chartevents.csv.gz")
    print(
        f"  reading {path.name} (device telemetry — this is the largest "
        f"table in MIMIC-IV and will take a while)",
        file=sys.stderr,
    )

    reader = pd.read_csv(
        path,
        usecols=["stay_id", "itemid", "valuenum"],
        chunksize=CHUNK_ROWS,
        low_memory=False,
    )
    for index, chunk in enumerate(reader, start=1):
        chunk = chunk.dropna(subset=["stay_id", "itemid", "valuenum"])
        if chunk.empty:
            continue
        # Decile within itemid, computed per chunk. Chunk-local binning is an
        # approximation of global deciles; it is stable enough for keyword
        # formation and avoids a second full pass over ~3x10^8 rows.
        bands = (
            chunk.groupby("itemid")["valuenum"]
            .rank(pct=True)
            .mul(10)
            .clip(upper=9)
            .astype(int)
        )
        for stay, item, band in zip(chunk["stay_id"], chunk["itemid"], bands):
            per_record[int(stay)].add(f"ce:{int(item)}:{int(band)}")
        print(f"    chunk {index} ({len(per_record):,} stays so far)", file=sys.stderr)
    return per_record


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------
def filter_keywords(
    per_record: Dict[int, Set[str]], config: Dict[str, Any]
) -> Dict[str, Any]:
    """Drop keywords that are too rare or too common to affect search.

    Rare keywords inflate the keyword universe without ever being queried;
    ubiquitous ones match nearly everything and carry no selectivity. Both
    distort Exp. 2, whose whole claim is that latency tracks the candidate
    set ``n_eff`` rather than total index size.
    """
    rules = config["mimic"]["keyword_filter"]
    min_df = int(rules["min_document_frequency"])
    max_ratio = float(rules["max_document_frequency_ratio"])
    cap = int(rules["max_keywords_per_record"])

    document_frequency: Counter[str] = Counter()
    for keywords in per_record.values():
        document_frequency.update(keywords)

    total = len(per_record)
    max_df = max_ratio * total
    keep = {
        kw for kw, df in document_frequency.items() if min_df <= df <= max_df
    }

    dropped_rare = sum(1 for kw, df in document_frequency.items() if df < min_df)
    dropped_common = sum(1 for kw, df in document_frequency.items() if df > max_df)

    filtered: Dict[int, List[str]] = {}
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
    config: Dict[str, Any],
    keywords: Dict[int, List[str]],
    *,
    record_unit: str,
    domains: int,
    limit: Optional[int],
) -> Iterator[Record]:
    """Join keywords to their patient and timestamp, and emit records."""
    if record_unit == "admission":
        path = _resolve(root, config["mimic"]["tables"]["admissions"])
        key_column, time_column = "hadm_id", config["mimic"]["timestamp_field"]
    else:
        path = _resolve(root, "icu/icustays.csv.gz")
        key_column, time_column = "stay_id", "intime"

    frame = pd.read_csv(
        path, usecols=[key_column, "subject_id", time_column], low_memory=False
    )
    frame = frame.dropna(subset=[key_column, "subject_id"])
    frame = frame.sort_values(key_column)

    emitted = 0
    for key, subject, timestamp in zip(
        frame[key_column], frame["subject_id"], frame[time_column]
    ):
        record_keywords = keywords.get(int(key))
        if not record_keywords:
            continue
        if limit is not None and emitted >= limit:
            break
        pid = pseudonymize(subject)
        yield Record(
            rid=emitted,
            pid=pid,
            vid=1,
            dom=assign_domain(pid, domains),
            ts=str(timestamp),
            kw=record_keywords,
        )
        emitted += 1


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive the searchable corpus from MIMIC-IV v3.1.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", type=Path, required=True,
                        help="MIMIC-IV v3.1 root (contains hosp/ and icu/)")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "Dataset" / "derived",
                        help="output directory")
    parser.add_argument("--manifest", type=Path,
                        default=REPO_ROOT / "Dataset" / "dataset_manifest.json",
                        help="manifest path; README §4 keeps it in Dataset/ "
                             "(committed provenance) while the corpus itself "
                             "stays git-ignored under derived/")
    parser.add_argument("--record-unit", choices=["admission", "icu_stay"],
                        default=None, help="default: dataset.yaml")
    parser.add_argument("--domains", type=int, default=None, help="default: dataset.yaml")
    parser.add_argument("--limit", type=int, default=None,
                        help="cap the number of records emitted")
    args = parser.parse_args(argv)

    config = load(DATASET_CONFIG_PATH)
    output_cfg = config["output"]
    record_unit = args.record_unit or config["mimic"]["record_unit"]
    domains = args.domains or int(config["corpus"]["domains"])

    root = Path(args.input)
    if not root.is_dir():
        raise MimicNotFoundError(f"--input is not a directory: {root}")

    print(f"Reading MIMIC-IV v3.1 from {root} (unit: {record_unit})", file=sys.stderr)
    if record_unit == "admission":
        per_record = collect_keywords_admission(root, config)
    else:
        per_record = collect_keywords_icu(root, config)

    if not per_record:
        raise SystemExit("no keywords extracted — check --input and dataset.yaml")

    print(f"  {len(per_record):,} source records; filtering keywords", file=sys.stderr)
    filtered = filter_keywords(per_record, config)
    per_record.clear()  # free before assembling records

    corpus_path = Path(args.output) / output_cfg["corpus_filename"]
    stats = write_corpus(
        corpus_path,
        build_records(
            root,
            config,
            filtered["keywords"],
            record_unit=record_unit,
            domains=domains,
            limit=args.limit,
        ),
    )

    manifest = write_manifest(
        Path(args.manifest),
        corpus_type="mimic",
        corpus_filename=output_cfg["corpus_filename"],
        stats=stats,
        params={
            "mimic_version": config["mimic"]["version"],
            "record_unit": record_unit,
            "domains": domains,
            "limit": args.limit,
            "keyword_filter": config["mimic"]["keyword_filter"],
            "extraction_stats": filtered["stats"],
            "generator": "prepare_dataset.py",
        },
        config_hashes=config_hashes(),
        repo_root=REPO_ROOT,
    )

    ceiling = manifest["records"]
    print(
        f"\nWrote {corpus_path}\n"
        f"  records     : {ceiling:,}\n"
        f"  keywords    : {manifest['keyword_universe_size']:,} distinct, "
        f"{manifest['keyword_document_pairs']:,} pairs\n"
        f"  per domain  : {manifest['per_domain_counts']}\n"
        f"  |W_i| mean  : {manifest['keywords_per_record']['mean']:.2f}\n"
        f"  fitted zipf : {manifest['frequency_profile']['fitted_exponent']}\n"
        f"  sha256      : {manifest['corpus_sha256']}",
        file=sys.stderr,
    )
    if ceiling < 1_000_000:
        print(
            f"\n  NOTE: this corpus holds {ceiling:,} records, below the 10^6 top\n"
            f"  of README §4's stated range. The Exp. 2 sweep cannot reach 10^6\n"
            f"  records at --record-unit {record_unit}. Decide whether to cap the\n"
            f"  sweep or to use a finer record unit before generating results.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
