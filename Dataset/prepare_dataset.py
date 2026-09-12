#!/usr/bin/env python3
"""Derive the searchable corpus from a Synthea CSV export.

Synthea (MITRE) generates synthetic patient records from epidemiologically
grounded disease modules. Apache 2.0, no credentialing, and the generator is
peer-reviewed and citable:

    Walonoski et al., "Synthea: An approach, method, and software mechanism
    for generating synthetic patients and the synthetic electronic health
    care record", JAMIA 25(3), 2018. doi:10.1093/jamia/ocx079

Emits the derived artefact skill.md describes — keyword set ``W_i`` plus
metadata ``(PID_i, VID_i, Dom_i, TS_i)`` per record.

NOT THE SAME AS ``synthetic_generator.py``
------------------------------------------
Both produce records without real patients, but they are different kinds of
thing. ``synthetic_generator.py`` draws keywords from a fitted Zipf law with
no clinical structure and is barred from reportable results (skill.md).
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
    balance_domains,
    pseudonymize,
    sha256_file,
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

    A source may declare ``value_binning``, which appends a quantile band to
    the code (``obs:8867-4:b3``). Without it a numeric observation would give
    every record a unique keyword and exercise no index at all.
    """
    tables = cfg["tables"]
    join_key = cfg["join_key"]
    normalize = cfg["keyword_filter"]["normalize"]

    per_record: Dict[str, Set[str]] = defaultdict(set)
    for source in cfg["keyword_sources"]:
        if not source.get("enabled", True):
            continue

        table = source["table"]
        if table not in tables:
            print(f"  skipping {table}: not declared in tables", file=sys.stderr)
            continue
        try:
            path = _resolve(root, tables[table])
        except SyntheaNotFoundError:
            # Synthea omits a table entirely when a run produced no rows for
            # it (small populations often have no imaging studies). Skipping
            # is correct; failing would make the corpus depend on population
            # size in a way that has nothing to do with the benchmark.
            print(f"  skipping {table}: not present in this export", file=sys.stderr)
            continue

        field, prefix = source["field"], source["prefix"]
        binning = source.get("value_binning") or {}
        use_bins = bool(binning.get("enabled"))
        columns = [join_key, field]
        if use_bins:
            columns.append(binning["value_field"])

        label = f"{prefix}*" + (" (value-binned)" if use_bins else "")
        print(f"  reading {path.name} ({field} -> {label})", file=sys.stderr)

        try:
            reader = pd.read_csv(
                path, usecols=columns, chunksize=CHUNK_ROWS, low_memory=False
            )
        except ValueError as exc:
            print(f"  skipping {table}: {exc}", file=sys.stderr)
            continue

        for chunk in reader:
            chunk = chunk.dropna(subset=[join_key, field])
            if use_bins:
                _add_binned(chunk, per_record, join_key, field, prefix,
                            binning, normalize)
            else:
                for key, value in zip(chunk[join_key], chunk[field]):
                    token = _normalize(value, normalize)
                    if token:
                        per_record[_key(key)].add(prefix + token)
    return per_record


def _add_binned(
    chunk: "pd.DataFrame",
    per_record: Dict[str, Set[str]],
    join_key: str,
    field: str,
    prefix: str,
    binning: Dict[str, Any],
    normalize: str,
) -> None:
    """Append a quantile band to each code: ``obs:8867-4:b3``.

    Bands are computed as a percentile rank WITHIN each code, per chunk.
    Chunk-local rather than global: a global pass would mean holding every
    observation value in memory, and at 10^6 encounters that is tens of
    millions of rows. The approximation is recorded in the manifest.

    Rows whose value is non-numeric (Synthea survey responses, categorical
    results) keep the bare code with no band — binning a category would be
    meaningless, and dropping the row would silently lose vocabulary.
    """
    bins = int(binning.get("bins", 5))
    value_field = binning["value_field"]

    numeric = pd.to_numeric(chunk[value_field], errors="coerce")
    has_value = numeric.notna()

    # Non-numeric rows: bare code.
    for key, code in zip(chunk[join_key][~has_value], chunk[field][~has_value]):
        token = _normalize(code, normalize)
        if token:
            per_record[_key(key)].add(prefix + token)

    if not has_value.any():
        return

    numeric_rows = chunk[has_value].assign(_value=numeric[has_value])
    # rank(pct=True) is in (0, 1]; scaling by `bins` and clipping keeps the
    # top rank inside the last band instead of creating a bins+1'th band.
    bands = (
        numeric_rows.groupby(field)["_value"]
        .rank(pct=True, method="average")
        .mul(bins)
        .apply(lambda x: min(int(x), bins - 1) if pd.notna(x) else 0)
    )
    for key, code, band in zip(
        numeric_rows[join_key], numeric_rows[field], bands
    ):
        token = _normalize(code, normalize)
        if token:
            per_record[_key(key)].add(f"{prefix}{token}:b{int(band)}")


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
    floor = int(rules.get("min_keywords_per_record", 1))

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
    below_floor = 0
    for key, keywords in per_record.items():
        surviving = sorted(keywords & keep)
        if len(surviving) > cap:
            # Keep the RAREST keywords: they are the selective ones, and
            # keeping the most common instead would flatten n_eff.
            surviving = sorted(surviving, key=lambda k: document_frequency[k])[:cap]
            truncated += 1
        if len(surviving) < floor:
            # A record with fewer keywords than the query size can never match
            # a conjunctive q-keyword query, so it contributes index weight
            # without ever appearing in a result. The manuscript fixes q=5
            # (§V, "each query contains five keywords"), and the unfiltered
            # corpus had a median |W_i| of 4 — over half the records were
            # structurally unmatchable at the default query size.
            below_floor += 1
            continue
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
            "min_keywords_per_record": floor,
            "records_below_keyword_floor": below_floor,
            "records_with_no_keywords": len(per_record) - len(filtered) - below_floor,
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
    """Join keywords to their patient, organisation, and timestamp.

    Domains are assigned by balancing whole organizations across buckets
    rather than hashing each one independently — see
    ``corpus.balance_domains``. The balance is computed over the encounters
    that actually survive keyword filtering, not over all encounters, so the
    emitted corpus is what ends up even.
    """
    path = _resolve(root, cfg["tables"]["encounters"])
    time_column = cfg["timestamp_field"]
    columns = ["Id", "PATIENT", "ORGANIZATION", time_column]

    frame = pd.read_csv(path, usecols=columns, low_memory=False)
    frame = frame.dropna(subset=["Id", "PATIENT"])
    frame = frame.sort_values("Id")

    # Pass 1: how many surviving records does each organization contribute?
    org_counts: Counter[str] = Counter()
    for enc_id, org in zip(frame["Id"], frame["ORGANIZATION"]):
        if keywords.get(_key(enc_id)):
            org_counts[str(org)] += 1
    org_domain = balance_domains(dict(org_counts), domains)

    # Pass 2: emit.
    emitted = 0
    for row in frame.itertuples(index=False):
        values = dict(zip(frame.columns, row))
        record_keywords = keywords.get(_key(values["Id"]))
        if not record_keywords:
            continue
        if limit is not None and emitted >= limit:
            break
        org = str(values["ORGANIZATION"])
        yield Record(
            rid=emitted,
            pid=pseudonymize(values["PATIENT"]),
            # Fall back to hashing only if an organization somehow never
            # appeared in pass 1, which should be impossible.
            dom=org_domain.get(org, assign_domain(org, domains)),
            vid=1,
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
                        help="manifest path; skill.md keeps it in Dataset/ "
                             "(committed provenance) while the corpus itself "
                             "stays git-ignored under derived/")
    parser.add_argument("--domains", type=int, default=None, help="default: dataset.yaml")
    parser.add_argument("--limit", type=int, default=None,
                        help="cap the number of records emitted")
    parser.add_argument("--synthea-version", default=None,
                        help="Synthea release used (e.g. 3.3.0). Recorded in the "
                             "manifest; without it the corpus is not reproducible")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing corpus. The corpus is meant to "
                             "be built ONCE and reused; regenerating it mid-campaign "
                             "makes earlier results incomparable (skill.md)")
    args = parser.parse_args(argv)

    config = load(DATASET_CONFIG_PATH)
    cfg = config["synthea"]
    output_cfg = config["output"]
    domains = args.domains or int(config["corpus"]["domains"])

    root = Path(args.input)
    if not root.is_dir():
        raise SyntheaNotFoundError(f"--input is not a directory: {root}")

    # Build once, reuse everywhere. Re-running this by accident must not
    # silently replace the corpus every scheme has already measured against.
    corpus_path = Path(args.output) / output_cfg["corpus_filename"]
    if corpus_path.is_file() and not args.force:
        existing = sha256_file(corpus_path)
        raise SystemExit(
            f"corpus already exists: {corpus_path}\n"
            f"  sha256: {existing}\n\n"
            f"The corpus is built ONCE and reused by every scheme on every\n"
            f"instance. Regenerating it now would make any results already\n"
            f"produced incomparable (skill.md).\n\n"
            f"If you genuinely want to rebuild, pass --force — and then re-run\n"
            f"EVERY scheme, and clear freeze.expected_corpus_sha256 in\n"
            f"Experiment Configuration/dataset.yaml."
        )

    if not args.synthea_version:
        print(
            "  WARNING: --synthea-version not given. Synthea output changes\n"
            "  between releases, so without it this corpus cannot be\n"
            "  reproduced from the manifest alone.",
            file=sys.stderr,
        )

    print(f"Reading Synthea CSV export from {root}", file=sys.stderr)
    per_record = collect_keywords(root, cfg)
    if not per_record:
        raise SystemExit("no keywords extracted — check --input and dataset.yaml")

    print(f"  {len(per_record):,} encounters; filtering keywords", file=sys.stderr)
    filtered = filter_keywords(per_record, cfg)
    per_record.clear()  # free before assembling records

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
            # Synthea output changes between releases; without this the corpus
            # is not reproducible from the manifest alone.
            "synthea_version": args.synthea_version or "unspecified",
            "export_format": cfg["export_format"],
            "record_unit": cfg["record_unit"],
            "domain_assignment": cfg["domain_assignment"],
            "domains": domains,
            "limit": args.limit,
            "keyword_filter": cfg["keyword_filter"],
            # The full vocabulary configuration is recorded, not just the
            # filter: the keyword universe drives n_eff, which is what Exp. 2
            # claims latency tracks. A reviewer must be able to see exactly
            # which sources and which binning produced it.
            "keyword_sources": cfg["keyword_sources"],
            "value_binning_note": (
                "Observation value bands are percentile ranks computed within "
                "each code, per 1M-row chunk, not globally."
            ),
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

    print(
        f"\n  TO FREEZE: copy this into Experiment Configuration/dataset.yaml\n"
        f"    freeze:\n"
        f"      expected_corpus_sha256: {manifest['corpus_sha256']}\n"
        f"      frozen_on: {manifest['generated_utc'][:10]}\n"
        f"  Every scheme then verifies the corpus at startup and refuses to\n"
        f"  run on a different one.",
        file=sys.stderr,
    )

    ceiling = manifest["records"]
    if ceiling < 1_000_000:
        # Scale from what THIS run actually produced rather than from a fixed
        # encounters-per-patient ratio. The keyword floor drops a large and
        # filter-dependent share of encounters (55% at min_keywords=5), so a
        # ratio derived from raw encounter counts overstates the yield badly.
        factor = 1_000_000 / ceiling
        floor = cfg["keyword_filter"].get("min_keywords_per_record", 1)
        print(
            f"\n  NOTE: {ceiling:,} records, below the 10^6 top of skill.md's\n"
            f"  range. Not a hard ceiling — scale the patient count by\n"
            f"  ~{factor:.2f}x and regenerate (this run's yield already\n"
            f"  accounts for min_keywords_per_record={floor}).",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
