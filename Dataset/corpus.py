"""Derived-corpus schema, manifest, and statistics.

Shared by ``prepare_dataset.py`` (Synthea) and ``synthetic_generator.py``.
Both emit the SAME format, which is the point: a scheme must not be able to
tell which corpus it is reading, or a development run and a reportable run
would not be measuring the same thing.

Corpus format — ``corpus.jsonl``, one JSON object per line::

    {"rid": 0, "pid": "a3f8...", "vid": 1, "dom": 2,
     "ts": "2180-07-23T14:31:00", "kw": ["dx:I10", "rx:aspirin"]}

which is README §4's "keyword set W_i + metadata (PID_i, VID_i, Dom_i, TS_i)".
JSONL rather than one big JSON array so a 10^6-record corpus streams instead
of loading whole.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

CORPUS_VERSION = 1


@dataclass
class Record:
    """One derived searchable record."""

    rid: int                    # record index, 0-based
    pid: str                    # PID_i — pseudonymous patient identifier
    vid: int                    # VID_i — authorization version, starts at 1
    dom: int                    # Dom_i — administrative domain, 0-based
    ts: str                     # TS_i — ISO-8601 timestamp
    kw: List[str] = field(default_factory=list)  # W_i — keyword set

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, line: str) -> "Record":
        return cls(**json.loads(line))


# ---------------------------------------------------------------------------
# Deterministic domain assignment
# ---------------------------------------------------------------------------
def assign_domain(patient_id: str, domains: int) -> int:
    """Map a patient to one administrative domain, deterministically.

    Hashing the PATIENT (not the record) keeps every record of one patient in
    a single domain, which is what "administrative healthcare domain" means —
    a patient is registered with one authority. A per-record coin flip would
    scatter one patient across four domains and make Exp. 3's cross-domain
    search measure something that does not occur in the system model.

    SHA-256 rather than ``hash()``: reproducible across processes and
    platforms (README §4 records a corpus SHA-256 that must be stable).
    """
    if domains <= 0:
        raise ValueError(f"domains must be positive, got {domains}")
    digest = hashlib.sha256(patient_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % domains


def pseudonymize(raw_id: str, *, salt: bytes = b"MA-LB-PQ-VDSE/pid") -> str:
    """Hash a source identifier into a stable pseudonym.

    Synthea's patient UUIDs are synthetic, so this is not a privacy control.
    It exists to give ``PID_i`` a uniform shape and length regardless of what
    the source identifier looked like, so that trapdoor and index sizes do
    not vary with an artefact of the corpus.
    """
    return hashlib.sha256(salt + str(raw_id).encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Writing and reading
# ---------------------------------------------------------------------------
def write_corpus(path: Path, records: Iterable[Record]) -> Dict[str, Any]:
    """Stream records to ``path``, returning summary statistics.

    Computes the SHA-256 incrementally while writing, so a 10^6-record corpus
    is never held in memory and never re-read just to be hashed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    count = 0
    keyword_counts: Counter[str] = Counter()
    per_domain: Counter[int] = Counter()
    lengths: List[int] = []

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            line = record.to_json() + "\n"
            handle.write(line)
            hasher.update(line.encode("utf-8"))
            count += 1
            per_domain[record.dom] += 1
            lengths.append(len(record.kw))
            keyword_counts.update(record.kw)

    if count == 0:
        raise ValueError("refusing to write an empty corpus")

    return {
        "records": count,
        "sha256": hasher.hexdigest(),
        "per_domain_counts": {str(k): v for k, v in sorted(per_domain.items())},
        "keyword_universe_size": len(keyword_counts),
        "keyword_document_pairs": sum(lengths),
        "keywords_per_record": _length_stats(lengths),
        "frequency_profile": frequency_profile(keyword_counts),
    }


def read_corpus(path: Path) -> Iterator[Record]:
    """Stream records back from a corpus file."""
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield Record.from_json(line)


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------
def _length_stats(lengths: List[int]) -> Dict[str, float]:
    if not lengths:
        return {}
    ordered = sorted(lengths)
    n = len(ordered)

    def pct(p: float) -> int:
        return ordered[min(n - 1, int(p * n))]

    return {
        "mean": sum(ordered) / n,
        "min": ordered[0],
        "max": ordered[-1],
        "p50": pct(0.50),
        "p95": pct(0.95),
    }


def frequency_profile(keyword_counts: Counter, *, top_k: int = 50) -> Dict[str, Any]:
    """Fit a Zipf exponent to the keyword-frequency distribution.

    This is what makes "statistically-matched synthetic corpus" (README §4) a
    checkable claim rather than an assertion: once a Synthea corpus has been
    built, ``synthetic_generator.py --match-profile`` reads the fitted
    exponent and universe size from its manifest and reproduces them, instead
    of using the placeholder in dataset.yaml.

    Fit is a least-squares line through ``log(rank)`` vs ``log(frequency)``;
    the Zipf exponent is the negated slope.
    """
    if not keyword_counts:
        return {}
    frequencies = sorted(keyword_counts.values(), reverse=True)
    ranks = range(1, len(frequencies) + 1)

    log_r = [math.log(r) for r in ranks]
    log_f = [math.log(f) for f in frequencies]
    n = len(log_r)
    mean_r = sum(log_r) / n
    mean_f = sum(log_f) / n
    denominator = sum((r - mean_r) ** 2 for r in log_r)
    slope = (
        sum((r - mean_r) * (f - mean_f) for r, f in zip(log_r, log_f)) / denominator
        if denominator
        else 0.0
    )

    return {
        "distribution": "zipf",
        "fitted_exponent": round(-slope, 4),
        "distinct_keywords": len(frequencies),
        "max_frequency": frequencies[0],
        "min_frequency": frequencies[-1],
        "top_keywords": [
            {"keyword": kw, "count": c} for kw, c in keyword_counts.most_common(top_k)
        ],
    }


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
def git_commit(repo_root: Optional[Path] = None) -> str:
    """Current git commit, for provenance (README §7)."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root) if repo_root else None,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return out.stdout.strip()
    except Exception:
        return "unknown"


def write_manifest(
    path: Path,
    *,
    corpus_type: str,
    corpus_filename: str,
    stats: Dict[str, Any],
    params: Dict[str, Any],
    config_hashes: Optional[Dict[str, str]] = None,
    repo_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Write ``dataset_manifest.json`` (README §4).

    ``corpus_type`` is one of:

    ``synthea``    Synthea (MITRE), Apache 2.0, citable generator with
                   epidemiologically grounded clinical structure. Reportable.
    ``synthetic``  ``synthetic_generator.py`` — a fitted Zipf law with no
                   clinical structure. NOT reportable (README §4).

    The distinction matters and is easy to lose: both are "not real
    patients", but only Synthea is a citable instrument with real
    co-occurrence structure. The value propagates into every
    ``run_meta.json``, so it is validated here rather than trusted.
    """
    reportable_types = {"synthea"}
    if corpus_type not in reportable_types | {"synthetic"}:
        raise ValueError(
            f"corpus_type must be 'synthea' or 'synthetic', got {corpus_type!r}"
        )

    manifest: Dict[str, Any] = {
        "corpus_version": CORPUS_VERSION,
        "corpus_type": corpus_type,
        "corpus_filename": corpus_filename,
        "corpus_sha256": stats["sha256"],
        "records": stats["records"],
        "domains": len(stats["per_domain_counts"]),
        "per_domain_counts": stats["per_domain_counts"],
        "keyword_universe_size": stats["keyword_universe_size"],
        "keyword_document_pairs": stats["keyword_document_pairs"],
        "keywords_per_record": stats["keywords_per_record"],
        "frequency_profile": stats["frequency_profile"],
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": git_commit(repo_root),
        "params": params,
        "config_hashes": config_hashes or {},
    }
    manifest["reportable"] = corpus_type in reportable_types
    if corpus_type == "synthetic":
        manifest["warning"] = (
            "DEVELOPMENT ONLY. README §4: results produced from the synthetic "
            "corpus must not be reported in the paper. For a reportable "
            "corpus, use Synthea via prepare_dataset.py."
        )
    elif corpus_type == "synthea":
        manifest["citation"] = (
            "Walonoski et al., Synthea: An approach, method, and software "
            "mechanism for generating synthetic patients and the synthetic "
            "electronic health care record, JAMIA 25(3), 2018. "
            "doi:10.1093/jamia/ocx079"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def load_manifest(path: Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
