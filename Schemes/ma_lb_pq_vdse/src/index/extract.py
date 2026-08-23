"""Phase IV Step 1 — Keyword and Metadata Extraction.

Manuscript `Overleaf/PQ-AVDSE-OJCOMS:606`:

    W_i    = {w_1, ..., w_t}
    Meta_i = (PID_i, VID_i, Dom_i, TS_i)

Extraction is a **projection** of a frozen-corpus record, not a re-derivation.
``Dataset/prepare_dataset.py`` already did the clinical work — SNOMED, RxNorm,
LOINC quantile binning, and the rest — and the corpus SHA-256 is pinned. Anything
this module computed rather than read would be an index over data the manifest
does not describe.

**``PID_i`` is not in the corpus, and the corpus's ``pid`` is not ``PID_i``.**

* The manuscript's ``PID_i`` is the **access-policy identifier** — notation table
  `:331`, Phase IV Step 1 `:630` ("``PID_i`` denotes the access-policy
  identifier"), Phase VI Step 4 `:971`.
* ``Dataset/corpus.py``'s ``Record.pid`` is a **patient pseudonym**:
  ``prepare_dataset.py:346`` sets ``pid=pseudonymize(values["PATIENT"])``.

README §4 lists the record schema as ``W_i + (PID_i, VID_i, Dom_i, TS_i)``, which
reads as though the two are the same field. They are not, and the difference is
not cosmetic: taking the corpus ``pid`` as ``PID_i`` yields **one access policy
per patient** — roughly 38,000 policies over the frozen corpus — and
``index.yaml``'s ``bitmap.granularity: domain_policy`` sizes its bitmap set as
``|Dom| x |PID|``. That choice therefore lands directly on Exp. 2's ``n_eff``.

So this module **requires an explicit** :class:`PolicyAssignment` and provides no
default. ``PHASE_IV_PLAN.md`` open decision 3 records ``|PID|`` and the
record-to-policy mapping as undecided, and a default here would be that decision
made silently, in the one place nobody would look for it.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional, Protocol, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from ..types import RecordMetadata  # noqa: E402

#: Default presentation names for the corpus's 0-based domain indices. The corpus
#: carries ``dom`` as an integer; every other module in this scheme keys domains
#: by string. Overridable, because a deployment's domains have real names.
DEFAULT_DOMAIN_NAMES = ("dom0", "dom1", "dom2", "dom3")


class ExtractionError(RuntimeError):
    """Raised when a corpus record cannot be indexed."""


class PolicyAssignment(Protocol):
    """Maps a corpus record to its access-policy identifier ``PID_i``."""

    def policy_id(self, *, patient_pseudonym: str, domain: str) -> str:
        ...

    @property
    def policy_count(self) -> int:
        """``|PID|`` — how many distinct policies this assignment can produce."""


@dataclass(frozen=True)
class BucketedPolicyAssignment:
    """Partition each domain's patients into a fixed number of policies.

    ``policies_per_domain`` must be given explicitly — it is open decision 3, and
    it sizes the ``domain_policy`` bitmap set that produces ``n_eff``. Assignment
    hashes the patient pseudonym, so every record of one patient shares a policy
    (a patient's records are governed together, which is what an access policy
    over clinical data means) and the mapping is deterministic and reproducible.
    """

    policies_per_domain: int
    domains: int = len(DEFAULT_DOMAIN_NAMES)

    def __post_init__(self) -> None:
        if self.policies_per_domain < 1:
            raise ValueError("policies_per_domain must be >= 1")
        if self.domains < 1:
            raise ValueError("domains must be >= 1")

    def policy_id(self, *, patient_pseudonym: str, domain: str) -> str:
        digest = hashes.sha256(
            patient_pseudonym.encode("utf-8"), domain=b"policy-assignment/v1"
        )
        bucket = int.from_bytes(digest[:8], "big") % self.policies_per_domain
        width = len(str(self.policies_per_domain - 1)) or 1
        return f"{domain}/pol{bucket:0{width}d}"

    @property
    def policy_count(self) -> int:
        return self.policies_per_domain * self.domains


@dataclass(frozen=True)
class PerPatientPolicyAssignment:
    """One policy per patient — the reading README §4 implies.

    Provided so the option can be measured rather than argued about, and marked
    here rather than buried: ``|PID|`` becomes the patient count (~38,000 for the
    frozen corpus), which makes the ``domain_policy`` bitmap set very large and
    each individual bitmap very sparse. Whether that helps or hurts ``n_eff`` is
    an empirical question, but it is not a neutral default.
    """

    patients: int

    def policy_id(self, *, patient_pseudonym: str, domain: str) -> str:
        return f"{domain}/pat-{patient_pseudonym}"

    @property
    def policy_count(self) -> int:
        return self.patients


@dataclass(frozen=True)
class ExtractedRecord:
    """One corpus record projected into ``(W_i, Meta_i)``."""

    record_id: int
    keywords: Tuple[str, ...]
    metadata: RecordMetadata
    patient_pseudonym: str

    @property
    def keyword_count(self) -> int:
        """``|W_i|`` — the corpus guarantees at least ``min_keywords_per_record``."""
        return len(self.keywords)

    @property
    def domain(self) -> str:
        return self.metadata.domain

    @property
    def policy_id(self) -> str:
        return self.metadata.policy_id


def domain_name(index: int, names: Sequence[str] = DEFAULT_DOMAIN_NAMES) -> str:
    """Map a corpus domain index to its name."""
    if not 0 <= index < len(names):
        raise ExtractionError(
            f"domain index {index} out of range for {len(names)} domains "
            f"{list(names)}"
        )
    return names[index]


def extract(
    record,
    *,
    assignment: PolicyAssignment,
    domain_names: Sequence[str] = DEFAULT_DOMAIN_NAMES,
    min_keywords: int = 5,
) -> ExtractedRecord:
    """Project one ``Dataset.corpus.Record`` into ``(W_i, Meta_i)``.

    Takes the record structurally rather than importing ``Dataset.corpus``, so
    this module is testable without a corpus on disk — which matters, since the
    committed manifest is the superseded v1 and ``load_verified_corpus()``
    currently refuses to load anything at all.

    ``min_keywords`` defaults to the corpus's own ``min_keywords_per_record: 5``,
    itself taken from the published ``q = 5``: a record with fewer keywords than
    the query size can never match a conjunctive query, so indexing it would add
    weight that is never returned.
    """
    keywords = tuple(getattr(record, "kw", ()) or ())
    if len(keywords) < min_keywords:
        raise ExtractionError(
            f"record {getattr(record, 'rid', '?')} has |W_i|={len(keywords)} < "
            f"{min_keywords}; a record with fewer keywords than the query size "
            f"can never match a conjunctive query"
        )
    if len(set(keywords)) != len(keywords):
        raise ExtractionError(
            f"record {getattr(record, 'rid', '?')} has duplicate keywords in W_i"
        )

    domain = domain_name(int(record.dom), domain_names)
    patient = str(record.pid)
    return ExtractedRecord(
        record_id=int(record.rid),
        # Sorted so the entry order of a record's Merkle tree is a function of
        # its keyword SET. Phase IV Step 4 batches per record, and an
        # insertion-order-dependent Root_i could not be recomputed by a verifier.
        keywords=tuple(sorted(keywords)),
        metadata=RecordMetadata(
            policy_id=assignment.policy_id(patient_pseudonym=patient, domain=domain),
            vid=int(record.vid),
            domain=domain,
            timestamp=str(record.ts),
        ),
        patient_pseudonym=patient,
    )


def extract_all(
    records: Iterable,
    *,
    assignment: PolicyAssignment,
    domain_names: Sequence[str] = DEFAULT_DOMAIN_NAMES,
    min_keywords: int = 5,
    limit: Optional[int] = None,
) -> Iterator[ExtractedRecord]:
    """Stream extraction over a corpus.

    A generator, not a list: README §14 issue 9 records that materialising the
    1.14M-record corpus costs 1-2 GB per process, and Exp. 2 sweeps index size to
    10^6. ``limit`` takes the prefix an experiment point needs without reading
    the rest.
    """
    for count, record in enumerate(records):
        if limit is not None and count >= limit:
            return
        yield extract(
            record,
            assignment=assignment,
            domain_names=domain_names,
            min_keywords=min_keywords,
        )


__all__ = [
    "DEFAULT_DOMAIN_NAMES",
    "ExtractionError",
    "PolicyAssignment",
    "BucketedPolicyAssignment",
    "PerPatientPolicyAssignment",
    "ExtractedRecord",
    "domain_name",
    "extract",
    "extract_all",
]
