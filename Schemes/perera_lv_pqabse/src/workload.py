"""Mapping the corpus onto Ref[54]'s Phase 2/3 inputs.

The corpus carries ``rid/pid/vid/dom/ts/kw`` (``Dataset.corpus.Record``). Ref[54]
indexes more field types than that — numeric ranges, categorical equality,
temporal epochs, fuzzy terms — so this module states exactly which corpus field
plays each role, rather than leaving the mapping implicit in a runner.

    keywords     Record.kw            (the B+-tree, exact match)
    epoch        Record.ts year       (temporal partitioning, Phase 3)
    category     Record.dom           (categorical equality bitmap)
    fuzzy terms  Record.kw            (n-gram map)

The numeric-range bitmap has no corpus field to index: the corpus carries no
numeric observation values. It is therefore built EMPTY and never queried, and
no Exp. 1-3 measurement depends on it — recorded here rather than quietly
populated with a synthesised field, which skill.md forbids.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from Common.crypto.rng import DeterministicRNG
from Dataset.corpus import Record

from . import scheme
from .hybrid_index import HybridIndex
from .params import SchemeParams


def epoch_of(record: Record) -> str:
    """Temporal partition key — the year of ``TS_i``."""
    return (record.ts or "unknown")[:4]


def build_fog_node(
    keys: scheme.SystemKeys,
    records: Sequence[Record],
    params: SchemeParams,
    *,
    with_abe: Optional[bool] = None,
) -> scheme.FogNode:
    """Phases 2-3 over ``records``. Untimed setup (skill.md).

    ``with_abe`` defaults to crypto.yaml's ``abe_on_measured_path`` (false):
    Exp. 1-3 read no ``ct_abe``, and producing one per record costs 758 ms
    here — 21 h at N = 10^5 — while changing no measured quantity. See
    ``abe.py`` and the crypto.yaml block for the full reasoning.
    """
    if with_abe is None:
        with_abe = params.abe_on_measured_path

    node = scheme.FogNode(keys=keys, index=HybridIndex(ngram_size=params.ngram_size))
    grow_fog_node(keys, node, records, params, with_abe=with_abe)
    return node


def grow_fog_node(
    keys: scheme.SystemKeys,
    node: "scheme.FogNode",
    records: Sequence[Record],
    params: SchemeParams,
    *,
    with_abe: Optional[bool] = None,
) -> "scheme.FogNode":
    """Ingest more records into an EXISTING fog node, then re-finalize.

    Exp. 2's sweep points are nested prefixes, so growing one index costs the
    largest point rather than the sum of all of them. `finalize()` recomputes
    the partition Merkle roots over everything ingested so far, so the node
    after growing to n is the node a fresh build of `records[:n]` produces.
    """
    if with_abe is None:
        with_abe = params.abe_on_measured_path

    for record in records:
        ct = scheme.edge_encrypt(
            keys, record.rid, b"", list(range(params.attribute_universe)),
        ) if with_abe else _light_ciphertext(keys, record)
        node.ingest(
            ct, record.kw, epoch=epoch_of(record), category=record.dom,
            fuzzy_terms=record.kw[:1],
        )
    node.finalize()
    return node


def _light_ciphertext(keys: scheme.SystemKeys, record: Record):
    """A Phase 2 ciphertext without ``ct_abe``.

    Everything the fog actually verifies at Phase 3 is still real and still
    checked — the AES-GCM body, the ML-KEM encapsulation, the provenance tag
    and digest, and the Dilithium3 edge signature. Only the CP-ABE payload-key
    encapsulation, which nothing in Exp. 1-3 reads, is absent.
    """
    return scheme.edge_encrypt(
        keys, record.rid, record.ts.encode("utf-8"), (),
    )


def keyword_frequency(records: Sequence[Record]) -> Dict[str, int]:
    freq: Dict[str, int] = {}
    for record in records:
        for kw in record.kw:
            freq[kw] = freq.get(kw, 0) + 1
    return freq


def select_keywords(
    freq: Dict[str, int], rng: DeterministicRNG, count: int, *,
    min_frequency: int = 2,
) -> List[str]:
    """Query keywords, drawn from terms that actually occur in this subset.

    Weighted by frequency so queries follow the corpus's Zipf shape rather than
    sampling the long tail uniformly — a uniform draw would return almost
    exclusively singleton keywords and make every search trivially cheap.
    """
    eligible = [w for w, n in freq.items() if n >= min_frequency]
    if not eligible:
        eligible = list(freq)
    if not eligible:
        return []
    eligible.sort(key=lambda w: (-freq[w], w))
    top = eligible[: max(1, len(eligible) // 4)]
    return [top[int(rng.integers(0, len(top)))] for _ in range(count)]
