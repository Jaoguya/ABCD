"""Phase V Steps 4-5 — shard propagation and the index catalog.

Manuscript `Overleaf/PQ-AVDSE-OJCOMS:797` (Step 4):

    Sync_i = ( I_i, PID_i, VID_i, CID_i )

"is propagated to the authorized Fog Search Nodes… Rather than replicating
encrypted IoMT data, each Fog Search Node maintains **only searchable-index
shards and corresponding metadata** required for encrypted search. Consequently,
encrypted data remain stored exclusively in IPFS."

And `:813` (Step 5):

    Catalog <- Catalog ∪ (CID_i, PID_i, VID_i)

"allowing subsequent search requests to efficiently locate authorized
searchable-index shards without scanning the complete encrypted repository."

``I_i`` is the *record's* entry set from Phase IV Step 3 — note the index shift
from ``I_j``, a single entry, to ``I_i``, all of one record's entries.

**No ciphertext crosses this boundary.** ``Sync_i`` carries index entries and
metadata, never ``CT_i``: the entries reference IPFS by ``CID_i`` and the
ciphertext stays there. That is what makes the synchronisation overhead Step 4
claims to be low, and a payload that carried data would silently turn every FSN
into a replica of the encrypted store.

**Propagation is selective, and there is no broadcast.** Same discipline as
``aim/aim.py``: :func:`route` computes which nodes serve a domain and
:func:`propagate` takes the endpoints to reach. Phase VII Step 6's selectivity is
what Exp. 6 measures, and a fan-out helper here would be inherited by the phase
that is supposed to be selective.

**Ordering precondition.** Step 4 opens "After successful blockchain
confirmation" — the record's ``BC_i`` transaction (Step 3) is anchored before its
index reaches the nodes. Steps 1-3 are not implemented, so that ordering is a
documented precondition here rather than an enforced one; ``CID_i`` is likewise a
placeholder until Step 1 produces a real IPFS identifier. Both are isolated the
same way ``SK_{U,i}`` was while Phase III Step 2 was open.

Module path note: ``SCHEME.md`` maps Phase V to ``src/chain/``. This lives in
``src/shard/`` because it is about index distribution rather than the ledger or
IPFS adapters, which is what ``chain/`` holds.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Dict, Iterable, List, Optional, Sequence, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ..fsn.fsn import FogSearchNode  # noqa: E402
from ..index.dsi import DynamicSearchIndex  # noqa: E402
from ..types import IndexEntry, Record, RecordMetadata  # noqa: E402

#: Stand-in for the IPFS content identifier Phase V Step 1 will produce.
PLACEHOLDER_CID_PREFIX = "placeholder-cid-"


class PropagationError(RuntimeError):
    """Raised when a record's index cannot be synchronised to the shards."""


@dataclass(frozen=True)
class SyncPayload(Record):
    """``Sync_i = (I_i, PID_i, VID_i, CID_i)`` — Phase V Step 4.

    A :class:`Record`, so the payload has a canonical encoding and a digest: what
    reaches a node is exactly what a receipt can be checked against.

    Carries no ciphertext field, deliberately — see the module docstring.
    """

    DOMAIN: ClassVar[bytes] = b"sync-payload/v1"

    entries: Tuple[IndexEntry, ...]
    policy_id: str
    vid: int
    cid: str

    def __post_init__(self) -> None:
        if not self.entries:
            raise PropagationError(
                "Sync_i must carry at least one index entry; the corpus "
                "guarantees |W_i| >= 5"
            )
        if not self.policy_id:
            raise ValueError("policy_id must not be empty")
        if not self.cid:
            raise ValueError("cid must not be empty")
        if self.vid < 0:
            raise ValueError(f"VID must be non-negative, got {self.vid}")
        # The payload binds ONE (PID_i, VID_i) pair, exactly as Commit_i does. An
        # entry under a different pair would be synchronised under a policy it
        # does not belong to, and the node's bitmap would then authorize it wrongly.
        mismatched = [
            entry
            for entry in self.entries
            if entry.policy_id != self.policy_id or entry.vid != self.vid
        ]
        if mismatched:
            raise PropagationError(
                f"{len(mismatched)} of {len(self.entries)} entries carry a "
                f"policy/version other than ({self.policy_id!r}, {self.vid}); "
                f"Sync_i binds a single pair"
            )
        if any(entry.cid != self.cid for entry in self.entries):
            raise PropagationError(
                f"every entry in Sync_i must reference CID {self.cid!r}; a "
                f"payload spanning records would be applied atomically to one "
                f"shard when its records may belong to different domains"
            )

    def _encoded_fields(self):
        return (list(self.entries), self.policy_id, self.vid, self.cid)

    @property
    def entry_count(self) -> int:
        """``|I_i|`` — equals ``|W_i|`` for a freshly indexed record."""
        return len(self.entries)

    @property
    def size_bytes(self) -> int:
        """On-wire size of the synchronisation message.

        The Exp. 6 secondary metric is the IAS message size; this is its Phase V
        counterpart, and the figure that backs Step 4's "low synchronization
        overhead" claim.
        """
        return len(self.encode())


def build_sync_payload(
    *,
    entries: Sequence[IndexEntry],
    metadata: RecordMetadata,
    cid: str,
) -> SyncPayload:
    """Assemble ``Sync_i`` for one record.

    ``PID_i`` and ``VID_i`` come from the record's ``Meta_i`` rather than from the
    entries, so a payload cannot be built that disagrees with the metadata the
    record was committed under.
    """
    return SyncPayload(
        entries=tuple(entries),
        policy_id=metadata.policy_id,
        vid=metadata.vid,
        cid=cid,
    )


def placeholder_cid(record_id: int) -> str:
    """A stand-in ``CID_i`` until Phase V Step 1 produces a real one.

    Named so it cannot be mistaken for an IPFS identifier in a log or a test
    fixture. Every reportable run needs real CIDs, because ``CID_i`` is bound into
    ``BC_i`` (Step 3) and returned by search (Phase VI Step 4).
    """
    return f"{PLACEHOLDER_CID_PREFIX}{record_id}"


@dataclass
class ShardEndpoint:
    """One Fog Search Node together with the PDSI shard it serves.

    Phase I Step 4 built the node (queue, ``VID_j``, ``N_j``) and Phase IV Step 3
    built the index; this pairs them, which is the composition Phase V Step 4
    needs and the first point in the protocol where both exist.

    ``N_j`` is deliberately kept in two places — ``node.shard.entry_count``, which
    Phase VI's ``C_j^verify`` reads, and the index's own count. Two counters that
    can diverge is a real wart, so :meth:`assert_consistent` exists and a test
    calls it after every mutation: a scheduler costing queries against a stale
    ``N_j`` would produce plausible, wrong Exp. 2 numbers.
    """

    node: FogSearchNode
    index: DynamicSearchIndex
    _applied: Set[str] = field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        if self.node.domains != self.index.domains:
            raise PropagationError(
                f"{self.node.node_id} serves {sorted(self.node.domains)} but its "
                f"shard holds {sorted(self.index.domains)}; the node set and the "
                f"shard set must be partitioned by one rule"
            )

    @property
    def node_id(self) -> str:
        return self.node.node_id

    @property
    def domains(self):
        return self.node.domains

    @property
    def entry_count(self) -> int:
        """``N_j``, read from the index — the single authority for the count."""
        return self.index.entry_count

    def serves(self, domain: str) -> bool:
        return self.node.serves_domain(domain)

    def has_applied(self, cid: str) -> bool:
        return cid in self._applied

    def apply(self, payload: SyncPayload, *, domain: str) -> int:
        """Apply ``Sync_i`` to this endpoint. Returns entries inserted.

        Refuses a replay: a second application of the same ``CID_i`` would insert
        the record's entries twice, inflating ``N_j`` and returning duplicate hits
        for one record — a corruption that no proof would catch, because each
        duplicate entry is individually well-formed.
        """
        if not self.serves(domain):
            raise PropagationError(
                f"{self.node_id} serves {sorted(self.domains)} and is not an "
                f"authorized node for domain {domain!r}"
            )
        if self.has_applied(payload.cid):
            raise PropagationError(
                f"{self.node_id} has already applied Sync_i for CID "
                f"{payload.cid!r}; re-applying would double-insert the record"
            )
        self.index.insert_record(payload.entries, domain=domain)
        self.node.shard.add_entries(payload.entry_count)
        self._applied.add(payload.cid)
        return payload.entry_count

    def assert_consistent(self) -> None:
        """``N_j`` as the node reports it must equal the index's live count."""
        if self.node.entry_count != self.index.entry_count:
            raise PropagationError(
                f"{self.node_id}: node reports N_j={self.node.entry_count} but "
                f"its shard holds {self.index.entry_count} entries"
            )

    def __repr__(self) -> str:
        return (
            f"ShardEndpoint({self.node_id}, domains={sorted(self.domains)}, "
            f"N_j={self.entry_count}, records={len(self._applied)})"
        )


@dataclass(frozen=True)
class PropagationReceipt:
    """Outcome of one Step 4 synchronisation.

    ``fsns_touched`` counts nodes contacted, matching ``aim.PropagationResult``:
    contacting a node is the cost, and Exp. 6 reports it.
    """

    cid: str
    domain: str
    entry_count: int
    payload_bytes: int
    fsns_touched: Tuple[str, ...]

    @property
    def touched_count(self) -> int:
        return len(self.fsns_touched)


def route(domain: str, endpoints: Sequence[ShardEndpoint]) -> Tuple[ShardEndpoint, ...]:
    """The endpoints authorized for ``domain`` — Step 4's "authorized FSNs".

    With the §V defaults (``d = 4`` domains over ``m = 4`` nodes) this is exactly
    one endpoint, which is what makes Phase VII's selective propagation
    observable: an update reaches one node in four.
    """
    targets = tuple(endpoint for endpoint in endpoints if endpoint.serves(domain))
    if not targets:
        raise PropagationError(
            f"no Fog Search Node serves domain {domain!r}; its records would be "
            f"indexed nowhere and silently unsearchable"
        )
    return targets


def propagate(
    payload: SyncPayload,
    *,
    domain: str,
    endpoints: Sequence[ShardEndpoint],
) -> PropagationReceipt:
    """Phase V Step 4: send ``Sync_i`` to exactly the endpoints given.

    The caller chooses the recipients — :func:`route` for the authorized set.
    There is deliberately no method that fans out to every endpoint on its own.
    """
    if not endpoints:
        raise PropagationError("no endpoints to propagate to")
    applied = 0
    touched: List[str] = []
    for endpoint in endpoints:
        touched.append(endpoint.node_id)
        applied += endpoint.apply(payload, domain=domain)
    return PropagationReceipt(
        cid=payload.cid,
        domain=domain,
        entry_count=applied,
        payload_bytes=payload.size_bytes,
        fsns_touched=tuple(touched),
    )


def propagate_to_authorized(
    payload: SyncPayload,
    *,
    domain: str,
    endpoints: Sequence[ShardEndpoint],
) -> PropagationReceipt:
    """Step 4 as published: route, then propagate to the authorized nodes."""
    return propagate(payload, domain=domain, endpoints=route(domain, endpoints))


# ===========================================================================
# Phase V Step 5 — the index catalog (:813)
# ===========================================================================
@dataclass(frozen=True)
class CatalogEntry(Record):
    """``(CID_i, PID_i, VID_i)`` — one catalog row."""

    DOMAIN: ClassVar[bytes] = b"catalog-entry/v1"

    cid: str
    policy_id: str
    vid: int
    domain: str

    def __post_init__(self) -> None:
        for name in ("cid", "policy_id", "domain"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")
        if self.vid < 0:
            raise ValueError(f"VID must be non-negative, got {self.vid}")

    def _encoded_fields(self):
        return (self.cid, self.policy_id, self.vid, self.domain)


class IndexCatalog:
    """``Catalog <- Catalog ∪ (CID_i, PID_i, VID_i)`` — Phase V Step 5.

    Maintained by the AIM so that search "can efficiently locate authorized
    searchable-index shards without scanning the complete encrypted repository"
    (`:813`). ``domain`` is carried alongside the published triple because
    locating a *shard* requires knowing which node holds it, and shards are
    domain-keyed — the triple alone identifies the record but not its location.
    """

    def __init__(self) -> None:
        self._by_cid: Dict[str, CatalogEntry] = {}

    def __len__(self) -> int:
        return len(self._by_cid)

    def __contains__(self, cid: str) -> bool:
        return cid in self._by_cid

    def add(self, entry: CatalogEntry) -> None:
        """Insert a row. A set union, so re-adding an identical row is a no-op.

        A *different* row under an existing ``CID_i`` is refused: that would mean
        one record catalogued under two policies, and a search would resolve it
        by whichever row it happened to read.
        """
        existing = self._by_cid.get(entry.cid)
        if existing is not None and existing != entry:
            raise PropagationError(
                f"CID {entry.cid!r} is already catalogued as "
                f"({existing.policy_id!r}, {existing.vid}) and cannot be "
                f"re-catalogued as ({entry.policy_id!r}, {entry.vid}); update "
                f"the version through Phase VII instead"
            )
        self._by_cid[entry.cid] = entry

    def record(self, payload: SyncPayload, *, domain: str) -> CatalogEntry:
        """Catalogue a synchronised record."""
        entry = CatalogEntry(
            cid=payload.cid,
            policy_id=payload.policy_id,
            vid=payload.vid,
            domain=domain,
        )
        self.add(entry)
        return entry

    def get(self, cid: str) -> CatalogEntry:
        try:
            return self._by_cid[cid]
        except KeyError:
            raise PropagationError(f"CID {cid!r} is not catalogued") from None

    def locate(
        self, authorized: Iterable[Tuple[str, str]]
    ) -> Tuple[CatalogEntry, ...]:
        """Rows a user authorized for these ``(domain, policy)`` pairs may reach.

        The Phase VI Step 2 shortcut: resolve authorized shards from the catalog
        instead of scanning the repository.
        """
        pairs = {tuple(pair) for pair in authorized}
        return tuple(
            sorted(
                (
                    entry
                    for entry in self._by_cid.values()
                    if (entry.domain, entry.policy_id) in pairs
                ),
                key=lambda e: e.cid,
            )
        )

    def domains(self) -> Tuple[str, ...]:
        return tuple(sorted({entry.domain for entry in self._by_cid.values()}))

    def __repr__(self) -> str:
        return f"IndexCatalog(records={len(self._by_cid)})"


def build_endpoints(
    nodes: Sequence[FogSearchNode], indexes: Sequence[DynamicSearchIndex]
) -> Tuple[ShardEndpoint, ...]:
    """Pair nodes with shards, positionally.

    Both come from the same domain assignment — ``fsn.build_fsn_set`` and
    ``dsi.build_shards`` over one ``assign_domains_to_fsns`` result — so position
    is the correspondence. :class:`ShardEndpoint` re-checks that the domains
    agree, so a mismatched pairing fails here rather than routing entries to the
    wrong shard.
    """
    if len(nodes) != len(indexes):
        raise PropagationError(
            f"{len(nodes)} nodes and {len(indexes)} shards; each Fog Search Node "
            f"maintains exactly one shard set"
        )
    return tuple(
        ShardEndpoint(node=node, index=index)
        for node, index in zip(nodes, indexes)
    )


__all__ = [
    "PLACEHOLDER_CID_PREFIX",
    "PropagationError",
    "SyncPayload",
    "ShardEndpoint",
    "PropagationReceipt",
    "CatalogEntry",
    "IndexCatalog",
    "build_sync_payload",
    "placeholder_cid",
    "route",
    "propagate",
    "propagate_to_authorized",
    "build_endpoints",
]
