"""Phase VII Step 3 — shard propagation and the index catalog.

Manuscript `Overleaf/MA-LB-PQ-VDSE.tex` (Step 4):

    Sync_i = ( I_i, PID_i, VID_i, CID_i )

"is propagated to the authorized Fog Search Nodes… Rather than replicating
encrypted IoMT data, each Fog Search Node maintains **only searchable-index
shards and corresponding metadata** required for encrypted search."

And (Step 5):

    Catalog <- Catalog ∪ (CID_i, PID_i, VID_i)

"allowing subsequent search requests to efficiently locate authorized
searchable-index shards without scanning the complete encrypted repository."

The payload itself is :class:`~..types.SyncPayload`, alongside every other
canonically-encoded protocol record. Applying one is
:meth:`~..fsn.fsn.FogSearchNode.apply_sync`, because a node receiving index state
is the node's own business — and since the node owns its shard, there is no
separate endpoint object to keep in step with it.

**Propagation is selective, and there is no broadcast.** Same discipline as
``aim/aim.py``: :func:`route` computes which nodes serve a domain and
:func:`propagate` takes the nodes to reach. Phase VII Step 4's selectivity is
what Exp. 6 measures, and a fan-out helper here would be inherited by the phase
that is supposed to be selective.

**Ordering precondition.** Step 4 opens "After successful blockchain
confirmation" — the record's ``BC_i`` transaction (Step 3) is anchored before its
index reaches the nodes. Steps 1-3 are not implemented, so that ordering is a
documented precondition rather than an enforced one; ``CID_i`` is likewise a
placeholder until Step 1 produces a real IPFS identifier.

Module path note: ``SCHEME.md`` maps Phase V to ``src/chain/``. This lives in
``src/shard/`` because it is about index distribution rather than the ledger or
IPFS adapters, which is what ``chain/`` holds.
"""

from __future__ import annotations

import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ..fsn.fsn import FSNError, FogSearchNode  # noqa: E402
from ..types import CatalogEntry, IndexEntry, RecordMetadata, SyncPayload  # noqa: E402

#: Stand-in for the IPFS content identifier Phase V Step 1 will produce.
PLACEHOLDER_CID_PREFIX = "placeholder-cid-"


class PropagationError(RuntimeError):
    """Raised when a record's index cannot be synchronised to the shards."""


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


def route(domain: str, nodes: Sequence[FogSearchNode]) -> Tuple[FogSearchNode, ...]:
    """The nodes authorized for ``domain`` — Step 4's "authorized FSNs".

    With the §VI defaults (``d = 4`` domains over ``m = 4`` nodes) this is exactly
    one node, which is what makes Phase VII's selective propagation observable: an
    update reaches one node in four.
    """
    targets = tuple(node for node in nodes if node.serves_domain(domain))
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
    nodes: Sequence[FogSearchNode],
) -> PropagationReceipt:
    """Phase V Step 4: send ``Sync_i`` to exactly the nodes given.

    The caller chooses the recipients — :func:`route` for the authorized set.
    There is deliberately no method that fans out to every node on its own.
    """
    if not nodes:
        raise PropagationError("no nodes to propagate to")
    applied = 0
    touched: List[str] = []
    for node in nodes:
        touched.append(node.node_id)
        try:
            applied += node.apply_sync(payload, domain=domain)
        except FSNError as exc:
            # The node owns the replay and domain checks; surface them as
            # propagation failures so a caller has one exception type to handle.
            raise PropagationError(str(exc)) from exc
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
    nodes: Sequence[FogSearchNode],
) -> PropagationReceipt:
    """Step 4 as published: route, then propagate to the authorized nodes."""
    return propagate(payload, domain=domain, nodes=route(domain, nodes))


# ===========================================================================
# Phase V Step 5 — the index catalog (:813)
# ===========================================================================
class IndexCatalog:
    """``Catalog <- Catalog ∪ (CID_i, PID_i, VID_i)`` — Phase V Step 5.

    Maintained by the AIM so that search "can efficiently locate authorized
    searchable-index shards without scanning the complete encrypted repository"
   .
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


__all__ = [
    "PLACEHOLDER_CID_PREFIX",
    "PropagationError",
    "PropagationReceipt",
    "IndexCatalog",
    "build_sync_payload",
    "placeholder_cid",
    "route",
    "propagate",
    "propagate_to_authorized",
]
