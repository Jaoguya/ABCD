"""Phase V Steps 2-3 — metadata registration and the initial ``BC_i`` anchor.

Manuscript `Overleaf/PQ-AVDSE-OJCOMS:763` (Step 2):

    Meta_i = ( CID_i, PID_i, VID_i, Root_i, Commit_i )

"Instead of recording encrypted data on-chain, the Data Owner registers only
compact searchable metadata… maintained by the cloud--fog infrastructure and
synchronized with the consortium blockchain."

And `:780` (Step 3):

    BC_i = ( CID_i, Commit_i, Root_i, VID_i, TS_i )

"Since only compact metadata are recorded, the blockchain storage complexity
remains independent of the encrypted IoMT data size."

So there are two registers, not one: an off-chain metadata register the
infrastructure maintains (Step 2, :class:`~..types.OutsourcedMetadata`) and the
on-chain transaction (Step 3, :class:`~..types.BlockchainAnchor`). They overlap in
four fields and differ in two — Step 2 carries ``PID_i``, Step 3 carries ``TS_i``
— which is why both exist.

**This closes the Phase VIII Step 3 gap.** Until now only Phase VII Step 7 wrote
an anchor, so a record that had never been updated had no ``BC_i`` and blockchain
consistency verification failed for it. :func:`anchor_initial_commitment` writes
the version-0 anchor at outsourcing time, which is where the manuscript puts it.

**No ciphertext and no index entries reach the ledger** — five fields, two of them
digests. That is the whole basis of the storage-complexity claim, and
:func:`outsource_record` asserts it rather than trusting the call sites.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from ..index.commit import RecordCommitment  # noqa: E402
from ..types import (  # noqa: E402
    BlockchainAnchor,
    IndexEntry,
    OutsourcedMetadata,
    RecordMetadata,
)
from .ipfs import ContentStore, upload_ciphertext  # noqa: E402
# Phase VII Step 7 anchors into the version-identifier namespace and Phase VIII
# Step 3 reads from it, so Step 3's initial anchor must land in the same place —
# otherwise a record's history would be split across two namespaces.
from .ledger import Ledger, NS_VERSION_IDENTIFIERS  # noqa: E402


class OutsourcingError(RuntimeError):
    """Raised when a record cannot be outsourced."""


class MetadataRegister:
    """Phase V Step 2's off-chain register, "maintained by the cloud--fog
    infrastructure".

    Keyed by ``CID_i``. Registering a *different* ``Meta_i`` under an existing CID
    is refused: the CID addresses immutable content, so two different metadata
    records for one CID would mean two different claims about the same bytes, and a
    reader would resolve it by whichever it happened to see. Version changes go
    through Phase VII, which anchors a new ``BC_i``.
    """

    def __init__(self) -> None:
        self._by_cid: Dict[str, OutsourcedMetadata] = {}

    def __len__(self) -> int:
        return len(self._by_cid)

    def __contains__(self, cid: str) -> bool:
        return cid in self._by_cid

    def register(self, metadata: OutsourcedMetadata) -> OutsourcedMetadata:
        existing = self._by_cid.get(metadata.cid)
        if existing is not None and existing != metadata:
            raise OutsourcingError(
                f"CID {metadata.cid!r} is already registered with different "
                f"metadata (policy {existing.policy_id!r} at VID {existing.vid}); "
                f"a CID addresses immutable content, so it cannot carry two "
                f"different claims"
            )
        self._by_cid[metadata.cid] = metadata
        return metadata

    def get(self, cid: str) -> OutsourcedMetadata:
        try:
            return self._by_cid[cid]
        except KeyError:
            raise OutsourcingError(f"CID {cid!r} is not registered") from None

    def all(self) -> Tuple[OutsourcedMetadata, ...]:
        return tuple(
            sorted(self._by_cid.values(), key=lambda meta: meta.cid)
        )

    def __repr__(self) -> str:
        return f"MetadataRegister(records={len(self._by_cid)})"


def register_metadata(
    register: MetadataRegister,
    *,
    cid: str,
    metadata: RecordMetadata,
    commitment: RecordCommitment,
) -> OutsourcedMetadata:
    """Phase V Step 2: ``Meta_i = (CID_i, PID_i, VID_i, Root_i, Commit_i)``.

    ``PID_i`` and ``VID_i`` come from the record's Phase IV ``Meta_i`` and
    ``Root_i``/``Commit_i`` from its Phase IV commitment, so the registered
    metadata cannot disagree with what was committed.
    """
    return register.register(
        OutsourcedMetadata(
            cid=cid,
            policy_id=metadata.policy_id,
            vid=metadata.vid,
            root=commitment.root,
            commit=commitment.commit,
        )
    )


def anchor_key(cid: str, vid: int) -> str:
    """Ledger key for ``BC_i`` — the same scheme Phase VII Step 7 uses.

    Zero-padded so lexicographic order is version order. Both writers and
    ``verify/ledger.py`` must agree on this, or Step 3 looks up keys that were
    never written.
    """
    if vid < 0:
        raise ValueError(f"VID must be non-negative, got {vid}")
    return f"{cid}#{vid:012d}"


def anchor_initial_commitment(
    ledger: Ledger,
    *,
    cid: str,
    commitment: RecordCommitment,
    vid: int,
    timestamp_ns: Optional[int] = None,
) -> BlockchainAnchor:
    """Phase V Step 3: anchor ``BC_i`` for a newly outsourced record.

    The same record and the same key scheme Phase VII Step 7 uses for ``BC_i'``, so
    a record's anchors form one ordered history from version 0 onward and Phase
    VIII Step 3 needs no special case for "never updated".
    """
    anchor = BlockchainAnchor(
        cid=cid,
        commit=commitment.commit,
        root=commitment.root,
        vid=vid,
        timestamp_ns=time.time_ns() if timestamp_ns is None else timestamp_ns,
    )
    ledger.append(NS_VERSION_IDENTIFIERS, anchor_key(cid, vid), anchor)
    return anchor



@dataclass(frozen=True)
class OutsourcingReceipt:
    """One record outsourced — Phase V Steps 1-3."""

    cid: str
    metadata: OutsourcedMetadata
    anchor: BlockchainAnchor
    ciphertext_bytes: int

    @property
    def on_chain_bytes(self) -> int:
        """``BC_i``'s encoded size — the storage-complexity claim, measured."""
        return len(self.anchor.encode())

    @property
    def off_chain_bytes(self) -> int:
        return self.ciphertext_bytes


def outsource_record(
    *,
    store: ContentStore,
    ledger: Ledger,
    register: MetadataRegister,
    ciphertext: bytes,
    metadata: RecordMetadata,
    commitment: RecordCommitment,
    entries: Sequence[IndexEntry] = (),
    timestamp_ns: Optional[int] = None,
) -> OutsourcingReceipt:
    """Phase V Steps 1-3 for one record: upload, register, anchor.

    ``entries`` is optional and used only for a consistency check: every entry must
    reference the ``CID_i`` the upload produced. Passing them catches the ordering
    mistake the published Step 1 invites — building the index before the CID exists
    — which would leave entries pointing at nothing.

    Asserts that the on-chain footprint is independent of the record size, which is
    Step 3's stated property and the one a reviewer is most likely to check.
    """
    cid = upload_ciphertext(store, ciphertext)

    mismatched = [entry for entry in entries if entry.cid != cid]
    if mismatched:
        raise OutsourcingError(
            f"{len(mismatched)} of {len(entries)} index entries reference a CID "
            f"other than {cid!r}; the index must be built over the CID the upload "
            f"returned"
        )

    registered = register_metadata(
        register, cid=cid, metadata=metadata, commitment=commitment
    )
    anchor = anchor_initial_commitment(
        ledger,
        cid=cid,
        commitment=commitment,
        vid=metadata.vid,
        timestamp_ns=timestamp_ns,
    )
    receipt = OutsourcingReceipt(
        cid=cid,
        metadata=registered,
        anchor=anchor,
        ciphertext_bytes=len(ciphertext),
    )
    # "only compact metadata are recorded" — the anchor must not carry the record.
    if ciphertext in anchor.encode():
        raise OutsourcingError(
            "the blockchain anchor contains the ciphertext; BC_i must hold only "
            "compact metadata"
        )
    return receipt


__all__ = [
    "OutsourcingError",
    "MetadataRegister",
    "OutsourcingReceipt",
    "register_metadata",
    "anchor_key",
    "anchor_initial_commitment",
    "outsource_record",
]
