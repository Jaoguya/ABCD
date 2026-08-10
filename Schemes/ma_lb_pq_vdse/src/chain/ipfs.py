"""Phase V Step 1 — encrypted data outsourcing to content-addressed storage.

Manuscript `Overleaf/PQ-AVDSE-OJCOMS:741`:

    CT_i  = ( C_i, I_i, Commit_i )
    CID_i = IPFS.Upload(CT_i)

"which serves as the immutable reference for subsequent retrieval."

**What is uploaded is ``C_i``, not the published ``CT_i``, and the reason is a
circularity in the published definition.** ``CT_i`` contains ``I_i``, the index
entry set; each entry is ``I_j = (T_j, CID_i, PID_i, VID_i)`` (Phase IV Step 3) and
therefore contains ``CID_i``. But ``CID_i`` is *derived from* ``CT_i`` — IPFS
addresses content by its hash. Computing the CID of content that contains its own
CID is impossible.

The resolution that keeps every other published statement true: the encrypted
record ``C_i`` is what IPFS stores and addresses, and ``Root_i`` and ``Commit_i``
travel as metadata — which is exactly what Phase V Step 2 registers and Step 3
anchors. Were they already inside the addressed content, registering them
separately would be redundant. Recorded in ``SCHEME.md``; worth correcting in §V.

**Content addressing is the property that matters**, not the CID format: the same
bytes must always yield the same identifier, and an identifier must always return
the bytes it was minted for. That is what makes ``CID_i`` an "immutable reference"
and what lets Phase VIII trust a fetch it did not perform itself.

:class:`InProcessContentStore` is a real content-addressed store, not a stub with a
counter — so deduplication and the immutability property behave as they will under
IPFS. Its identifiers carry a deliberate ``dev-`` prefix so they cannot be mistaken
for real IPFS CIDs in a log, a fixture, or a committed result: a genuine CIDv1 is
multibase-encoded multihash, and producing something that *looked* like one would
invite exactly that confusion.
"""

from __future__ import annotations

import base64
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

#: Prefix marking a development identifier. Every reportable run needs a real
#: IPFS daemon, because ``CID_i`` is bound into ``BC_i`` and returned by search.
DEV_CID_PREFIX = "dev-cid-"

_CID_DOMAIN = b"ipfs-cid/v1"


class ContentStoreError(RuntimeError):
    """Raised when content cannot be stored or retrieved."""


class ContentNotFound(ContentStoreError):
    """Raised when a CID names content the store does not hold."""


class ContentStore(ABC):
    """The storage interface Phase V Step 1 and Phase VIII Step 4 share.

    A real IPFS client implements this; :class:`InProcessContentStore` is what the
    scheme runs against until the daemon is available. Phase VIII Step 4 (ciphertext
    retrieval) is outside Exp. 4's measurement boundary, so nothing timed depends on
    which implementation is live — but ``CID_i`` itself is bound into ``BC_i``, so a
    reportable run does.
    """

    @abstractmethod
    def put(self, content: bytes) -> str:
        """Store content, returning its identifier. Idempotent by construction."""

    @abstractmethod
    def get(self, cid: str) -> bytes:
        """Return the content ``cid`` names. Raises :class:`ContentNotFound`."""

    @abstractmethod
    def has(self, cid: str) -> bool:
        ...

    @abstractmethod
    def __len__(self) -> int:
        """Distinct objects held — deduplicated, so this is not the put count."""

    def verify(self, cid: str) -> bool:
        """Check that stored content still hashes to its identifier.

        Content addressing makes tampering self-evident: altered bytes no longer
        match the CID they are filed under. This is the check that turns that from a
        property of the design into one the code can assert.
        """
        try:
            content = self.get(cid)
        except ContentNotFound:
            return False
        return self.content_id(content) == cid

    @staticmethod
    def content_id(content: bytes) -> str:
        """The identifier for these bytes — a pure function of the content."""
        digest = hashes.sha256(content, domain=_CID_DOMAIN)
        encoded = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
        return f"{DEV_CID_PREFIX}{encoded}"


@dataclass
class InProcessContentStore(ContentStore):
    """Content-addressed storage in one process.

    Correct for everything except the reportable-run requirement of a real daemon:
    the identifier is a function of the content, storing the same bytes twice is one
    object, and retrieval returns exactly what was stored.
    """

    _objects: Dict[str, bytes] = field(default_factory=dict, repr=False)
    _puts: int = field(default=0, repr=False)

    def put(self, content: bytes) -> str:
        if not isinstance(content, (bytes, bytearray)):
            raise TypeError(
                f"content must be bytes, got {type(content).__name__}"
            )
        if not content:
            raise ContentStoreError("refusing to store empty content")
        cid = self.content_id(bytes(content))
        self._puts += 1
        existing = self._objects.get(cid)
        if existing is not None and existing != bytes(content):
            # Only reachable on a SHA-256 collision, which would be a finding in
            # its own right. Checked because silently overwriting would break the
            # immutability CID_i is relied on for.
            raise ContentStoreError(
                f"identifier collision on {cid!r}: two distinct objects"
            )
        self._objects[cid] = bytes(content)
        return cid

    def get(self, cid: str) -> bytes:
        try:
            return self._objects[cid]
        except KeyError:
            raise ContentNotFound(f"no content stored for CID {cid!r}") from None

    def has(self, cid: str) -> bool:
        return cid in self._objects

    def __len__(self) -> int:
        return len(self._objects)

    @property
    def put_count(self) -> int:
        """Total ``put`` calls, including duplicates — for measuring dedup."""
        return self._puts

    @property
    def bytes_stored(self) -> int:
        return sum(len(content) for content in self._objects.values())

    def __repr__(self) -> str:
        return (
            f"InProcessContentStore(objects={len(self._objects)}, "
            f"puts={self._puts}, bytes={self.bytes_stored})"
        )


def upload_ciphertext(store: ContentStore, ciphertext: bytes) -> str:
    """``CID_i = IPFS.Upload(C_i)`` — Phase V Step 1.

    Named for what it takes: the encrypted record, not the published ``CT_i``. See
    the module docstring on why the published tuple cannot be what is addressed.
    """
    return store.put(ciphertext)


__all__ = [
    "DEV_CID_PREFIX",
    "ContentStoreError",
    "ContentNotFound",
    "ContentStore",
    "InProcessContentStore",
    "upload_ciphertext",
]
