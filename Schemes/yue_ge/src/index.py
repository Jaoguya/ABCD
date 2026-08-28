"""Server-side encrypted index for Ref[55] — the pair ``I_c = (A_c, T_c)``.

Ref[55] Algorithm 1, Update line 17: "Send ``I_c <- (A_c, T_c)`` to the server",
and the server's only job is "Store the received encrypted index by setting
``I = I union I_c``".

So the index is a *list of per-batch* structures, one per update batch ``c`` —
not one merged table. That is load-bearing for forward privacy: search must be
told which batches to look in (via ``ST = {st_1..st_c}``), and a token for
batches ``1..c`` is structurally unable to address batch ``c+1``.

Two containers per batch:

  ``A_c``  the address array holding the encrypted linked-list nodes. Node
           payloads are XOR-masked; the server can only unmask a node once it
           holds the right ``tau_3``, which it only gets from a valid token.

  ``T_c``  the entry table mapping ``F1_{k_l}(w||st_c)`` to the masked address
           of the first node at level ``l``. ``bottom`` (``None`` here) when a
           level sees nothing in this batch — Algorithm 1, Update lines 12-13.

``A_c`` IS A DENSE ARRAY, BECAUSE THE PAPER SAYS IT IS
-----------------------------------------------------
ListGen line 10: "Randomly select the non-repeating ``addr_j``
(``1 <= addr_j <= |A_c|``)". Non-repeating draws over ``[1, |A_c|]``, one per
node, are a random PERMUTATION of the address space — so every slot is filled
and the array is dense, not sparse. ``A_c`` is therefore one flat ``bytearray``
of ``|A_c|`` fixed-width slots, indexed arithmetically.

This started as a dict keyed by a random 64-bit address, on the reasoning that
it "avoids needing ``|A_c|`` up front". ``|A_c|`` is in fact known up front —
it is the node count of the batch being built, which ``Update``/``Add`` already
hold before they write anything — and the dict cost ~245 B of CPython object
overhead per node (int key, tuple, two ``bytes`` headers, table slot) on top of
the ~312 B of actual payload. At the published ``N = 10^6`` sweep point that is
17.8 GB against ``global.yaml``'s 16 GiB host; the dense array is 9.9 GB and
fits. Measured, not estimated: see ``debug_history.md``.

Address ``0`` is reserved as the end-of-chain terminator (``next_addr = 0``),
which is why addresses run ``1..|A_c|`` as the paper writes them rather than
``0..|A_c|-1``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# A node payload: (masked_blob, r_j).  Algorithm 1, Update lines 5 and 8.
Node = Tuple[bytes, bytes]


class NodeArray:
    """``A_c`` — ``capacity`` fixed-width slots in one contiguous buffer.

    Slot ``addr`` (1-based, as the paper numbers them) holds ``blob || r_j`` at
    byte offset ``(addr - 1) * record_bytes``. The width is fixed by the
    construction and the parameters — Peony's node blob is 48 B, Peony++'s is
    ``4 + |t| + h * (8 + |ct_i|) + 8 + 32`` — so it is learned from the first
    node written and then enforced, rather than being guessed here.
    """

    __slots__ = ("capacity", "record_bytes", "_buf", "_filled", "_blob_bytes")

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.record_bytes = 0      # learned from the first put()
        self._buf: bytearray = bytearray()
        self._filled = 0
        self._blob_bytes = 0

    def put(self, address: int, blob: bytes, r: bytes) -> None:
        if not 1 <= address <= self.capacity:
            raise IndexError(
                f"address {address} outside A_c = [1, {self.capacity}]"
            )
        width = len(blob) + len(r)
        if self.record_bytes == 0:
            self.record_bytes = width
            self._buf = bytearray(self.capacity * width)
            self._blob_bytes = len(blob)
        elif width != self.record_bytes:
            raise ValueError(
                f"node width {width} != {self.record_bytes}; A_c slots are "
                "fixed-width and every node in a batch must share the layout"
            )
        off = (address - 1) * width
        self._buf[off:off + width] = blob + r
        self._filled += 1

    def get(self, address: int) -> Optional[Node]:
        """``A_j[v_2]`` — None when the address is outside the array."""
        if not 1 <= address <= self.capacity or self.record_bytes == 0:
            return None
        off = (address - 1) * self.record_bytes
        rec = self._buf[off:off + self.record_bytes]
        return bytes(rec[:self._blob_bytes]), bytes(rec[self._blob_bytes:])

    def __len__(self) -> int:
        return self._filled

    @property
    def size_bytes(self) -> int:
        return len(self._buf)


@dataclass
class UpdateBatch:
    """One batch ``I_c = (A_c, T_c)``, exactly as the server receives it."""

    batch_id: int
    A: Optional[NodeArray] = None
    T: Dict[bytes, Optional[bytes]] = field(default_factory=dict)

    # Count of (keyword, level) pairs where this batch holds no file at exactly
    # that level, so T stores bottom. Each one is a level whose users cannot
    # reach this batch at all — see peony.list_gen's "ON X_w" note. Counted, not
    # repaired: repairing it would give the baseline recall the published
    # construction does not have.
    sparse_levels: int = 0

    # ---- server-side operations (Algorithm 1, Search) ----
    def lookup(self, tau1: bytes) -> Optional[bytes]:
        """``T_j[tau^j_1]`` — returns None for both 'absent' and 'bottom'."""
        return self.T.get(tau1)

    def allocate(self, capacity: int) -> "NodeArray":
        """Size ``A_c`` before writing into it — ``|A_c|`` is the node count."""
        self.A = NodeArray(capacity)
        return self.A

    def node(self, address: int) -> Optional[Node]:
        """``A_j[v_2]``."""
        return self.A.get(address) if self.A is not None else None

    @property
    def node_count(self) -> int:
        return len(self.A) if self.A is not None else 0

    @property
    def entry_count(self) -> int:
        return len(self.T)

    @property
    def size_bytes(self) -> int:
        """Serialised index size — Exp. 5 secondary metric.

        ``A_c`` is its own byte count: a dense array carries no per-node key,
        which is exactly what makes it dense.
        """
        total = self.A.size_bytes if self.A is not None else 0
        for tag, val in self.T.items():
            total += len(tag) + (len(val) if val else 0)
        return total


@dataclass
class EncryptedIndex:
    """``I`` — the union of every batch the server has stored."""

    batches: List[UpdateBatch] = field(default_factory=list)

    def add_batch(self, batch: UpdateBatch) -> None:
        """``I = I union I_c`` — Algorithm 1, Update, Server line 1."""
        self.batches.append(batch)

    @property
    def batch_count(self) -> int:
        return len(self.batches)

    @property
    def total_nodes(self) -> int:
        return sum(b.node_count for b in self.batches)

    @property
    def total_entries(self) -> int:
        return sum(b.entry_count for b in self.batches)

    @property
    def size_bytes(self) -> int:
        return sum(b.size_bytes for b in self.batches)

    def __len__(self) -> int:
        return len(self.batches)
