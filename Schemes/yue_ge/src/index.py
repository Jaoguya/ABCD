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

``A_c`` is a dict keyed by address rather than a Python list. The paper picks
addresses at random from ``|A_c|`` (ListGen line 10), so the array is sparse by
construction; a dict is the honest representation and avoids pretending the
server allocates a dense array it never fills.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# A node payload: (masked_blob, r_j).  Algorithm 1, Update lines 5 and 8.
Node = Tuple[bytes, bytes]


@dataclass
class UpdateBatch:
    """One batch ``I_c = (A_c, T_c)``, exactly as the server receives it."""

    batch_id: int
    A: Dict[int, Node] = field(default_factory=dict)
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

    def node(self, address: int) -> Optional[Node]:
        """``A_j[v_2]``."""
        return self.A.get(address)

    @property
    def node_count(self) -> int:
        return len(self.A)

    @property
    def entry_count(self) -> int:
        return len(self.T)

    @property
    def size_bytes(self) -> int:
        """Serialised index size — Exp. 5 secondary metric."""
        total = 0
        for blob, r in self.A.values():
            total += len(blob) + len(r) + 8  # +8 for the address key
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
