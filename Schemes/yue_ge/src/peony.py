"""Peony — forward-private multilevel DSSE. Ref[55] §V, Algorithm 1.

Four algorithms: ``KeyGen``, ``ListGen``, ``Update``, ``Search``.

The shape of the thing
----------------------
For each keyword ``w`` and each update batch ``c``, the owner builds one
encrypted linked list over the files touching ``w``, ordered by access level
DESCENDING. A user at level ``a(u)`` is handed the address of the first node at
their own level and walks forward; because the list is level-ordered, walking
forward from level ``a(u)`` reaches exactly the files at level ``<= a(u)`` and
nothing above. That single ordering trick is what makes the scheme multilevel
without per-level duplication of the file list.

Forward privacy comes from the per-batch state ``st_c``. Every PRF input is
``w||st_c``, so a token issued when ``c`` batches existed derives addresses only
for those ``c`` batches. Data added later is unreachable by an old token —
which is the definition (§V-C, Definition 5): the update leakage function is
stateless.

Client cost is one constrained-PRF evaluation, independent of how many files
come back (§VII-B: "The search time for the data users in both Peony and
Peony++ remains constant at 0.95 us"). The server does the ``3c`` derivations.

Three PRFs, named as the paper names them
-----------------------------------------
    F1_{k_l}(w||st_c)  -> the table address in T_c
    F2_{k_l}(w||st_c)  -> the mask over the start address
    F3_{k_l}(w||st_c)  -> the node-decryption key for level l

All three are keyed by the LEVEL key ``k_l``, which is why a level-2 user cannot
derive a level-3 node key even holding the whole index.
"""

from __future__ import annotations

from array import array
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set, Tuple

from Common.crypto.hashes import hmac_sha256, sha256
from Common.crypto.rng import secure_random_bytes, secure_random_int

from .index import EncryptedIndex, UpdateBatch
from .levels import sort_descending_by_level
from .params import SchemeParams

# Widths. The node blob packs (id, next_address, next_key); see _pack_node.
ID_BYTES = 8
ADDR_BYTES = 8
KEY_BYTES = 32
NODE_BLOB_BYTES = ID_BYTES + ADDR_BYTES + KEY_BYTES  # 48
OP_ADD = 1
OP_DEL = 0


# ---------------------------------------------------------------------------
# Keys and tokens
# ---------------------------------------------------------------------------
@dataclass
class OwnerKey:
    """``K_O = ({k_l}_{l in [|L|]}, st_1, st_2, ..., st_n)`` — KeyGen."""

    level_keys: Dict[int, bytes]
    states: List[bytes] = field(default_factory=list)

    def state(self, batch_id: int) -> bytes:
        """``st_c``. Batches are 1-based, matching the paper."""
        while len(self.states) < batch_id:
            self.states.append(secure_random_bytes(16))
        return self.states[batch_id - 1]


@dataclass
class SearchToken:
    """What the data user sends: ``{tk_{w,a(u)}, ST}`` — Algorithm 1, Search.

    ``tk`` is the constrained key. In the paper the server derives all ``3c``
    PRF values from it via ``F.Eval``; here ``tk`` is the level key restricted
    to this keyword, which is the same capability: it opens ``w`` at level
    ``a(u)`` for every batch in ``ST`` and nothing else.
    """

    tk: bytes
    level: int
    states: List[bytes]

    @property
    def size_bytes(self) -> int:
        """Search communication cost — the paper reports 96 B for Peony (§VII-B).

        One PRF value plus the update states, which is exactly what the paper
        counts: "includes only one PRF value and two random strings st".
        """
        return len(self.tk) + sum(len(s) for s in self.states)


@dataclass
class SearchOutcome:
    """Server result plus the counters the benchmark needs."""

    result_ids: Set[int]
    nodes_traversed: int = 0
    table_lookups: int = 0
    prf_evaluations: int = 0
    batches_scanned: int = 0


# ---------------------------------------------------------------------------
# F.Cons / F.Eval — the constrained PRF of §III-A
# ---------------------------------------------------------------------------
def f_cons(level_key: bytes, keyword: str) -> bytes:
    """``F.Cons(k_{a(u)}, w)`` — constrain the level key to one keyword.

    The predicate is the prefix ``w``: the constrained key evaluates the PRF at
    any input beginning with ``w`` and nothing else. Instantiated as an HMAC
    over the keyword, which is the standard prefix-constrained construction and
    matches the paper's OpenSSL/HMAC toolchain (§VII-A).
    """
    return hmac_sha256(level_key, b"yue_ge/cons", keyword.encode("utf-8"))


def f_eval(tk: bytes, state: bytes, index: int) -> bytes:
    """``F.Eval(tk_{w,a(u)}, st_j || i)`` — Algorithm 1, Search lines 3-5.

    ``index`` selects which of the three per-batch values is wanted:
    1 -> tau_1 (table address), 2 -> tau_2 (address mask), 3 -> tau_3 (node key).
    """
    return hmac_sha256(tk, state, bytes([index]))


def _f_level(level_key: bytes, keyword: str, state: bytes, index: int) -> bytes:
    """Owner-side ``F{index}_{k_l}(w||st_c)``.

    Identical by construction to ``f_eval(f_cons(k_l, w), st_c, index)`` — the
    owner and the server must land on the same value or the index is unopenable.
    ``test_scheme.py`` asserts that equality directly rather than trusting it.
    """
    return f_eval(f_cons(level_key, keyword), state, index)


# ---------------------------------------------------------------------------
# KeyGen — Algorithm 1
# ---------------------------------------------------------------------------
def keygen(params: SchemeParams) -> OwnerKey:
    """``KeyGen(1^lambda)`` — one key per access level, plus update states."""
    return OwnerKey(
        level_keys={
            lvl: secure_random_bytes(params.lambda_bytes)
            for lvl in range(1, params.access_levels + 1)
        },
        states=[],
    )


# ---------------------------------------------------------------------------
# ListGen — Algorithm 1
# ---------------------------------------------------------------------------
def list_gen(
    entries: Sequence[Tuple[int, int]],
    op: int,
    address_pool: "AddressAllocator",
) -> Tuple[List[Tuple[int, int]], Dict[int, int], List[int]]:
    """``ListGen(D_w, c, op)`` -> ``(L_w, X_w, N_w)``.

    Args:
        entries: ``(file_id, file_level)`` pairs for this keyword.
        op: ``OP_ADD`` or ``OP_DEL``.
        address_pool: supplies distinct random addresses (ListGen line 10).

    Returns:
        ``L_w`` as ``(file_id, op)`` sorted descending by level,
        ``X_w`` as ``{level: start_index}``,
        ``N_w`` as the address list.

    ON X_w — AN ASSUMPTION THE PAPER DOES NOT STATE
    ----------------------------------------------
    ``X_w[l]`` is the index of the first entry whose level is EXACTLY ``l``, and
    levels absent from this batch get no entry at all (``T_c`` then stores bottom
    for them — Algorithm 1, Update lines 12-13).

    It is tempting to "improve" this to the first entry with level ``<= l``, so a
    level-2 user could still reach a level-1 file in a batch containing no
    level-2 file. **That does not work, and the reason is in the masking.**
    Update line 5 masks node ``j`` with its OWN level key:

        A_c[N_w[j]] <- ((L_w[j], N_w[j+1], F3_{k_a(L_w[j+1])}(w||st_c))
                        XOR H(F3_{k_a(L_w[j])}(w||st_c), r_j),  r_j)

    while Search line 5 has the user derive ``tau_3 = F3_{k_a(u)}(w||st_j)`` —
    their own level's key, and only that. So the entry node must be masked under
    exactly ``k_{a(u)}``, i.e. must sit at exactly level ``a(u)``. After the
    first hop the chain is self-keying (each node carries the next node's key,
    Search line 12), which is why traversal continues correctly downward through
    lower levels; but the FIRST hop cannot be redirected.

    CONSEQUENCE — a real limitation of the published scheme, not of this code:
    if a batch contains no file at level ``l`` for keyword ``w``, a level-``l``
    user sees nothing from that batch for ``w``, even if it holds files at levels
    below ``l`` they are entitled to. The paper never states the assumption that
    every level is populated per batch; at its own scale (2.2M files, 3 levels,
    batched updates) it holds overwhelmingly and the case never arises.

    Implemented as published rather than repaired: strengthening a baseline
    beyond its published construction is forbidden, and silently
    fixing this would credit Peony with recall it does not have. Instead the
    condition is COUNTED (``UpdateBatch.sparse_levels``) so a run that hits it
    reports the fact rather than quietly losing results. ``workload.py`` also
    sizes batches so the corpus does not land in the degenerate regime.
    """
    level_of = {fid: lvl for fid, lvl in entries}
    ordered = sort_descending_by_level([(fid, op) for fid, _ in entries], level_of)

    x: Dict[int, int] = {}
    for pos, (fid, _op) in enumerate(ordered):
        lvl = level_of[fid]
        if lvl not in x:
            x[lvl] = pos

    n = [address_pool.next() for _ in ordered]
    return ordered, x, n


class AddressAllocator:
    """Distinct random addresses within one ``A_c`` — ListGen line 10.

    "Randomly select the non-repeating ``addr_j`` (``1 <= addr_j <= |A_c|``)."
    Taken literally: ``capacity`` non-repeating draws from ``[1, capacity]`` are
    a random permutation of the whole address space, so the allocator IS a
    shuffled ``1..capacity``, handed out one at a time.

    That is what makes ``A_c`` dense (see ``index.NodeArray``), and it is the
    only reading under which the paper's own bound ``addr_j <= |A_c|`` holds —
    an allocator drawing from a 64-bit space violates it on the first draw.

    The shuffle uses ``SecureRandom`` rather than ``DeterministicRNG``: node
    placement is key-dependent secret material (it is what the address mask
    ``tau_2`` hides), not a reproducible experiment artefact, so it belongs on
    the OS entropy side of the rule in ``Common/crypto/rng.py``.
    """

    def __init__(self, capacity: int) -> None:
        if capacity < 0:
            raise ValueError(f"|A_c| must be non-negative, got {capacity}")
        self.capacity = capacity
        # Fisher-Yates over 1..capacity, drawing each swap index from OS
        # entropy. array("q") rather than a list: at the published N = 10^6
        # sweep point a batch holds ~8M addresses, which is 64 MB packed
        # against ~280 MB as boxed Python ints.
        self._order = array("q", range(1, capacity + 1))
        for i in range(capacity - 1, 0, -1):
            j = secure_random_int(i + 1)
            self._order[i], self._order[j] = self._order[j], self._order[i]
        self._next = 0

    def next(self) -> int:
        if self._next >= self.capacity:
            raise IndexError(
                f"A_c exhausted: {self.capacity} addresses allocated, more "
                "requested — the batch was sized smaller than its node count"
            )
        addr = int(self._order[self._next])
        self._next += 1
        return addr


# ---------------------------------------------------------------------------
# Update — Algorithm 1
# ---------------------------------------------------------------------------
def update(
    params: SchemeParams,
    key: OwnerKey,
    index: EncryptedIndex,
    batch_id: int,
    per_keyword: Dict[str, List[Tuple[int, int]]],
    op: int = OP_ADD,
) -> UpdateBatch:
    """``Update(D_W, c, K_O)`` — Algorithm 1.

    Builds ``I_c = (A_c, T_c)`` for one batch and hands it to the server.

    Args:
        per_keyword: ``{keyword: [(file_id, file_level), ...]}`` for this batch.
        op: ``OP_ADD`` or ``OP_DEL``. Peony encodes deletions as index entries
            (Peony++ does not — see ``peony_plus.py``).
    """
    st = key.state(batch_id)
    batch = UpdateBatch(batch_id=batch_id)
    # |A_c| — ListGen line 10's bound. Known before anything is written: it is
    # the node count of this batch, one node per (keyword, file) posting.
    capacity = sum(len(e) for e in per_keyword.values())
    pool = AddressAllocator(capacity)
    nodes = batch.allocate(capacity)

    for keyword, entries in per_keyword.items():
        if not entries:
            continue
        level_of = {fid: lvl for fid, lvl in entries}
        L_w, X_w, N_w = list_gen(entries, op, pool)

        # --- Lines 3-8: the encrypted linked list in A_c ---
        for j, (fid, op_j) in enumerate(L_w):
            is_last = j == len(L_w) - 1
            next_addr = 0 if is_last else N_w[j + 1]
            if is_last:
                next_key = b"\x00" * KEY_BYTES
            else:
                next_level = level_of[L_w[j + 1][0]]
                next_key = _f_level(
                    key.level_keys[next_level], keyword, st, 3
                )

            blob = _pack_node(fid, op_j, next_addr, next_key)

            # Mask under THIS node's level key: H(F3_{k_a(L_w[j])}(w||st_c), r_j)
            this_level = level_of[fid]
            tau3 = _f_level(key.level_keys[this_level], keyword, st, 3)
            r_j = secure_random_bytes(16)
            masked = _xor(blob, _mask(tau3, r_j, len(blob)))
            nodes.put(N_w[j], masked, r_j)

        # --- Lines 9-15: the entry table T_c ---
        for lvl in range(1, params.access_levels + 1):
            tau1 = _f_level(key.level_keys[lvl], keyword, st, 1)
            if lvl in X_w:
                tau2 = _f_level(key.level_keys[lvl], keyword, st, 2)
                start_addr = N_w[X_w[lvl]]
                batch.T[tau1] = _xor(
                    start_addr.to_bytes(ADDR_BYTES, "big"),
                    tau2[:ADDR_BYTES],
                )
            else:
                # Line 13: bottom — this level sees nothing in this batch.
                batch.T[tau1] = None
                batch.sparse_levels += 1

    index.add_batch(batch)
    return batch


# ---------------------------------------------------------------------------
# Search — Algorithm 1
# ---------------------------------------------------------------------------
def token_gen(key: OwnerKey, keyword: str, user_level: int,
              batch_count: int) -> SearchToken:
    """Data-user side of Search, lines 1-3.

    ``tk_{w,a(u)} <- F.Cons(k_{a(u)}, w)`` and ``ST = {st_1..st_c}``. This is
    the whole client cost — one constrained-PRF evaluation, no dependence on
    result size. It is the operation Exp. 1 measures.
    """
    return SearchToken(
        tk=f_cons(key.level_keys[user_level], keyword),
        level=user_level,
        states=[key.state(c) for c in range(1, batch_count + 1)],
    )


def search(token: SearchToken, index: EncryptedIndex) -> SearchOutcome:
    """Server side of Search, lines 1-20.

    Walks batches from newest to oldest (line 2: ``for j = c to 1``), and within
    each batch follows the encrypted chain applying ``add``/``del``. Newest
    first matters: a later deletion must be able to cancel an earlier addition.
    """
    out = SearchOutcome(result_ids=set())

    for batch in reversed(index.batches):
        if batch.batch_id > len(token.states):
            # Forward privacy in action: this batch postdates the token, and
            # the token cannot derive its state. Not an error — the server
            # simply has no address for it.
            continue
        st = token.states[batch.batch_id - 1]
        out.batches_scanned += 1

        tau1 = f_eval(token.tk, st, 1)
        tau2 = f_eval(token.tk, st, 2)
        tau3 = f_eval(token.tk, st, 3)
        out.prf_evaluations += 3

        out.table_lookups += 1
        masked_addr = batch.lookup(tau1)
        if masked_addr is None:
            continue  # line 6-8: bottom, nothing at this level in this batch

        v2 = int.from_bytes(
            _xor(masked_addr, tau2[:ADDR_BYTES]), "big"
        )

        # Lines 10-18: walk the chain.
        while v2 != 0:
            node = batch.node(v2)
            if node is None:
                break
            masked, r_j = node
            blob = _xor(masked, _mask(tau3, r_j, len(masked)))
            fid, op_j, next_addr, next_key = _unpack_node(blob)
            out.nodes_traversed += 1

            if op_j == OP_ADD:
                out.result_ids.add(fid)
            else:
                out.result_ids.discard(fid)

            v2 = next_addr
            tau3 = next_key if next_addr else tau3

    return out


# ---------------------------------------------------------------------------
# node packing / masking
# ---------------------------------------------------------------------------
def _pack_node(fid: int, op: int, next_addr: int, next_key: bytes) -> bytes:
    """``(L_w[j], N_w[j+1], F3_...)`` as a fixed-width blob.

    ``op`` rides in the top bit of the id field — the paper stores ``id||op``
    (ListGen line 5), so it is one field, not two.
    """
    tagged = (fid << 1) | (op & 1)
    return (
        tagged.to_bytes(ID_BYTES, "big")
        + next_addr.to_bytes(ADDR_BYTES, "big")
        + next_key[:KEY_BYTES].ljust(KEY_BYTES, b"\x00")
    )


def _unpack_node(blob: bytes) -> Tuple[int, int, int, bytes]:
    tagged = int.from_bytes(blob[:ID_BYTES], "big")
    next_addr = int.from_bytes(blob[ID_BYTES:ID_BYTES + ADDR_BYTES], "big")
    next_key = blob[ID_BYTES + ADDR_BYTES:NODE_BLOB_BYTES]
    return tagged >> 1, tagged & 1, next_addr, next_key


def _mask(tau3: bytes, r: bytes, length: int) -> bytes:
    """``H(F3_..., r_j)`` stretched to ``length`` bytes.

    The paper writes a single hash application; SHA-256 gives 32 bytes and the
    node blob is 48, so the mask is generated in counter-indexed blocks. This is
    the standard way to instantiate ``H`` as a variable-length mask and does not
    change what is XORed where.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += sha256(tau3, r, bytes([counter]), domain=b"yue_ge/nodemask")
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
