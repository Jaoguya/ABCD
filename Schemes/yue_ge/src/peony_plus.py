"""Peony++ — forward + Type-II backward private, publicly verifiable MLDSSE.

Scheme 30 §VI. Built from Peony (§V) plus MSRE (§IV), with multilevel digests
published to a smart contract for public verification.

    Setup, ListGen, Add, Delete, Search, Verify

What changes relative to Peony
------------------------------
1. **Nodes carry MSRE ciphertexts, not plaintext ids.** ``ListGen`` computes a
   tag ``t <- F_{K_t}(w, id)`` and stores ``ct <- MSRE.Enc(lsk, id, a(id), t)``
   (§VI-A). The server walks the same linked list but must run ``MSRE.Dec`` to
   learn an identifier.

2. **Deletion never touches the server.** Peony writes a ``del`` entry into the
   index; Peony++ instead inserts the tag into the owner's local Bloom filters
   (§VI-A, Delete). That is the Type-II backward-privacy mechanism: the server
   is not asked to honor a delete flag, it is made unable to decrypt. It is also
   why the paper's deletion cost is microseconds (Table VII) — no round-trip.

3. **Every Add publishes a digest.** ``prooflist[pt^c_{w,l}]`` commits to the
   files added at level ``<= l`` in batch ``c``, and ``Verify`` recomputes it.

The verification algebra
------------------------
This is the part worth reading carefully, because it is what makes verification
constant-size rather than proportional to the result set.

    prooflist[pt^c_{w,l}] = H(0, r^c_{w,l}) XOR (XOR_{j added, level<=l} H(1, C_idj))
    proof_del             = (XOR_{j deleted} H(1, C_idj)) XOR (XOR_i H(0, r^i_{w,l}))

XOR the prooflist entries over batches ``1..c`` and then XOR in ``proof_del``:
the ``H(0, r^i)`` terms cancel pairwise, the deleted ``H(1, C_id)`` terms cancel
against their own additions, and what survives is exactly

    XOR_{j still present} H(1, C_idj)

which is what the server's returned result set hashes to. That is multiset
hashing over XOR: order-independent, one 32-byte digest regardless of how many
files match. The cancellation is the whole trick.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from Common.crypto.hashes import hmac_sha256
from Common.crypto.rng import secure_random_bytes
from Common.crypto.symmetric import Ciphertext
from Common.crypto.symmetric import encrypt as se_encrypt

from . import msre
from .digest import keccak256, xor_digest, ZERO_DIGEST
from .index import EncryptedIndex, UpdateBatch
from .levels import levels_to_update_on_delete
from .msre import MSRECiphertext, MSREKey, RevokedKey
from .params import SchemeParams
from .peony import (
    ADDR_BYTES,
    KEY_BYTES,
    OP_ADD,
    AddressAllocator,
    OwnerKey,
    SearchOutcome,
    SearchToken,
    _f_level,
    _mask,
    _xor,
    f_cons,
    f_eval,
    keygen,
    list_gen,
)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
@dataclass
class ProofList:
    """The smart contract's storage — Scheme 30 §VI-A.

    A dict standing in for on-chain key/value storage. The paper measures gas to
    *deploy* entries here (Fig. 8); this benchmark measures the *computation*
    that produces and checks them, per the Exp. 4 boundary recorded in
    ``References/Ref[55]/Ref[55].md`` §6.
    """

    entries: Dict[bytes, bytes] = field(default_factory=dict)

    def publish(self, pt: bytes, digest: bytes) -> None:
        self.entries[pt] = digest

    def get(self, pt: bytes) -> Optional[bytes]:
        return self.entries.get(pt)

    @property
    def size_bytes(self) -> int:
        """On-chain storage. The paper reports 144 B per added batch (§VII-B)."""
        return sum(len(k) + len(v) for k, v in self.entries.items())

    def __len__(self) -> int:
        return len(self.entries)


@dataclass
class OwnerState:
    """Everything the data owner keeps. Never sent to the server wholesale."""

    params: SchemeParams
    key: OwnerKey
    kt: bytes                                        # K_t, tag derivation key
    msre_keys: Dict[str, MSREKey] = field(default_factory=dict)
    # C_id per file — the AES ciphertext the digests commit to.
    cid: Dict[int, bytes] = field(default_factory=dict)
    # Accumulated XOR of H(1, C_id) over DELETED files, per (keyword, level).
    deleted_acc: Dict[Tuple[str, int], bytes] = field(default_factory=dict)
    # Which batches touched a given keyword — needed to rebuild proof_del.
    keyword_batches: Dict[str, List[int]] = field(default_factory=dict)
    # Revocation lists R per keyword: (tag, file_level).
    revoked: Dict[str, List[Tuple[bytes, int]]] = field(default_factory=dict)

    def msre_key_for(self, keyword: str, deletions_hint: int) -> MSREKey:
        """``LSK[w]`` — one MSRE key per keyword (§VI-B)."""
        if keyword not in self.msre_keys:
            self.msre_keys[keyword] = msre.bgen(
                array_bits=self.params.bloom_array_bits(deletions_hint),
                num_hashes=self.params.bloom_num_hashes,
                access_levels=self.params.access_levels,
                output_bytes=self.params.punc_output_bytes,
                key_bytes=self.params.lambda_bytes,
            )
        return self.msre_keys[keyword]


@dataclass
class PlusSearchToken:
    """``{tk_{w,a(u)}, ST, sk_{R_l}, B_{w,a(u)}}`` — §VI-A Search.

    The owner assists: it supplies the revoked key and the deletion filter
    alongside the user's constrained key. §IX lists removing that assistance as
    future work, so the dependency is the paper's own, not an artifact here.
    """

    base: SearchToken
    revoked_key: Optional[RevokedKey]

    @property
    def size_bytes(self) -> int:
        """Search communication cost — the paper's §VII-B metric."""
        n = self.base.size_bytes
        if self.revoked_key is not None:
            n += self.revoked_key.size_bytes
        return n


@dataclass
class VerifyOutcome:
    accepted: bool
    proof_expected: bytes
    proof_computed: bytes
    entries_combined: int


# ---------------------------------------------------------------------------
# Setup — §VI-A
# ---------------------------------------------------------------------------
def setup(params: SchemeParams) -> Tuple[OwnerState, EncryptedIndex, ProofList]:
    """``Setup(1^lambda, D, U) -> (KL, DL, UL)``.

    Generates the per-level keys, the tag key ``K_t``, and the empty server
    index and contract storage.
    """
    return (
        OwnerState(
            params=params,
            key=keygen(params),
            kt=secure_random_bytes(params.lambda_bytes),
        ),
        EncryptedIndex(),
        ProofList(),
    )


# ---------------------------------------------------------------------------
# tags and file ciphertexts
# ---------------------------------------------------------------------------
def make_tag(state: OwnerState, keyword: str, file_id: int) -> bytes:
    """``t <- F_{K_t}(w, id)`` — §VI-A ListGen."""
    return hmac_sha256(
        state.kt, b"yue_ge/tag", keyword.encode("utf-8"),
        file_id.to_bytes(8, "big"),
    )


def make_cid(state: OwnerState, file_id: int) -> bytes:
    """``C_id`` — the AES ciphertext the digests commit to.

    §VI-A: "C_id represents a file encrypted using the AES algorithm.
    Importantly, for identical plaintext files, the resulting ciphertext
    varies." AES-GCM with a fresh random nonce gives exactly that, so two
    records with identical content still commit to distinct digests.

    BENCHMARK NOTE: this repo's corpus carries record identifiers and keyword
    sets, not document bodies (``Dataset.corpus.Record``). ``C_id`` is therefore
    the encryption of the identifier rather than of a file payload. Exp. 4 is
    scoped to verification computation only (skill.md), so no measured quantity
    depends on the plaintext length — but the substitution is recorded here
    rather than left implicit.
    """
    if file_id not in state.cid:
        ct = se_encrypt(_widen(state.key.level_keys[1]), file_id.to_bytes(8, "big"))
        state.cid[file_id] = ct.to_bytes()
    return state.cid[file_id]


def _widen(key: bytes) -> bytes:
    from Common.crypto.hashes import sha256

    return key if len(key) == 32 else sha256(key, domain=b"yue_ge/filekey")


# ---------------------------------------------------------------------------
# digest helpers — §VI-A
# ---------------------------------------------------------------------------
def _pt(state: OwnerState, keyword: str, level: int, batch_id: int) -> bytes:
    """``pt^c_{w,l}`` — the prooflist label.

    Derived from the level-constrained key so only a user who can search
    ``(w, l)`` can locate the corresponding on-chain entry.
    """
    tk = f_cons(state.key.level_keys[level], keyword)
    return keccak256(b"pt", tk, batch_id.to_bytes(4, "big"))


def _r(state: OwnerState, keyword: str, level: int, batch_id: int) -> bytes:
    """``r^c_{w,l} = H(F.Cons(k_l, w), c||2)`` — §VI-A."""
    tk = f_cons(state.key.level_keys[level], keyword)
    return keccak256(tk, batch_id.to_bytes(4, "big"), b"\x02")


def _h0(r: bytes) -> bytes:
    """``H(0, r)``."""
    return keccak256(b"\x00", r)


def _h1(cid: bytes) -> bytes:
    """``H(1, C_id)``."""
    return keccak256(b"\x01", cid)


# ---------------------------------------------------------------------------
# Add — §VI-A
# ---------------------------------------------------------------------------
def add(
    state: OwnerState,
    index: EncryptedIndex,
    prooflist: ProofList,
    batch_id: int,
    per_keyword: Dict[str, List[Tuple[int, int]]],
) -> UpdateBatch:
    """``Add(D_add, c, KL) -> (A_c, T_c, prooflist)`` — §VI-A.

    Follows Peony's Update, with two differences: nodes hold MSRE ciphertexts,
    and each ``(keyword, level)`` gets a published digest.
    """
    params = state.params
    st = state.key.state(batch_id)
    batch = UpdateBatch(batch_id=batch_id)
    capacity = sum(len(e) for e in per_keyword.values())
    pool = AddressAllocator(capacity)
    nodes = batch.allocate(capacity)

    for keyword, entries in per_keyword.items():
        if not entries:
            continue
        state.keyword_batches.setdefault(keyword, []).append(batch_id)
        lsk = state.msre_key_for(keyword, params.deletions_between_searches)
        level_of = {fid: lvl for fid, lvl in entries}
        L_w, X_w, N_w = list_gen(entries, OP_ADD, pool)

        # --- encrypted linked list, nodes carrying MSRE ciphertexts ---
        for j, (fid, _op) in enumerate(L_w):
            is_last = j == len(L_w) - 1
            next_addr = 0 if is_last else N_w[j + 1]
            if is_last:
                next_key = b"\x00" * KEY_BYTES
            else:
                next_key = _f_level(
                    state.key.level_keys[level_of[L_w[j + 1][0]]],
                    keyword, st, 3,
                )

            tag = make_tag(state, keyword, fid)
            ct = msre.enc(lsk, fid.to_bytes(8, "big"), tag)

            blob = _pack_plus_node(ct, next_addr, next_key)
            tau3 = _f_level(state.key.level_keys[level_of[fid]], keyword, st, 3)
            r_j = secure_random_bytes(16)
            nodes.put(N_w[j], _xor(blob, _mask(tau3, r_j, len(blob))), r_j)

        # --- entry table ---
        for lvl in range(1, params.access_levels + 1):
            tau1 = _f_level(state.key.level_keys[lvl], keyword, st, 1)
            if lvl in X_w:
                tau2 = _f_level(state.key.level_keys[lvl], keyword, st, 2)
                batch.T[tau1] = _xor(
                    N_w[X_w[lvl]].to_bytes(ADDR_BYTES, "big"),
                    tau2[:ADDR_BYTES],
                )
            else:
                batch.T[tau1] = None
                batch.sparse_levels += 1

        # --- prooflist, one entry per level ---
        # Level l commits to every file at level <= l, matching what a level-l
        # user will actually be returned (§VI-A worked example).
        for lvl in range(1, params.access_levels + 1):
            acc = _h0(_r(state, keyword, lvl, batch_id))
            for fid, flvl in entries:
                if flvl <= lvl:
                    acc = xor_digest(acc, _h1(make_cid(state, fid)))
            prooflist.publish(_pt(state, keyword, lvl, batch_id), acc)

    index.add_batch(batch)
    return batch


# ---------------------------------------------------------------------------
# Delete — §VI-A
# ---------------------------------------------------------------------------
def delete(
    state: OwnerState,
    keyword: str,
    deletions: Sequence[Tuple[int, int]],
) -> None:
    """``Delete(LSK, W_del, D_del, R, LR)`` — §VI-A.

    Purely local: insert each tag into the owner's Bloom filters and fold the
    file's digest into the running deletion accumulator. No server round-trip,
    which is why the paper measures this in microseconds (Table VII).

    Args:
        deletions: ``(file_id, file_level)`` pairs to delete for ``keyword``.
    """
    params = state.params
    lsk = state.msre_key_for(keyword, params.deletions_between_searches)

    for fid, flvl in deletions:
        tag = make_tag(state, keyword, fid)
        state.revoked.setdefault(keyword, []).append((tag, flvl))

        # Set the filter bits, propagating upward (§IV-B MSRE.Comp).
        for lvl in levels_to_update_on_delete(flvl, params.access_levels):
            lsk.filters[lvl].add(tag)
            k = (keyword, lvl)
            state.deleted_acc[k] = xor_digest(
                state.deleted_acc.get(k, ZERO_DIGEST),
                _h1(make_cid(state, fid)),
            )


# ---------------------------------------------------------------------------
# Search — §VI-A
# ---------------------------------------------------------------------------
def token_gen(
    state: OwnerState,
    keyword: str,
    user_level: int,
    batch_count: int,
) -> PlusSearchToken:
    """Token generation, including the owner's revoked-key assistance.

    The data user's own cost is one ``F.Cons`` call; the owner adds
    ``sk_{R_l}`` and the deletion filter. Exp. 1 measures this whole path,
    because that is what has to happen before a query can be issued.
    """
    from .peony import token_gen as peony_token_gen

    base = peony_token_gen(state.key, keyword, user_level, batch_count)

    revoked_key = None
    if keyword in state.msre_keys:
        lsk = state.msre_keys[keyword]
        keys = msre.klrev(
            lsk, state.revoked.get(keyword, []), levels=[user_level]
        )
        revoked_key = keys[user_level]
    return PlusSearchToken(base=base, revoked_key=revoked_key)


def search(
    state: OwnerState,
    token: PlusSearchToken,
    index: EncryptedIndex,
    keyword: str,
) -> SearchOutcome:
    """Server-side search — Peony's traversal plus ``MSRE.Dec`` per node.

    A node whose ``MSRE.Dec`` returns ``None`` is one the server cannot open:
    either the tag was revoked, or the Bloom filter false-positived. Both are
    silently skipped, exactly as the construction intends — the server never
    learns which.
    """
    base = token.base
    out = SearchOutcome(result_ids=set())
    lsk = state.msre_keys.get(keyword)

    for batch in reversed(index.batches):
        if batch.batch_id > len(base.states):
            continue  # forward privacy: token predates this batch
        st = base.states[batch.batch_id - 1]
        out.batches_scanned += 1

        tau1 = f_eval(base.tk, st, 1)
        tau2 = f_eval(base.tk, st, 2)
        tau3 = f_eval(base.tk, st, 3)
        out.prf_evaluations += 3

        out.table_lookups += 1
        masked_addr = batch.lookup(tau1)
        if masked_addr is None:
            continue

        v2 = int.from_bytes(_xor(masked_addr, tau2[:ADDR_BYTES]), "big")

        while v2 != 0:
            node = batch.node(v2)
            if node is None:
                break
            masked, r_j = node
            blob = _xor(masked, _mask(tau3, r_j, len(masked)))
            ct, next_addr, next_key = _unpack_plus_node(blob)
            out.nodes_traversed += 1

            if lsk is not None and token.revoked_key is not None:
                plain = msre.dec(lsk.prf, token.revoked_key, ct)
                if plain is not None:
                    out.result_ids.add(int.from_bytes(plain, "big"))

            v2 = next_addr
            tau3 = next_key if next_addr else tau3

    return out


# ---------------------------------------------------------------------------
# Verify — §VI-A
# ---------------------------------------------------------------------------
def verify(
    state: OwnerState,
    prooflist: ProofList,
    keyword: str,
    user_level: int,
    result_ids: Iterable[int],
    batch_ids: Optional[Sequence[int]] = None,
) -> VerifyOutcome:
    """``Verify(R_{w,a(u)}, prooflist, proof_del)`` — §VI-A.

    Executed by the smart contract in the paper. Here it is the same
    computation, run off-chain: see ``References/Ref[55]/Ref[55].md`` §6 for why
    that is the right measurement boundary and why it is not the Ref[36]/SGX
    situation.

    Steps:
      1. XOR the ``prooflist`` entries for batches ``1..c`` at this level.
      2. XOR in the deletion digest ``proof_del``.
      3. Compare against ``XOR_{C_id in R} H(1, C_id)``.
    """
    batches = list(
        batch_ids if batch_ids is not None
        else state.keyword_batches.get(keyword, [])
    )

    # Step 1 — combine the published per-batch digests.
    proof = ZERO_DIGEST
    combined = 0
    for bid in batches:
        entry = prooflist.get(_pt(state, keyword, user_level, bid))
        if entry is None:
            continue
        proof = xor_digest(proof, entry)
        combined += 1

    # Step 2 — fold in the deletions, together with the H(0, r^i) terms that
    # cancel the ones already inside the prooflist entries.
    proof_del = state.deleted_acc.get((keyword, user_level), ZERO_DIGEST)
    for bid in batches:
        proof_del = xor_digest(proof_del, _h0(_r(state, keyword, user_level, bid)))
    proof = xor_digest(proof, proof_del)

    # Step 3 — hash the returned result set and compare.
    computed = ZERO_DIGEST
    for fid in result_ids:
        computed = xor_digest(computed, _h1(make_cid(state, fid)))

    return VerifyOutcome(
        accepted=(proof == computed),
        proof_expected=proof,
        proof_computed=computed,
        entries_combined=combined,
    )


# ---------------------------------------------------------------------------
# node packing for Peony++ (MSRE ciphertext payload)
# ---------------------------------------------------------------------------
def _pack_plus_node(
    ct: MSRECiphertext, next_addr: int, next_key: bytes
) -> bytes:
    parts = [
        len(ct.components).to_bytes(2, "big"),
        len(ct.tag).to_bytes(2, "big"),
        ct.tag,
    ]
    for pos, comp in zip(ct.positions, ct.components):
        raw = comp.to_bytes()
        parts.append(pos.to_bytes(4, "big"))
        parts.append(len(raw).to_bytes(4, "big"))
        parts.append(raw)
    parts.append(next_addr.to_bytes(ADDR_BYTES, "big"))
    parts.append(next_key[:KEY_BYTES].ljust(KEY_BYTES, b"\x00"))
    return b"".join(parts)


def _unpack_plus_node(blob: bytes) -> Tuple[MSRECiphertext, int, bytes]:
    off = 0
    n_comp = int.from_bytes(blob[off:off + 2], "big"); off += 2
    tag_len = int.from_bytes(blob[off:off + 2], "big"); off += 2
    tag = blob[off:off + tag_len]; off += tag_len

    positions: List[int] = []
    components: List[Ciphertext] = []
    for _ in range(n_comp):
        pos = int.from_bytes(blob[off:off + 4], "big"); off += 4
        raw_len = int.from_bytes(blob[off:off + 4], "big"); off += 4
        components.append(Ciphertext.from_bytes(blob[off:off + raw_len]))
        off += raw_len
        positions.append(pos)

    next_addr = int.from_bytes(blob[off:off + ADDR_BYTES], "big")
    off += ADDR_BYTES
    next_key = blob[off:off + KEY_BYTES]
    return (
        MSRECiphertext(components=components, tag=tag, positions=positions),
        next_addr,
        next_key,
    )
