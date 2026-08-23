"""Core VDSSE algorithms for Guo et al. (Ref[35]).

Implements Algorithms 1–4 from the paper:

  Setup  — Alg. 1, Ref[35].txt:641-650
  Update — Alg. 2, Ref[35].txt:797-877
  Search — Alg. 3, Ref[35].txt:1022-1138
  Verify — Alg. 4, Ref[35].txt:1152-1173

Every operation uses Common/crypto/ primitives.  Scheme-specific
constructions (the dual index, the conjunctive query protocol, the
verification tag design) are implemented here.

NO HARDCODED PARAMETERS.  Every numeric constant (λ, domain_bits,
hash_output_bits) is read from crypto.yaml via ``config.scheme_params``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from Common.crypto import config as crypto_config
from Common.crypto.prf import PuncturablePRF, PuncturedKey
from Common.crypto.rng import secure_random_bytes

from .index import EncryptedDatabase
from .state import ClientState

# =====================================================================
# Encoding helpers
# =====================================================================

_OP_ADD = b"\x01"
_OP_DEL = b"\x00"


def _encode_doc_id(rid: int) -> bytes:
    """Encode a record ID as 8-byte big-endian uint64."""
    return struct.pack(">Q", rid)


def _decode_doc_id(raw: bytes) -> int:
    """Decode an 8-byte big-endian uint64 back to an integer."""
    return struct.unpack(">Q", raw[:8])[0]


def _encode_keyword(w: str) -> bytes:
    """Encode a keyword string to bytes."""
    return w.encode("utf-8")


def _encode_int(n: int) -> bytes:
    """Encode a non-negative integer as 4-byte big-endian uint32."""
    return struct.pack(">I", n)


def _xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings.  Pads the shorter one with 0x00."""
    length = max(len(a), len(b))
    a_padded = a.ljust(length, b"\x00")
    b_padded = b.ljust(length, b"\x00")
    return bytes(x ^ y for x, y in zip(a_padded, b_padded))


def _zero_bytes(n: int) -> bytes:
    """Return n zero bytes — the identity element for XOR accumulation."""
    return b"\x00" * n


# =====================================================================
# PuncturedKey serialization / deserialization
# =====================================================================
# The paper stores ``data' = F2(id) ⊕ kS_id`` in Tf.  ``kS_id`` is a
# PuncturedKey (variable-size GGM co-path).  We serialise it, then XOR
# with a pad derived from F2(id) via HKDF so the client can recover
# the key from ``data'`` alone (Alg. 3 line 40).


def _serialize_punctured_key(pk: PuncturedKey) -> bytes:
    """Deterministic serialization of a PuncturedKey."""
    prefix_bytes = (pk.domain_bits + 7) // 8
    parts: list[bytes] = []
    parts.append(struct.pack(">I", pk.domain_bits))
    parts.append(struct.pack(">I", pk.output_bytes))
    parts.append(struct.pack(">I", pk.key_bytes))
    # Nodes — sorted for determinism
    sorted_nodes = sorted(pk.nodes.items())
    parts.append(struct.pack(">I", len(sorted_nodes)))
    for (depth, prefix), node_key in sorted_nodes:
        parts.append(struct.pack(">I", depth))
        parts.append(prefix.to_bytes(prefix_bytes, "big"))
        parts.append(node_key)
    # Punctured set — sorted for determinism
    sorted_punctured = sorted(pk.punctured)
    parts.append(struct.pack(">I", len(sorted_punctured)))
    for pt in sorted_punctured:
        parts.append(pt.to_bytes(prefix_bytes, "big"))
    return b"".join(parts)


def _deserialize_punctured_key(data: bytes) -> PuncturedKey:
    """Deserialize a PuncturedKey from stored bytes."""
    offset = 0

    def _read(n: int) -> bytes:
        nonlocal offset
        chunk = data[offset : offset + n]
        offset += n
        return chunk

    domain_bits = struct.unpack(">I", _read(4))[0]
    output_bytes = struct.unpack(">I", _read(4))[0]
    key_bytes = struct.unpack(">I", _read(4))[0]
    prefix_bytes = (domain_bits + 7) // 8

    num_nodes = struct.unpack(">I", _read(4))[0]
    nodes: Dict[Tuple[int, int], bytes] = {}
    for _ in range(num_nodes):
        depth = struct.unpack(">I", _read(4))[0]
        prefix = int.from_bytes(_read(prefix_bytes), "big")
        node_key = _read(key_bytes)
        nodes[(depth, prefix)] = node_key

    num_punctured = struct.unpack(">I", _read(4))[0]
    punctured: Set[int] = set()
    for _ in range(num_punctured):
        pt = int.from_bytes(_read(prefix_bytes), "big")
        punctured.add(pt)

    return PuncturedKey(
        nodes=nodes,
        punctured=punctured,
        domain_bits=domain_bits,
        output_bytes=output_bytes,
        key_bytes=key_bytes,
    )


def _expand_mask(seed: bytes, length: int) -> bytes:
    """Expand a PRF output into a one-time pad for XOR masking.

    Used for the forward-index masking:
        data' = expand(F2(id), |kS_id|)  ⊕  serialize(kS_id)

    Uses HMAC-SHA256 in counter mode because the serialized PuncturedKey
    with domain_bits=128 exceeds HKDF's RFC 5869 output limit of 8160
    bytes.  Counter mode: block_i = HMAC(seed, "guo/fwd/" || i).
    """
    if length == 0:
        return b""
    from Common.crypto.hashes import hmac_sha256

    blocks: list[bytes] = []
    needed = length
    counter = 0
    while needed > 0:
        block = hmac_sha256(seed, b"guo/fwd/", counter.to_bytes(4, "big"))
        blocks.append(block)
        needed -= len(block)
        counter += 1
    return b"".join(blocks)[:length]


# =====================================================================
# Search result
# =====================================================================


@dataclass
class SearchResult:
    """Holds everything a search produces — results, proofs, and counters.

    The counters (entries_traversed, forward_evals) are for Exp. 2's
    secondary metrics.  Keeping them here avoids the caller having to
    instrument the search internals.
    """

    result_ids: Set[int] = field(default_factory=set)
    proof_inverted: bytes = b""
    proof_forward: bytes = b""
    # (doc_id, data') pairs — kept for verify() (Alg. 4)
    forward_data: List[Tuple[int, bytes]] = field(default_factory=list)
    entries_traversed: int = 0
    forward_evals: int = 0
    least_frequent_keyword: str = ""
    lcnt_x: int = 0
    single_keyword_result_count: int = 0

    @staticmethod
    def empty(vtag_bytes: int = 32) -> "SearchResult":
        return SearchResult(proof_inverted=_zero_bytes(vtag_bytes),
                            proof_forward=_zero_bytes(vtag_bytes))


# =====================================================================
# The four VDSSE algorithms
# =====================================================================


class GuoVDSSE:
    """Algorithms 1-4 from Ref[35].

    Construction parameters are read from crypto.yaml once at init.
    """

    def __init__(self) -> None:
        params = crypto_config.scheme_params("guo_vdsse")
        prf_params = params["puncturable_prf"]
        self._domain_bits: int = prf_params["domain_bits"]
        self._prf_output_bytes: int = prf_params["output_bits"] // 8
        self._lambda_bytes: int = params["security_parameter_lambda"] // 8
        self._hash_output_bytes: int = params["hash_output_bits"] // 8
        self._vtag_bytes: int = params["verification_tag_bits"] // 8

        # A "utility" PuncturablePRF for encode() and eval_punctured().
        # These methods do not use the PRF's root key — they operate
        # only on node keys inside the PuncturedKey and on the domain
        # parameters, so any key of the right length works.
        self._prf_util = PuncturablePRF(
            b"\x00" * self._lambda_bytes,
            domain_bits=self._domain_bits,
            output_bytes=self._prf_output_bytes,
            key_bytes=self._lambda_bytes,
        )

    # ------------------------------------------------------------------
    # Setup  (Algorithm 1, Ref[35].txt:641-650)
    # ------------------------------------------------------------------
    def setup(self) -> Tuple[ClientState, EncryptedDatabase]:
        """Setup(λ, DB) → (σ, EDB).

        Initialises client state and empty encrypted database.
        Population is done via repeated calls to ``update()``.
        """
        state = ClientState()
        edb = EncryptedDatabase(hash_output_bytes=self._hash_output_bytes)
        return state, edb

    # ------------------------------------------------------------------
    # Update  (Algorithm 2, Ref[35].txt:797-877)
    # ------------------------------------------------------------------
    def update(
        self,
        state: ClientState,
        edb: EncryptedDatabase,
        op: str,
        doc_id: int,
        keywords: List[str],
    ) -> int:
        """Update(σ, op, in={id, W_id}; EDB) → (σ'; EDB').

        Args:
            op: ``"add"`` or ``"del"``.
            doc_id: integer record ID (``rid``).
            keywords: keyword strings in the document.

        Returns:
            Number of index entries written (Exp. 5 secondary metric).
        """
        if op not in ("add", "del"):
            raise ValueError(f"op must be 'add' or 'del', got {op!r}")

        op_byte = _OP_ADD if op == "add" else _OP_DEL
        doc_id_bytes = _encode_doc_id(doc_id)
        entries_written = 0

        # Per-document random key for the forward index — Alg. 2, line 1:
        #   "ran_id $← {0,1}^λ"
        ran_id = secure_random_bytes(self._lambda_bytes)

        # Create the PuncturablePRF with ran_id as root key.
        # This instance is used for puncturing (and for encode() during
        # construction of S_id).
        prf = PuncturablePRF(
            ran_id,
            domain_bits=self._domain_bits,
            output_bytes=self._prf_output_bytes,
            key_bytes=self._lambda_bytes,
        )

        # Accumulate puncture set — Alg. 2, line 15
        s_id_points: List[int] = []

        # ------ Build inverted-index entries (lines 2-16) ------
        for w in keywords:
            w_bytes = _encode_keyword(w)
            kw_state = state.get_or_init(w)

            # k_w_v = F1(w || v_w) — line 8
            k_w_v = state.f1(w_bytes, _encode_int(kw_state.v_w))

            # lcnt_w ← lcnt_w + 1 — line 8
            kw_state.lcnt_w += 1

            # valcnt_w update — line 9
            if op == "add":
                kw_state.valcnt_w += 1
            else:
                kw_state.valcnt_w -= 1

            # tag = H1(k_w_v || lcnt_w) — line 10
            tag = edb.h1(k_w_v, _encode_int(kw_state.lcnt_w))

            # data = H2(k_w_v || lcnt_w) ⊕ (id || op) — line 11
            h2_out = edb.h2(k_w_v, _encode_int(kw_state.lcnt_w))
            payload = doc_id_bytes + op_byte
            data = _xor(h2_out, payload)

            # vt = F3(w||(lcnt_w-1)) ⊕ F3(w||lcnt_w) ⊕ F3(id) — line 12
            vt = _xor(
                _xor(
                    state.f3(w_bytes, _encode_int(kw_state.lcnt_w - 1)),
                    state.f3(w_bytes, _encode_int(kw_state.lcnt_w)),
                ),
                state.f3(doc_id_bytes),
            )

            # Ti[tag] ← (data, vt) — line 25
            edb.add_inverted(tag, data, vt)
            entries_written += 1

            # S_id ∪= {F2(w)} if op = add — line 15
            if op == "add":
                f2_w = state.f2(w_bytes)
                s_id_points.append(prf.encode(f2_w))

        # ------ Build forward-index entry (lines 17-21) ------
        if op == "add" and keywords:
            # kS_id = Ft.Punc(ran_id, S_id) — line 18
            ks_id = prf.puncture(s_id_points)

            # Serialize and mask: data' = F2(id) ⊕ kS_id — line 19
            serialized = _serialize_punctured_key(ks_id)
            mask = _expand_mask(state.f2(doc_id_bytes), len(serialized))
            data_fwd = _xor(mask, serialized)

            # vt' = F3(id || data') — line 19
            vt_fwd = state.f3(doc_id_bytes, data_fwd)

            # Tf[id] ← (data', vt') — line 27
            edb.add_forward(doc_id_bytes, data_fwd, vt_fwd)
            entries_written += 1

        return entries_written

    # ------------------------------------------------------------------
    # Token generation — split out for Exp. 1 timing
    # ------------------------------------------------------------------
    def generate_search_token(
        self,
        state: ClientState,
        query_keywords: List[str],
    ) -> Optional["SearchToken"]:
        """Client-side trapdoor generation (Alg. 3, lines 1-13).

        Separated from search() so Exp. 1 can time ONLY this step.
        Returns None if any keyword is not in the dictionary or has no
        matching documents.
        """
        # Lines 2-8: look up all keywords
        q_info: Dict[str, "KeywordState"] = {}  # type: ignore[name-defined]
        for w in query_keywords:
            kw_state = state.get(w)
            if kw_state is None or kw_state.lcnt_w == 0:
                return None
            q_info[w] = kw_state

        # Line 9: find the least-frequent term x
        x = min(q_info, key=lambda w: q_info[w].valcnt_w)
        x_state = q_info[x]
        x_bytes = _encode_keyword(x)

        # Line 10: k_x_{v-1} — only if v_x > 1 (a previous search exists)
        # Ref[35].txt:893-896: "k_w_{v-1} is generated only if v_w > 1"
        k_x_v_prev: Optional[bytes] = None
        if x_state.v_w > 1:
            k_x_v_prev = state.f1(x_bytes, _encode_int(x_state.v_w - 1))

        # Line 11: k_x_v
        k_x_v = state.f1(x_bytes, _encode_int(x_state.v_w))

        # Line 12: st1 = (k_x_{v-1}, k_x_v, lcnt_x)
        conjunctive = len(query_keywords) > 1

        return SearchToken(
            x=x,
            k_x_v_prev=k_x_v_prev,
            k_x_v=k_x_v,
            lcnt_x=x_state.lcnt_w,
            conjunctive=conjunctive,
            all_keywords=list(query_keywords),
            lambda_bytes=state.lambda_bytes,
        )

    # ------------------------------------------------------------------
    # Search  (Algorithm 3, Ref[35].txt:1022-1138)
    # ------------------------------------------------------------------
    def search(
        self,
        state: ClientState,
        edb: EncryptedDatabase,
        query_keywords: List[str],
    ) -> SearchResult:
        """Search(q, σ; EDB) → (σ', R; EDB').

        Full end-to-end search: token generation + server retrieval +
        client-side conjunctive filtering.
        """
        # --- Client: generate search token (lines 1-13) ---
        token = self.generate_search_token(state, query_keywords)
        if token is None:
            return SearchResult.empty(self._vtag_bytes)

        # --- Server: retrieve (lines 14-36) ---
        return self._execute_search(state, edb, token)

    def _execute_search(
        self,
        state: ClientState,
        edb: EncryptedDatabase,
        token: "SearchToken",
    ) -> SearchResult:
        """Execute the server-side and client-side parts of Algorithm 3."""

        r_add: Set[int] = set()
        r_del: Set[int] = set()
        proof = _zero_bytes(self._vtag_bytes)
        proof_fwd = _zero_bytes(self._vtag_bytes)
        entries_traversed = 0

        # Lines 15-23: scan inverted index for keyword x, counting down
        cnt = token.lcnt_x
        while cnt > 0:
            tag = edb.h1(token.k_x_v, _encode_int(cnt))
            entry = edb.find_inverted(tag)
            if entry is None:
                break
            data, vt = entry
            entries_traversed += 1

            # (id || op) = H2(k_x_v || cnt) ⊕ data — line 18
            h2_out = edb.h2(token.k_x_v, _encode_int(cnt))
            decoded = _xor(h2_out, data)
            doc_id = _decode_doc_id(decoded)
            op_byte = decoded[8:9]

            if op_byte == _OP_ADD:
                r_add.add(doc_id)
            elif op_byte == _OP_DEL:
                r_del.add(doc_id)

            # Accumulate proof — line 18
            proof = _xor(proof, vt)

            cnt -= 1

        # Lines 24-27: merge cached results
        if token.k_x_v_prev is not None:
            cached = edb.get_cached(token.k_x_v_prev)
            if cached is not None:
                cached_ids, cached_proof = cached
                r_add |= cached_ids
                proof = _xor(proof, cached_proof)

        # R' = Radd - Rdel — line 28
        r_prime = r_add - r_del
        single_kw_count = len(r_prime)

        # Cache current results — line 28
        edb.cache_result(token.k_x_v, r_prime, proof)

        # Lines 29-35: conjunctive → forward index lookup
        forward_results: List[Tuple[int, bytes]] = []
        forward_evals = 0

        if token.conjunctive:
            for doc_id in r_prime:
                doc_id_bytes = _encode_doc_id(doc_id)
                fwd_entry = edb.find_forward(doc_id_bytes)
                if fwd_entry is not None:
                    data_fwd, vt_fwd = fwd_entry
                    forward_results.append((doc_id, data_fwd))
                    proof_fwd = _xor(proof_fwd, vt_fwd)
                    forward_evals += 1
        else:
            forward_results = [(did, b"") for did in r_prime]

        # --- Client: update state + filter (lines 37-43) ---
        # v_x += 1 — line 37
        x_state = state.get(token.x)
        if x_state is not None:
            x_state.v_w += 1

        remaining = [w for w in token.all_keywords if w != token.x]
        final_results: Set[int] = set()

        if token.conjunctive and remaining:
            for doc_id, data_fwd in forward_results:
                doc_id_bytes = _encode_doc_id(doc_id)

                # Recover kS_id = F2(id) ⊕ data' — line 40
                mask = _expand_mask(state.f2(doc_id_bytes), len(data_fwd))
                serialized = _xor(mask, data_fwd)
                ks_id = _deserialize_punctured_key(serialized)

                # Check Ft.Eval(kS_id, F2(w)) = ⊥ for all w ∈ q\x — line 41
                # ⊥ (None) means F2(w) is in the punctured set S_id,
                # i.e. the document CONTAINS that keyword.
                all_match = True
                for w in remaining:
                    w_bytes = _encode_keyword(w)
                    f2_w = state.f2(w_bytes)
                    point = self._prf_util.encode(f2_w)
                    result = self._prf_util.eval_punctured(ks_id, point)
                    if result is not None:
                        # Not ⊥ → keyword NOT in document → miss
                        all_match = False
                        break

                if all_match:
                    final_results.add(doc_id)
        else:
            # Single-keyword query or no remaining — R = R'
            final_results = r_prime

        return SearchResult(
            result_ids=final_results,
            proof_inverted=proof,
            proof_forward=proof_fwd,
            forward_data=forward_results,
            entries_traversed=entries_traversed,
            forward_evals=forward_evals,
            least_frequent_keyword=token.x,
            lcnt_x=token.lcnt_x,
            single_keyword_result_count=single_kw_count,
        )

    # ------------------------------------------------------------------
    # Verify  (Algorithm 4, Ref[35].txt:1152-1173)
    # ------------------------------------------------------------------
    def verify(
        self,
        state: ClientState,
        keyword: str,
        search_result: SearchResult,
    ) -> bool:
        """Verify(w, σ, R'', proof, proof') → accept/reject.

        Client-side verification of the completeness and correctness
        of the search result.

        Args:
            keyword: the least-frequent keyword ``x`` from the search.
            search_result: the SearchResult returned by search().

        Returns:
            True (accept) if both proofs check out, False (reject) otherwise.
        """
        w_bytes = _encode_keyword(keyword)
        kw_state = state.get(keyword)
        if kw_state is None:
            return False

        # proof1 = F3(w||0) ⊕ F3(w||lcnt_w) — line 2
        proof1 = _xor(
            state.f3(w_bytes, _encode_int(0)),
            state.f3(w_bytes, _encode_int(kw_state.lcnt_w)),
        )

        # proof2 = 0 — line 2
        proof2 = _zero_bytes(self._vtag_bytes)

        # lines 3-6: for each (id, data') in R''
        for doc_id, data_fwd in search_result.forward_data:
            doc_id_bytes = _encode_doc_id(doc_id)
            # proof1 ⊕= F3(id) — line 4
            proof1 = _xor(proof1, state.f3(doc_id_bytes))
            # proof2 ⊕= F3(id || data') — line 5
            if data_fwd:
                proof2 = _xor(proof2, state.f3(doc_id_bytes, data_fwd))

        # lines 7-11: compare
        proof_ok = (search_result.proof_inverted == proof1)
        proof_fwd_ok = True
        if search_result.forward_data and any(d for _, d in search_result.forward_data):
            proof_fwd_ok = (search_result.proof_forward == proof2)

        return proof_ok and proof_fwd_ok


# =====================================================================
# Search token (internal data class)
# =====================================================================


@dataclass
class SearchToken:
    """Search token st = (st1, st2) — Alg. 3, line 12.

    Encapsulates the client-generated trapdoor so that:
    1) Exp. 1 can measure token generation separately.
    2) The server doesn't see the keyword — it gets only derived keys.
    """

    x: str                          # least-frequent keyword
    k_x_v_prev: Optional[bytes]     # k_x_{v-1}, None if first search
    k_x_v: bytes                    # k_x_v
    lcnt_x: int                     # total updates for keyword x
    conjunctive: bool               # st2: True for conjunctive query
    all_keywords: List[str]         # full query for client-side filtering
    lambda_bytes: int               # for size reporting

    @property
    def size_bytes(self) -> int:
        """Serialised trapdoor size — Exp. 1 secondary metric.

        st1 = (k_x_{v-1}, k_x_v, lcnt_x)
        st2 = 1 byte (conjunctive flag)
        """
        key_sizes = self.lambda_bytes  # k_x_v always present
        if self.k_x_v_prev is not None:
            key_sizes += self.lambda_bytes
        return key_sizes + 4 + 1  # +4 for lcnt_x (uint32), +1 for st2
