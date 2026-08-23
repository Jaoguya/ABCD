"""Encrypted database (EDB) for Guo VDSSE (Ref[35]).

Two hash tables plus a results cache:

  Ti  — inverted index: tag → (data, vt)
  Tf  — forward index:  doc_id_bytes → (data', vt')
  cache — previous query results keyed by version key

Ref[35].txt:649: "EDB ← {Ti, Tf}"
Ref[35].txt:1766: "All of the schemes were implemented in C++ with all
data stored in hash tables."

H1 and H2 are SHA-256 truncated to 192 bits per Ref[35].txt:1763-1764.
They live here because they operate on EDB-level data (tag addresses
and payload masks) and are not used by any other scheme.
"""

from __future__ import annotations

from typing import Dict, Optional, Set, Tuple

from Common.crypto.hashes import sha256_bits

# Type aliases for clarity
Tag = bytes       # H1 output, 192 bits (24 bytes)
Data = bytes      # XOR-masked payload
VerifTag = bytes  # F3-based verification tag, 32 bytes


class EncryptedDatabase:
    """Server-side encrypted database EDB = {Ti, Tf, cache}.

    All operations are dict lookups — faithful to Ref[35]'s "all data stored
    in hash tables" (Ref[35].txt:1766).  No ordering, no tree structure.
    """

    def __init__(self, hash_output_bytes: int) -> None:
        """Initialise empty EDB.

        Args:
            hash_output_bytes: output size for H1/H2.  Read from crypto.yaml
                ``guo_vdsse.hash_output_bits // 8`` (24 for the published
                192-bit setting).
        """
        self._hash_output_bytes = hash_output_bytes

        # Ti: inverted index (Ref[35].txt:663)
        self._ti: Dict[bytes, Tuple[Data, VerifTag]] = {}

        # Tf: forward index (Ref[35].txt:664)
        self._tf: Dict[bytes, Tuple[Data, VerifTag]] = {}

        # Cache of previous search results per version key
        # (Ref[35].txt:878-879, Alg. 3 line 28)
        self._cache: Dict[bytes, Tuple[Set[int], VerifTag]] = {}

    # ------------------------------------------------------------------
    # H1, H2 — hash functions with published 192-bit output
    # Ref[35].txt:1756-1764
    # ------------------------------------------------------------------
    def h1(self, *parts: bytes) -> bytes:
        """H1 — address function for inverted-index entries."""
        return sha256_bits(
            *parts, bits=self._hash_output_bytes * 8, domain=b"guo/H1"
        )

    def h2(self, *parts: bytes) -> bytes:
        """H2 — masking function for inverted-index payloads."""
        return sha256_bits(
            *parts, bits=self._hash_output_bytes * 8, domain=b"guo/H2"
        )

    # ------------------------------------------------------------------
    # Inverted index Ti
    # ------------------------------------------------------------------
    def add_inverted(self, tag: bytes, data: bytes, vt: bytes) -> None:
        """Ti[tag] ← (data, vt) — Alg. 2, line 25."""
        self._ti[tag] = (data, vt)

    def find_inverted(self, tag: bytes) -> Optional[Tuple[Data, VerifTag]]:
        """Ti.find(tag) — Alg. 3, lines 16-17.  Returns None if absent."""
        return self._ti.get(tag)

    # ------------------------------------------------------------------
    # Forward index Tf
    # ------------------------------------------------------------------
    def add_forward(self, doc_id_bytes: bytes, data: bytes, vt: bytes) -> None:
        """Tf[tag'] ← (data', vt') — Alg. 2, line 27."""
        self._tf[doc_id_bytes] = (data, vt)

    def find_forward(
        self, doc_id_bytes: bytes
    ) -> Optional[Tuple[Data, VerifTag]]:
        """Tf[id] — Alg. 3, line 32.  Returns None if absent."""
        return self._tf.get(doc_id_bytes)

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------
    def cache_result(
        self, key: bytes, valid_ids: Set[int], proof: bytes
    ) -> None:
        """EDBcache[k_x_v] ← (R', proof) — Alg. 3, line 28."""
        self._cache[key] = (set(valid_ids), bytes(proof))

    def get_cached(
        self, key: bytes
    ) -> Optional[Tuple[Set[int], VerifTag]]:
        """EDBcache[k_x_v-1] — Alg. 3, line 25.  Returns None if absent."""
        return self._cache.get(key)

    # ------------------------------------------------------------------
    # Counters for secondary metrics
    # ------------------------------------------------------------------
    @property
    def inverted_entry_count(self) -> int:
        """Number of entries in Ti — Exp. 5 secondary metric."""
        return len(self._ti)

    @property
    def forward_entry_count(self) -> int:
        """Number of entries in Tf."""
        return len(self._tf)

    @property
    def total_entry_count(self) -> int:
        return len(self._ti) + len(self._tf)
