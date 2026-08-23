"""Client-side state for Guo VDSSE (Ref[35]).

Implements σ = (SK, Dict) from Table II and Algorithm 1 (Ref[35].txt:619-666).

- SK = {sk1, sk2, sk3}: three PRF keys for F1, F2, F3
- Dict[w] = (v_w, lcnt_w, valcnt_w): per-keyword version, update count,
  valid-document count

All parameters read from crypto.yaml § guo_vdsse — nothing is hardcoded.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from Common.crypto import config as crypto_config
from Common.crypto.prf import PRF
from Common.crypto.rng import secure_random_bytes


@dataclass
class KeywordState:
    """Per-keyword metadata stored in the client's Dict (Ref[35].txt:621-632).

    v_w:      version number, initially 1, incremented after each search on w.
    lcnt_w:   total number of updates (add + del) for keyword w.
    valcnt_w: count of currently valid (added but not deleted) documents
              containing w — used to find the least frequent term (Alg. 3 line 9).
    """

    v_w: int = 1
    lcnt_w: int = 0
    valcnt_w: int = 0


class ClientState:
    """Client state σ = (SK, Dict) per Algorithm 1.

    Parameters are read from crypto.yaml ``guo_vdsse`` section at construction
    time. Never hardcode λ, hash-output bits, or key sizes — they propagate
    from the config so ``run_meta.json`` records the exact values used.
    """

    def __init__(self) -> None:
        params = crypto_config.scheme_params("guo_vdsse")
        lambda_bits: int = params["security_parameter_lambda"]
        self._lambda_bytes: int = lambda_bits // 8  # 16 for λ=128
        self._hash_output_bytes: int = params["hash_output_bits"] // 8  # 24
        self._vtag_bytes: int = params["verification_tag_bits"] // 8  # 32

        # Three secret keys — Ref[35].txt:644-648:
        #   "sk_{1,2,3} $← {0,1}^λ; SK ← {sk1, sk2, sk3}"
        self.sk1: bytes = secure_random_bytes(self._lambda_bytes)
        self.sk2: bytes = secure_random_bytes(self._lambda_bytes)
        self.sk3: bytes = secure_random_bytes(self._lambda_bytes)

        # PRF instances — all HMAC-SHA256 per Ref[35].txt:1756.
        # Output sizes match their usage:
        #   F1  → k_w_v (used as key material for H1/H2)  → λ bytes
        #   F2  → domain encoding + forward-index mask     → vtag bytes
        #   F3  → verification tags (XOR-accumulated)      → vtag bytes
        self._f1 = PRF(self.sk1, output_bytes=self._lambda_bytes)
        self._f2 = PRF(self.sk2, output_bytes=self._vtag_bytes)
        self._f3 = PRF(self.sk3, output_bytes=self._vtag_bytes)

        # Per-keyword dictionary — Ref[35].txt:619-632
        self._dict: Dict[str, KeywordState] = {}


    @property
    def lambda_bytes(self) -> int:
        """Security parameter in bytes (λ / 8)."""
        return self._lambda_bytes

    @property
    def hash_output_bytes(self) -> int:
        """Hash output size in bytes (192-bit / 8 = 24)."""
        return self._hash_output_bytes

    @property
    def vtag_bytes(self) -> int:
        """Verification tag size in bytes (F2/F3 output, from config)."""
        return self._vtag_bytes


    def get_or_init(self, w: str) -> KeywordState:
        """Look up Dict[w], initialising to (1, 0, 0) if absent.

        Ref[35] Algorithm 2, lines 3-4:
            "if Dict.find(w) = ⊥ then v_w ← 1; lcnt_w ← 0; valcnt_w ← 0"
        """
        if w not in self._dict:
            self._dict[w] = KeywordState()
        return self._dict[w]

    def get(self, w: str) -> Optional[KeywordState]:
        """Look up Dict[w], returning None if absent.

        Ref[35] Algorithm 3, lines 3-4:
            "if Dict.find(w) = ⊥ then return ∅"
        """
        return self._dict.get(w)

    def keyword_count(self) -> int:
        """Number of distinct keywords tracked in the dictionary."""
        return len(self._dict)

    def f1(self, *parts: bytes) -> bytes:
        """PRF F1 — inverted-index key derivation (Ref[35].txt:654-656)."""
        return self._f1(*parts)

    def f2(self, *parts: bytes) -> bytes:
        """PRF F2 — forward-index domain encoding (Ref[35].txt:654-656)."""
        return self._f2(*parts)

    def f3(self, *parts: bytes) -> bytes:
        """PRF F3 — verification tag computation (Ref[35].txt:654-656)."""
        return self._f3(*parts)
