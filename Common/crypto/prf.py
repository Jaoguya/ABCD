"""Pseudorandom functions, including the t-puncturable PRF of Ref[35].

Ref[35].txt:1756-1758 states the published instantiation:

    "we implemented the hash functions and PRFs with SHA256 and HMAC based on
     SHA256 ... In particular, the t-Pun-PRF was constructed by two HMACs
     based on SHA256 and Blake2b"

and Ref[35].txt:368-395 gives the abstract interface (Setup / Punc / Eval)
with the correctness requirement that Eval returns the real PRF value off the
punctured set and bottom on it.

Two HMACs and a Setup/Punc/Eval interface is the GGM tree construction: the
two keyed functions are the left and right child-derivation functions, and
puncturing hands out the co-path. That reading is recorded here rather than
assumed silently — see ``PuncturablePRF`` for the full note.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .hashes import hmac_blake2b, hmac_sha256, sha256
from .rng import secure_random_bytes

# Node label: (depth, value-of-first-`depth`-bits). Depth 0 is the root.
NodeLabel = Tuple[int, int]


class PRF:
    """Plain PRF from HMAC-SHA256 (Ref[35].txt:1756)."""

    def __init__(self, key: bytes, *, output_bytes: int = 32) -> None:
        if not key:
            raise ValueError("PRF key must be non-empty")
        if not 1 <= output_bytes <= 32:
            raise ValueError(f"output_bytes must be in 1..32, got {output_bytes}")
        self._key = key
        self._output_bytes = output_bytes

    @classmethod
    def generate(cls, *, key_bytes: int = 32, output_bytes: int = 32) -> "PRF":
        return cls(secure_random_bytes(key_bytes), output_bytes=output_bytes)

    def __call__(self, *parts: bytes) -> bytes:
        return hmac_sha256(self._key, *parts)[: self._output_bytes]

    eval = __call__


# ---------------------------------------------------------------------------
# t-puncturable PRF
# ---------------------------------------------------------------------------
@dataclass
class PuncturedKey:
    """A t-punctured key: subtree roots covering exactly ``X \\ S``.

    ``nodes`` maps a node label to that subtree's key. ``punctured`` is kept
    so that Eval can distinguish "x was punctured" (return bottom, which is
    correct) from "this key is malformed" (a bug).
    """

    nodes: Dict[NodeLabel, bytes]
    punctured: Set[int]
    domain_bits: int
    output_bytes: int
    key_bytes: int

    @property
    def size_bytes(self) -> int:
        """Serialised size — Exp. 1 reports trapdoor size in bytes."""
        # Each entry: 4-byte depth + ceil(domain_bits/8) label + key.
        label_bytes = (self.domain_bits + 7) // 8
        return len(self.nodes) * (4 + label_bytes + self.key_bytes)


class PuncturablePRF:
    """GGM-tree t-puncturable PRF with the two HMACs of Ref[35].

    Construction
    ------------
    The domain is ``{0,1}^d``. Evaluation walks a binary tree of depth ``d``
    from the root key, taking the left or right derivation at each bit::

        k_0 = k
        k_i = HMAC-SHA256 (k_{i-1}, "0")   if bit i of x is 0
        k_i = HMAC-BLAKE2b(k_{i-1}, "1")   if bit i of x is 1

    and the leaf key is finalised into the output. Puncturing at a set ``S``
    releases the minimal set of subtree roots covering ``X \\ S``: everything
    off ``S`` is still derivable, and no key on the path to any ``x in S`` is
    ever handed out, so those points are unrecoverable.

    Faithfulness note
    -----------------
    Ref[35] cites its t-Pun-PRF definition to reference [33] and states only
    the two-HMAC instantiation, not the tree layout. GGM is the standard
    construction matching that description and the Setup/Punc/Eval interface
    of Ref[35].txt:375-395, and its cost profile (d HMACs per evaluation,
    <= t*d nodes per punctured key) is what the paper's complexity implies.
    If the recovered Ref[35] text later shows a different layout, this class
    is the only place that changes — no scheme code depends on the internals.
    """

    def __init__(
        self,
        key: bytes,
        *,
        domain_bits: int = 128,
        output_bytes: int = 24,  # 192 bits, Ref[35].txt:1763-1764
        key_bytes: int = 16,     # lambda = 128, Ref[35].txt:1763
    ) -> None:
        if len(key) != key_bytes:
            raise ValueError(f"key must be {key_bytes} bytes, got {len(key)}")
        if domain_bits <= 0:
            raise ValueError(f"domain_bits must be positive, got {domain_bits}")
        self._key = key
        self.domain_bits = domain_bits
        self.output_bytes = output_bytes
        self.key_bytes = key_bytes

    # -- Ft.Setup -----------------------------------------------------------
    @classmethod
    def setup(
        cls,
        *,
        domain_bits: int = 128,
        output_bytes: int = 24,
        key_bytes: int = 16,
    ) -> "PuncturablePRF":
        """``Ft.Setup(1^lambda)`` — Ref[35].txt:375."""
        return cls(
            secure_random_bytes(key_bytes),
            domain_bits=domain_bits,
            output_bytes=output_bytes,
            key_bytes=key_bytes,
        )

    # -- domain encoding ----------------------------------------------------
    def encode(self, item: bytes) -> int:
        """Map an arbitrary byte string (a keyword) into ``{0,1}^d``."""
        digest = sha256(item, domain=b"punprf/domain")
        return int.from_bytes(digest, "big") >> max(0, 256 - self.domain_bits)

    # -- Ft.Eval on the full key -------------------------------------------
    def eval(self, x: int) -> bytes:
        """Evaluate at a domain point held as an integer."""
        self._check_point(x)
        return self._finalise(self._derive(self._key, 0, self.domain_bits, x))

    def eval_bytes(self, item: bytes) -> bytes:
        """Evaluate at an arbitrary byte string (encodes, then evaluates)."""
        return self.eval(self.encode(item))

    # -- Ft.Punc ------------------------------------------------------------
    def puncture(self, points: Iterable[int]) -> PuncturedKey:
        """``Ft.Punc(k, S)`` — Ref[35].txt:379.

        Emits the co-path of every punctured point: walking root-to-leaf, the
        sibling subtree at each step contains no punctured point and so can be
        released whole. Shared prefixes are visited once, so overlapping
        punctures do not duplicate nodes.
        """
        targets = sorted({self._checked(x) for x in points})
        nodes: Dict[NodeLabel, bytes] = {}
        self._cover(self._key, depth=0, prefix=0, targets=targets, nodes=nodes)
        return PuncturedKey(
            nodes=nodes,
            punctured=set(targets),
            domain_bits=self.domain_bits,
            output_bytes=self.output_bytes,
            key_bytes=self.key_bytes,
        )

    def _cover(
        self,
        node_key: bytes,
        *,
        depth: int,
        prefix: int,
        targets: List[int],
        nodes: Dict[NodeLabel, bytes],
    ) -> None:
        if not targets:
            # No punctured point below here: release this whole subtree.
            nodes[(depth, prefix)] = node_key
            return
        if depth == self.domain_bits:
            # A leaf that is itself punctured: release nothing.
            return

        shift = self.domain_bits - depth - 1
        left_targets = [t for t in targets if not (t >> shift) & 1]
        right_targets = [t for t in targets if (t >> shift) & 1]

        self._cover(
            self._child(node_key, 0),
            depth=depth + 1,
            prefix=prefix << 1,
            targets=left_targets,
            nodes=nodes,
        )
        self._cover(
            self._child(node_key, 1),
            depth=depth + 1,
            prefix=(prefix << 1) | 1,
            targets=right_targets,
            nodes=nodes,
        )

    # -- Ft.Eval on a punctured key ----------------------------------------
    def eval_punctured(self, punctured_key: PuncturedKey, x: int) -> Optional[bytes]:
        """``Ft.Eval(k_S, x)`` — Ref[35].txt:382.

        Returns the PRF value for ``x not in S`` and ``None`` (bottom) for
        ``x in S``, which is exactly the correctness property required at
        Ref[35].txt:386-395.
        """
        self._check_point(x)
        for depth in range(self.domain_bits, -1, -1):
            prefix = x >> (self.domain_bits - depth)
            node_key = punctured_key.nodes.get((depth, prefix))
            if node_key is not None:
                return self._finalise(
                    self._derive(node_key, depth, self.domain_bits, x)
                )
        return None

    # -- internals ----------------------------------------------------------
    def _child(self, node_key: bytes, bit: int) -> bytes:
        """One GGM step. Left uses HMAC-SHA256, right uses keyed BLAKE2b."""
        if bit:
            return hmac_blake2b(node_key, b"1", digest_size=self.key_bytes)
        return hmac_sha256(node_key, b"0")[: self.key_bytes]

    def _derive(self, node_key: bytes, from_depth: int, to_depth: int, x: int) -> bytes:
        key = node_key
        for depth in range(from_depth, to_depth):
            bit = (x >> (self.domain_bits - depth - 1)) & 1
            key = self._child(key, bit)
        return key

    def _finalise(self, leaf_key: bytes) -> bytes:
        return hmac_sha256(leaf_key, b"out")[: self.output_bytes]

    def _check_point(self, x: int) -> None:
        if not 0 <= x < (1 << self.domain_bits):
            raise ValueError(f"domain point out of range for {self.domain_bits} bits")

    def _checked(self, x: int) -> int:
        self._check_point(x)
        return x
