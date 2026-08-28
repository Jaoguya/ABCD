"""Multilevel Symmetric Revocable Encryption (MSRE) — Ref[55] §IV.

The paper's new primitive, and what buys Peony++ its Type-II backward privacy.
It generalizes Sun et al.'s SRE (their [6], Aura) from one revocation filter to
``|L|`` of them, one per access level, so a deletion can be expressed at a level
rather than globally.

    MSRE = (BGen, Enc, KLRev, Dec)

The whole idea in one paragraph: a file identifier is encrypted ``h`` times,
once under each of the ``h`` Bloom-filter positions its tag hashes to. To revoke
it, the owner sets those ``h`` positions in the filter and hands the server a
GGM key punctured at every set position. The server can still derive the leaf
key for any position that is 0, so it can decrypt anything not revoked — and can
derive nothing for a revoked tag, because all ``h`` of its positions are 1. The
server is not trusted to honor a delete flag; it is made *unable* to decrypt.

Correctness error comes only from the Bloom filter false positive, which the
paper states plainly (§IV-A, Definition 1) rather than hiding.

Primitives are the repo's shared ones (README §245: primitives a paper *cites*
live in ``Common/``): ``PuncturablePRF`` is the GGM-tree t-punc-PRF the paper
specifies in §VI-B, ``BloomFilter`` the ``(b, h, n)`` filter of §III-B, and
``symmetric`` the ``SE`` of §IV-B.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from Common.crypto.bloom import BloomFilter
from Common.crypto.prf import PuncturablePRF, PuncturedKey
from Common.crypto.rng import secure_random_bytes
from Common.crypto.symmetric import Ciphertext, DecryptionError
from Common.crypto.symmetric import decrypt as se_decrypt
from Common.crypto.symmetric import encrypt as se_encrypt

from .levels import levels_to_update_on_delete


def domain_bits_for(array_bits: int) -> int:
    """GGM tree depth needed to address every Bloom position.

    Ref[55] §IV-B, MSRE.Enc step 1: "Calculates j_i = H_i(t) in [b] and
    sk_{j_i} = F(sk, j_i)". The t-punc-PRF domain is therefore exactly the
    filter's index space ``[b]`` — not some wider fixed domain. Deriving the
    depth from ``b`` keeps the punctured key the size the paper's own
    communication-cost figures imply (§VII-B), instead of paying for a tree
    covering an address space the scheme never touches.
    """
    return max(1, math.ceil(math.log2(max(2, array_bits))))


@dataclass
class MSREKey:
    """``lsk`` — the multilevel system secret key from ``MSRE.BGen``.

    One of these per keyword: Ref[55] §VI-B says "each keyword has a unique GGM
    PRF key sk_w", and the filters are likewise per keyword (``B_{w,l}``).
    """

    prf: PuncturablePRF                     # sk <- Ft.Setup(1^lambda)
    filters: Dict[int, BloomFilter]         # B = {B_1 .. B_|L|}
    array_bits: int                         # b
    num_hashes: int                         # h
    access_levels: int                      # |L|

    def positions(self, tag: bytes) -> List[int]:
        """``j_i = H_i(t)`` for ``i in [h]`` — the filter's own hash family.

        Uses the BloomFilter's positions so Enc and Check agree by construction;
        deriving them separately would be a correctness bug waiting to happen.
        """
        return self.filters[1]._positions(tag)

    @property
    def filter_size_bytes(self) -> int:
        """Total BF storage — the paper's Table V metric."""
        return sum(bf.size_bytes for bf in self.filters.values())


@dataclass
class MSRECiphertext:
    """``ct = (ct_1, ..., ct_h)`` together with its tag ``t``."""

    components: List[Ciphertext]
    tag: bytes
    positions: List[int] = field(default_factory=list)

    @property
    def size_bytes(self) -> int:
        return sum(c.size_bytes for c in self.components) + len(self.tag)


@dataclass
class RevokedKey:
    """``sk_{R_l} = (sk_{I_l}, H, B_{R_l})`` for one access level."""

    level: int
    punctured: PuncturedKey                 # sk_{I_l}
    bloom: BloomFilter                      # B_{R_l}
    array_bits: int

    @property
    def size_bytes(self) -> int:
        """Search-token contribution — the paper's §VII-B communication metric."""
        return self.punctured.size_bytes + self.bloom.size_bytes


# ---------------------------------------------------------------------------
# MSRE.BGen — §IV-B
# ---------------------------------------------------------------------------
def bgen(
    array_bits: int,
    num_hashes: int,
    access_levels: int,
    *,
    output_bytes: int = 32,
    key_bytes: int = 16,
) -> MSREKey:
    """``MSRE.BGen(1^lambda, b, h, L)`` — Ref[55] §IV-B.

    1. ``sk <- Ft.Setup(1^lambda)``
    2. ``(H, B) <- BF.Gen(b, h)``, then ``|L|-1`` additional copies of ``B``.
    """
    prf = PuncturablePRF.setup(
        domain_bits=domain_bits_for(array_bits),
        output_bytes=output_bytes,
        key_bytes=key_bytes,
    )
    filters = {
        level: BloomFilter(array_bits=array_bits, num_hashes=num_hashes)
        for level in range(1, access_levels + 1)
    }
    return MSREKey(
        prf=prf,
        filters=filters,
        array_bits=array_bits,
        num_hashes=num_hashes,
        access_levels=access_levels,
    )


# ---------------------------------------------------------------------------
# MSRE.Enc — §IV-B
# ---------------------------------------------------------------------------
def enc(lsk: MSREKey, message: bytes, tag: bytes) -> MSRECiphertext:
    """``MSRE.Enc(lsk, m, a(m), t)`` — Ref[55] §IV-B.

    1. ``j_i = H_i(t)`` and ``sk_{j_i} = F(sk, j_i)`` for all ``i in [h]``
    2. ``ct_i = SE.Enc(sk_{j_i}, m)``; output ``ct = (ct_1..ct_h)`` and ``t``

    Note the access level ``a(m)`` is an argument in the paper's signature but
    is not consumed by Enc itself — the level only decides *which* filters a
    later revocation touches (``MSRE.KLRev``). Encryption is level-independent,
    which is exactly why the paper can say "the file addition time for Peony and
    Peony++ is independent of the access level of the file" (§VII-B).
    """
    positions = lsk.positions(tag)
    components: List[Ciphertext] = []
    for j in positions:
        leaf_key = lsk.prf.eval(j)
        components.append(se_encrypt(_aes_key(leaf_key), message))
    return MSRECiphertext(components=components, tag=tag, positions=positions)


# ---------------------------------------------------------------------------
# MSRE.KLRev — §IV-B
# ---------------------------------------------------------------------------
def klrev(
    lsk: MSREKey,
    revoked: Sequence[Tuple[bytes, int]],
    levels: Optional[Iterable[int]] = None,
) -> Dict[int, RevokedKey]:
    """``MSRE.KLRev(lsk, R, L_R)`` — Ref[55] §IV-B.

    Args:
        lsk: the keyword's multilevel system secret key.
        revoked: the revocation list ``R`` as ``(tag, file_level)`` pairs.
        levels: which levels to produce keys for. Defaults to all of them.

    Two steps, both from the paper:

    ``MSRE.Comp`` — classify ``R`` by level and set the filter bits, propagating
    UPWARD: a tag revoked at level ``l`` is also set in every ``B_xi`` with
    ``xi > l`` (§IV-B, and spelled out concretely in §VII-B). ``levels.py``
    holds that rule.

    ``MSRE.cKLRev`` — ``I_l = {j : B_{R_l}[j] = 1}``, then
    ``sk_{I_l} <- Ft.punc(sk, I_l)`` and ``sk_{R_l} = (sk_{I_l}, H, B_{R_l})``.
    """
    # MSRE.Comp — set bits, with upward level propagation.
    for tag, file_level in revoked:
        for lvl in levels_to_update_on_delete(file_level, lsk.access_levels):
            lsk.filters[lvl].add(tag)

    # MSRE.cKLRev — puncture at every set position.
    target_levels = (
        list(levels) if levels is not None
        else list(range(1, lsk.access_levels + 1))
    )
    out: Dict[int, RevokedKey] = {}
    for lvl in target_levels:
        bf = lsk.filters[lvl]
        set_positions = _set_bits(bf.bits, lsk.array_bits)
        punctured = lsk.prf.puncture(set_positions)
        out[lvl] = RevokedKey(
            level=lvl,
            punctured=punctured,
            bloom=bf,
            array_bits=lsk.array_bits,
        )
    return out


# ---------------------------------------------------------------------------
# MSRE.Dec — §IV-B
# ---------------------------------------------------------------------------
def dec(
    lsk_prf: PuncturablePRF,
    skr: RevokedKey,
    ct: MSRECiphertext,
) -> Optional[bytes]:
    """``MSRE.Dec(sk_{R_l}, ct, t)`` — Ref[55] §IV-B.

    1. If ``BF.Check(H, B_{R_l}, t) = 1``, decryption fails (the tag is revoked
       at this level, or the filter false-positived).
    2. Locate ``j*`` with ``B_{R_l}[j*] = 0``, derive
       ``sk_{j*} = Ft.eval(sk_{I_l}, j*)``.
    3. Recover ``m = SE.Dec(sk_{j*}, ct_{j*})``.

    ``j*`` is drawn from the tag's own ``h`` positions: those are the only
    indices for which a ciphertext component exists (Enc produced exactly one
    per position). Step 1 failing is precisely the statement that none of them
    is still 0.

    Returns the plaintext, or ``None`` when the entry is revoked — which is what
    Type-II backward privacy means operationally: the server holds the
    ciphertext and simply cannot open it.
    """
    positions = ct.positions or [
        p for p in skr.bloom._positions(ct.tag)
    ]

    # Step 1: BF.Check — 1 iff every position is set.
    bits = skr.bloom.bits
    open_indices = [
        (i, j) for i, j in enumerate(positions) if not ((bits >> j) & 1)
    ]
    if not open_indices:
        return None

    # Steps 2-3: use the first still-open position.
    comp_index, j_star = open_indices[0]
    leaf_key = lsk_prf.eval_punctured(skr.punctured, j_star)
    if leaf_key is None:
        return None
    try:
        return se_decrypt(_aes_key(leaf_key), ct.components[comp_index])
    except DecryptionError:
        return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _aes_key(leaf_key: bytes) -> bytes:
    """Widen a GGM leaf output to an AES-256 key.

    ``PuncturablePRF`` emits ``output_bytes``; ``Common.crypto.symmetric``
    requires 32. When the PRF is configured at 256 bits these are already equal
    and this is the identity — the branch exists so a narrower PRF setting stays
    usable rather than raising deep inside encryption.
    """
    if len(leaf_key) == 32:
        return leaf_key
    from Common.crypto.hashes import sha256

    return sha256(leaf_key, domain=b"yue_ge/msre/leafkey")


def _set_bits(bits: int, array_bits: int) -> List[int]:
    """Indices of the 1 bits of ``bits`` — the index set ``I_l``."""
    out: List[int] = []
    remaining = bits
    while remaining:
        low = remaining & -remaining
        idx = low.bit_length() - 1
        if idx < array_bits:
            out.append(idx)
        remaining ^= low
    return out
