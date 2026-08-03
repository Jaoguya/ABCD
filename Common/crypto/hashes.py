"""Hash functions and hash-derived helpers.

Shared by every scheme. Ref[35] runs its hashes at a 192-bit output
(Ref[35].txt:1763-1764) while the rest of the benchmark uses full 256-bit
SHA-256, so truncation is a first-class parameter here rather than something
each scheme re-derives.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
from typing import Iterable, List

import numpy as np

# Domain-separation tag. Prevents a digest computed for one purpose from being
# valid for another when the same key or input appears in two contexts.
_DOMAIN = b"MA-LB-PQ-VDSE/v1/"


def _join(parts: Iterable[bytes]) -> bytes:
    """Length-prefixed concatenation.

    Plain concatenation is ambiguous: (b"ab", b"c") and (b"a", b"bc") would
    hash identically. Prefixing each part with its 4-byte length makes the
    encoding injective, so distinct inputs cannot collide by framing alone.
    """
    out = bytearray()
    for part in parts:
        if not isinstance(part, (bytes, bytearray, memoryview)):
            raise TypeError(f"expected bytes, got {type(part).__name__}")
        out += len(part).to_bytes(4, "big")
        out += bytes(part)
    return bytes(out)


def sha256(*parts: bytes, domain: bytes = b"") -> bytes:
    """SHA-256 over a length-prefixed concatenation of ``parts``."""
    return hashlib.sha256(_DOMAIN + domain + _join(parts)).digest()


def sha256_bits(*parts: bytes, bits: int, domain: bytes = b"") -> bytes:
    """SHA-256 truncated to ``bits``.

    Truncating a SHA-256 digest is the standard way to obtain a shorter hash
    (FIPS 180-4 §7 permits it); it costs the expected 2^(bits/2) collision
    resistance, which at 192 bits is 96-bit — the level Ref[35] published.
    """
    if bits <= 0 or bits > 256:
        raise ValueError(f"bits must be in 1..256, got {bits}")
    if bits % 8:
        raise ValueError(f"bits must be a whole number of bytes, got {bits}")
    return sha256(*parts, domain=domain)[: bits // 8]


def blake2b(*parts: bytes, digest_size: int = 32, key: bytes = b"") -> bytes:
    """BLAKE2b digest. Used by Ref[35]'s t-Pun-PRF (Ref[35].txt:1758)."""
    if not 1 <= digest_size <= 64:
        raise ValueError(f"digest_size must be in 1..64, got {digest_size}")
    hasher = hashlib.blake2b(digest_size=digest_size, key=key)
    hasher.update(_DOMAIN + _join(parts))
    return hasher.digest()


def hmac_sha256(key: bytes, *parts: bytes) -> bytes:
    """HMAC-SHA256 (FIPS 198-1)."""
    return _hmac.new(key, _join(parts), hashlib.sha256).digest()


def hmac_blake2b(key: bytes, *parts: bytes, digest_size: int = 32) -> bytes:
    """Keyed BLAKE2b.

    BLAKE2b's native keying is the designers' recommended MAC mode, so this
    does not wrap it in the HMAC construction — HMAC exists to fix
    length-extension in Merkle-Damgard hashes, and BLAKE2b is not vulnerable
    to that. Ref[35]'s "HMAC based on Blake2b" is read as "a MAC built on
    BLAKE2b", which is what keyed BLAKE2b is.
    """
    return blake2b(*parts, digest_size=digest_size, key=key)


def hkdf_sha256(ikm: bytes, *, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    """HKDF-SHA256 (RFC 5869): extract-then-expand key derivation."""
    if length <= 0 or length > 255 * 32:
        raise ValueError(f"length must be in 1..8160, got {length}")
    prk = _hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = _hmac.new(prk, block + _DOMAIN + info + bytes([counter]),
                          hashlib.sha256).digest()
        okm += block
        counter += 1
    return bytes(okm[:length])


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Timing-safe comparison, for verification paths (Exp. 4)."""
    return _hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# Hash-to-field, for the lattice schemes
# ---------------------------------------------------------------------------
def hash_to_zq(data: bytes, q: int, *, count: int = 1, domain: bytes = b"") -> np.ndarray:
    """Hash ``data`` to ``count`` uniform elements of Z_q.

    Ref[52] needs hash functions H_i : {0,1}* -> Z_q (Ref[52].txt:239-240).

    Uses rejection sampling rather than ``digest % q``: for a q that is not a
    power of two, the modulo shortcut biases low residues, and a biased H is
    exactly the kind of detail that survives review only until someone checks.
    When q IS a power of two (Ref[52] uses q = 2^24) masking is already exact,
    so the rejection loop simply never rejects.
    """
    if q < 2:
        raise ValueError(f"q must be >= 2, got {q}")
    if count <= 0:
        raise ValueError(f"count must be positive, got {count}")

    bits = (q - 1).bit_length()
    nbytes = (bits + 7) // 8
    mask = (1 << bits) - 1

    out: List[int] = []
    counter = 0
    while len(out) < count:
        block = sha256(data, counter.to_bytes(8, "big"), domain=b"h2zq/" + domain)
        counter += 1
        for start in range(0, len(block) - nbytes + 1, nbytes):
            candidate = int.from_bytes(block[start : start + nbytes], "big") & mask
            if candidate < q:
                out.append(candidate)
                if len(out) == count:
                    break
    return np.array(out, dtype=np.int64)


def hash_to_indices(data: bytes, modulus: int, *, count: int) -> List[int]:
    """``count`` independent indices in ``[0, modulus)``.

    Used for Bloom-filter positions where a keyed, cryptographic hash is
    wanted instead of MurmurHash3.
    """
    return [int(x) for x in hash_to_zq(data, modulus, count=count, domain=b"idx")]
