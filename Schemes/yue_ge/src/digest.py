"""keccak256 and the XOR multiset accumulator — Ref[55] §VI-A / §VII-A.

The paper builds its verification digests with keccak256 (§VII-A names it
alongside SHA-256 in the OpenSSL toolchain, and the digests are consumed by an
Ethereum contract, which is keccak256's natural home).

**keccak256 is not SHA3-256.** They differ in the domain-separation byte —
Keccak pads with `0x01`, NIST SHA-3 with `0x06` — so `hashlib.sha3_256` would
silently produce different digests. Ethereum uses original Keccak. We use
pycryptodome's `Crypto.Hash.keccak`, already pinned in `requirements.txt`, and
`test_scheme.py` checks it against the known `keccak256("")` vector so a wrong
implementation fails loudly instead of producing plausible wrong numbers.

This lives in the scheme rather than in `Common/` because keccak256 is specific
to Ref[55]'s on-chain digests; no other scheme here uses it (README §245:
`Common/` holds primitives that *multiple* schemes cite).
"""

from __future__ import annotations

from Crypto.Hash import keccak

DIGEST_BYTES = 32
ZERO_DIGEST = b"\x00" * DIGEST_BYTES


def keccak256(*parts: bytes) -> bytes:
    """keccak256 over the concatenation of ``parts``.

    Parts are length-prefixed so that ``(b"ab", b"c")`` and ``(b"a", b"bc")``
    give different digests — without it the XOR accumulator below could be
    manipulated by re-splitting inputs.
    """
    h = keccak.new(digest_bits=256)
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return h.digest()


def xor_digest(a: bytes, b: bytes) -> bytes:
    """XOR two digests — the multiset-hash combiner of §VI-A.

    XOR is commutative and associative, so the combined digest does not depend
    on the order files are returned in, and self-cancelling, so a deletion
    digest removes exactly the addition it mirrors. Those two properties are
    what let ``Verify`` stay one 32-byte comparison no matter how large the
    result set is.
    """
    return bytes(x ^ y for x, y in zip(a, b))
