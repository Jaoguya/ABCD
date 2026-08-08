"""Phase III Step 3 — Post-Quantum Secure Key Delivery.

Manuscript `Overleaf/PQ-AVDSE-OJCOMS:526`:

    (ct_i, ss_i) <- ML-KEM.Encaps(pk_U^KEM)
    K_i          = HKDF(ss_i)
    EncKey_i     = AES-256-GCM.Enc(K_i, SK_{U,i})

A KEM-DEM hybrid: ML-KEM-768 establishes a per-delivery shared secret, HKDF
expands it into an AES-256-GCM key, and the attribute key share is sealed under
it. Every primitive comes from ``Common/crypto`` (liboqs 0.16.0 for ML-KEM), so
this step needs no pairing backend and is complete today — which is why
``PHASE_III_PLAN.md`` schedules it before Steps 1 and 4 despite the protocol
order.

The share being delivered is **opaque** to this module. Phase III Step 2's
``KeyGen`` is an interface only in the manuscript, so ``SK_{U,i}``'s structure is
undecided; delivery is agnostic to what it delivers, and nothing here will change
when that decision lands.

**Two bindings the manuscript does not specify** (`benchmark` provenance, no
measurable cost, both recorded in ``PHASE_III_PLAN.md``):

* HKDF ``info`` is ``(kdf.info_prefix, UID, ID_i, VID_i)``. The paper writes
  ``HKDF(ss_i)`` with no salt or info, which would let one derived key serve any
  recipient. Binding the triple means a key derived for one user and authority
  cannot be reused for another.
* The AEAD associated data is the same triple, so ``EncKey_i`` cannot be replayed
  to a different user or across an authorization version change. The AEAD tag
  fails rather than yielding a wrong plaintext.

**Observation — the manuscript's forward-secrecy claim does not hold.** `:547`
states this mechanism "provides confidentiality, forward secrecy, and resistance
against quantum adversaries during attribute-key distribution". Encapsulation is
to a **static** ``pk_U^KEM``, so an adversary who records ``ct_i`` and later
compromises the user's decapsulation key recovers ``ss_i``, hence ``K_i``, hence
``SK_{U,i}``. Forward secrecy would require an ephemeral KEM keypair per
delivery. This module implements the published static-key construction and
reports the observation, on the Ref[41] precedent — strengthening our own scheme
beyond what it claims would be as much a fidelity failure as weakening a baseline.
Confidentiality and post-quantum resistance do hold.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes, kem as kem_mod, symmetric  # noqa: E402
from Common.crypto.config import get as crypto_get  # noqa: E402

from ..types import (  # noqa: E402
    AttributeKeyShare,
    EncryptedKeyDelivery,
    canonical,
)

#: Width of the HKDF output — an AES-256 key (crypto.yaml: aead.key_bits: 256).
DELIVERY_KEY_BYTES = symmetric.KEY_BYTES


class DeliveryError(RuntimeError):
    """Raised when key delivery cannot be completed."""


class DeliveryAuthenticationError(DeliveryError):
    """Raised when a delivery fails to authenticate.

    Covers a tampered ciphertext, a wrong decapsulation key, and a delivery
    addressed to a different user or version — the AEAD cannot distinguish these,
    and neither should a caller: all three mean "do not use this key".
    """


def _binding(uid: str, authority_id: str, vid: int) -> bytes:
    """The recipient triple bound into both the HKDF info and the AEAD AD.

    Length-prefixed and type-tagged through ``types.canonical``, so
    ``(uid="a", authority_id="b1")`` cannot frame-collide with
    ``(uid="a1", authority_id="b")``.
    """
    return canonical([uid, authority_id, vid])


def delivery_info(uid: str, authority_id: str, vid: int) -> bytes:
    """HKDF ``info`` for one delivery."""
    prefix = str(crypto_get("global", "kdf", "info_prefix")).encode("utf-8")
    return canonical([prefix, _binding(uid, authority_id, vid)])


def delivery_associated_data(uid: str, authority_id: str, vid: int) -> bytes:
    """AES-256-GCM associated data for one delivery."""
    return _binding(uid, authority_id, vid)


def derive_delivery_key(
    shared_secret: bytes, *, uid: str, authority_id: str, vid: int
) -> bytes:
    """``K_i = HKDF(ss_i)``, with the recipient triple bound into ``info``."""
    if len(shared_secret) != kem_mod.SHARED_SECRET_BYTES:
        raise DeliveryError(
            f"ML-KEM shared secret must be {kem_mod.SHARED_SECRET_BYTES} bytes "
            f"(FIPS 203), got {len(shared_secret)}"
        )
    return hashes.hkdf_sha256(
        shared_secret,
        length=DELIVERY_KEY_BYTES,
        info=delivery_info(uid, authority_id, vid),
    )


@dataclass(frozen=True)
class DeliveryReceipt:
    """A sealed delivery plus the figures Phase III reports.

    ``kem_ciphertext_bytes`` and ``sealed_key_bytes`` are the on-wire cost of
    post-quantum key distribution. They are a setup cost, reported separately
    from the Exp. 1 trapdoor curve per the Exp. 1 measurement rule, never inside
    it.
    """

    delivery: EncryptedKeyDelivery
    kem_backend: str
    kem_ciphertext_bytes: int
    sealed_key_bytes: int

    @property
    def total_bytes(self) -> int:
        return self.kem_ciphertext_bytes + self.sealed_key_bytes


def seal_key_share(
    share: AttributeKeyShare,
    encapsulation_key: bytes,
    *,
    vid: int,
    kem: Optional[kem_mod.MLKEM768] = None,
) -> DeliveryReceipt:
    """Authority side of Step 3: encapsulate, derive, and seal ``SK_{U,i}``.

    A **fresh** encapsulation per call, so two deliveries of the same share share
    neither ``ct_i`` nor ciphertext. Reusing an encapsulation would reuse ``K_i``,
    and an AES-GCM key with a repeated nonce loses authenticity outright.
    """
    kem = kem or kem_mod.MLKEM768()
    if len(encapsulation_key) != kem_mod.ENCAPSULATION_KEY_BYTES:
        raise DeliveryError(
            f"pk_U^KEM must be {kem_mod.ENCAPSULATION_KEY_BYTES} bytes for "
            f"ML-KEM-768 (FIPS 203), got {len(encapsulation_key)}"
        )

    encapsulation = kem.encapsulate(encapsulation_key)
    key = derive_delivery_key(
        encapsulation.shared_secret,
        uid=share.uid,
        authority_id=share.authority_id,
        vid=vid,
    )
    sealed = symmetric.encrypt(
        key,
        share.to_sealed_bytes(),
        associated_data=delivery_associated_data(share.uid, share.authority_id, vid),
    )
    delivery = EncryptedKeyDelivery(
        authority_id=share.authority_id,
        uid=share.uid,
        vid=vid,
        kem_ciphertext=encapsulation.ciphertext,
        sealed_key=sealed.to_bytes(),
    )
    return DeliveryReceipt(
        delivery=delivery,
        kem_backend=kem.backend,
        kem_ciphertext_bytes=len(encapsulation.ciphertext),
        sealed_key_bytes=len(delivery.sealed_key),
    )


def open_key_delivery(
    delivery: EncryptedKeyDelivery,
    decapsulation_key: bytes,
    *,
    kem: Optional[kem_mod.MLKEM768] = None,
    expected_uid: Optional[str] = None,
) -> AttributeKeyShare:
    """User side of Step 3: decapsulate, derive, open, and check the share.

    ``expected_uid`` guards against acting on a delivery addressed to someone
    else. The AEAD binding already makes such a delivery fail to open, but a
    caller that knows its own identity should say so rather than relying on the
    tag alone to notice.
    """
    kem = kem or kem_mod.MLKEM768()
    if expected_uid is not None and delivery.uid != expected_uid:
        raise DeliveryError(
            f"delivery is addressed to {delivery.uid!r}, not {expected_uid!r}"
        )

    try:
        shared_secret = kem.decapsulate(decapsulation_key, delivery.kem_ciphertext)
    except Exception as exc:
        raise DeliveryAuthenticationError(
            f"ML-KEM decapsulation failed: {type(exc).__name__}: {exc}"
        ) from exc

    key = derive_delivery_key(
        shared_secret,
        uid=delivery.uid,
        authority_id=delivery.authority_id,
        vid=delivery.vid,
    )
    try:
        plaintext = symmetric.decrypt(
            key,
            symmetric.Ciphertext.from_bytes(delivery.sealed_key),
            associated_data=delivery_associated_data(
                delivery.uid, delivery.authority_id, delivery.vid
            ),
        )
    except Exception as exc:
        # ML-KEM decapsulation does not fail on a wrong key — it returns an
        # implicitly-rejected secret — so a wrong key surfaces HERE, as an AEAD
        # tag failure, and is indistinguishable from tampering. That is the
        # correct outcome, not a missing check.
        raise DeliveryAuthenticationError(
            f"could not open EncKey_i for {delivery.uid!r} from "
            f"{delivery.authority_id!r} at VID {delivery.vid}: wrong "
            f"decapsulation key, a tampered ciphertext, or a delivery bound to "
            f"different (UID, authority, VID) values"
        ) from exc

    share = AttributeKeyShare.from_sealed_bytes(plaintext)
    # The sealed plaintext repeats the recipient and issuer, so a mismatch means
    # the sealer and the envelope disagree. Cheap to check, and it fails closed.
    if share.uid != delivery.uid or share.authority_id != delivery.authority_id:
        raise DeliveryAuthenticationError(
            f"sealed share claims ({share.authority_id!r}, {share.uid!r}) but the "
            f"delivery claims ({delivery.authority_id!r}, {delivery.uid!r})"
        )
    return share


__all__ = [
    "DELIVERY_KEY_BYTES",
    "DeliveryError",
    "DeliveryAuthenticationError",
    "DeliveryReceipt",
    "delivery_info",
    "delivery_associated_data",
    "derive_delivery_key",
    "seal_key_share",
    "open_key_delivery",
]
