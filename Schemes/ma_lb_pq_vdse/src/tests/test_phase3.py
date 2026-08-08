#!/usr/bin/env python3
"""Verification tests for MA-LB-PQ-VDSE Phase III modules.

Each test checks a DEFINING PROPERTY of the construction. A key delivery that
returns 1088 bytes but opens under the wrong decapsulation key has passed the
shallow test and failed the real one.

Runs standalone with no test framework::

    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase3.py           # all
    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase3.py delivery  # one module

and is also collectible by pytest if it is installed.

Covers ``user/delivery.py`` (Step 3), ``user/registration.py`` (Step 1) and
``user/profile.py`` (Step 4). Step 2 has no tests because it has no
implementation — the manuscript gives ``KeyGen`` as an interface only.

Phase I-II fixtures are imported from ``test_phase1_2`` rather than duplicated:
the stub group provider and the four-authority federation are both needed here,
and two copies would drift.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Common.crypto import kem as kem_mod  # noqa: E402
from Common.crypto import symmetric  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import types  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.aim import aim as aim_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.user import delivery as delivery_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.user import profile as profile_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.user import registration as reg_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.tests import test_phase1_2 as base  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


DOMAINS = base.DOMAINS


def require_kem() -> None:
    if not base.kem_available():
        raise Skip("no ML-KEM-768 backend available")


# ===========================================================================
# Fixtures
# ===========================================================================
def make_user(
    uid: str = "DU-1",
    domain: str = "hospital",
    role: str = "physician",
    credential: bytes = b"signed-credential-blob",
) -> reg_mod.User:
    require_kem()
    return reg_mod.User.create(
        uid=uid, domain=domain, role=role, credential=credential
    )


def make_share(
    authority_id: str = "AA1",
    uid: str = "DU-1",
    attributes: Tuple[str, ...] = ("AA1:attr01", "AA1:attr02"),
    key_material: bytes = b"opaque-SK_U_i-placeholder",
) -> types.AttributeKeyShare:
    """A placeholder SK_{U,i}.

    Opaque by design: Phase III Step 2's construction is undecided, and delivery
    is agnostic to what it delivers (PHASE_III_PLAN.md open decision 1).
    """
    return types.AttributeKeyShare(
        authority_id=authority_id,
        uid=uid,
        attributes=attributes,
        key_material=key_material,
    )


def make_policy(domain: str = "hospital", per_role: int = 4) -> reg_mod.RolePrefixPolicy:
    return reg_mod.RolePrefixPolicy(
        accepted_roles=("physician", "specialist"),
        attributes_per_role=per_role,
        domain=domain,
    )


# ===========================================================================
# types.py — Phase III records
# ===========================================================================
def test_user_request_binds_every_field():
    """Req_U = (UID, Dom, Role, Cred), plus the bound pk_U^KEM."""
    fields = dict(
        uid="DU-1",
        domain="hospital",
        role="physician",
        credential=b"cred",
        kem_encapsulation_key=b"pk",
    )
    base_request = types.UserRequest(**fields)
    for name, replacement in (
        ("uid", "DU-2"),
        ("domain", "laboratory"),
        ("role", "nurse"),
        ("credential", b"other-cred"),
        ("kem_encapsulation_key", b"other-pk"),
    ):
        variant = types.UserRequest(**{**fields, name: replacement})
        assert variant.digest() != base_request.digest(), f"{name} not bound"


def test_user_request_binds_the_kem_key_against_substitution():
    """An unbound pk_U^KEM would let an adversary receive the user's keys."""
    request = types.UserRequest(
        uid="DU-1",
        domain="hospital",
        role="physician",
        credential=b"cred",
        kem_encapsulation_key=b"honest-pk",
    )
    assert b"honest-pk" in request.encode()


def test_attribute_key_share_is_not_publishable():
    """SK_{U,i} is user secret key material, like MSK_i."""
    share = make_share()
    assert not isinstance(share, types.Record)
    for method in (share.encode, share.digest):
        try:
            method()
        except types.SecretMaterialError:
            continue
        raise AssertionError(f"{method.__name__} must refuse secret key material")


def test_attribute_key_share_repr_redacts():
    share = make_share(key_material=b"SECRET-KEY-BYTES")
    assert "SECRET-KEY-BYTES" not in repr(share)
    assert "redacted" in repr(share)


def test_attribute_key_share_sealing_round_trip():
    """to_sealed_bytes/from_sealed_bytes must be exact — it carries a key."""
    share = make_share(attributes=("AA1:a", "AA1:b", "AA1:c"))
    restored = types.AttributeKeyShare.from_sealed_bytes(share.to_sealed_bytes())
    assert restored == share


def test_attribute_key_share_sealing_rejects_trailing_bytes():
    share = make_share()
    try:
        types.AttributeKeyShare.from_sealed_bytes(share.to_sealed_bytes() + b"\x00")
    except types.EncodingError as exc:
        assert "trailing" in str(exc)
        return
    raise AssertionError("trailing bytes should be rejected")


def test_attribute_key_share_rejects_empty_attributes():
    try:
        make_share(attributes=())
    except ValueError:
        return
    raise AssertionError("a share covering no attribute should be refused")


def test_vap_requires_sorted_domains_and_commitments():
    """Canonical order, or the VAP digest depends on enumeration order."""
    for kwargs in (
        dict(domains=("hospital", "emergency"), commitments=(bytes(32),)),
        dict(
            domains=("emergency",),
            commitments=(bytes([1]) + bytes(31), bytes(32)),
        ),
    ):
        try:
            types.VersionBoundAuthorizationProfile(
                uid="DU-1", auth_root=bytes(32), vid=0, **kwargs
            )
        except ValueError:
            continue
        raise AssertionError(f"unsorted {list(kwargs)} should be refused")


# ===========================================================================
# user/delivery.py — Phase III Step 3
# ===========================================================================
def test_delivery_round_trip_recovers_the_share():
    """The defining property: the user gets back exactly what was sealed."""
    require_kem()
    user = make_user()
    share = make_share(uid=user.uid)
    receipt = delivery_mod.seal_key_share(share, user.encapsulation_key, vid=0)
    opened = delivery_mod.open_key_delivery(
        receipt.delivery, user.decapsulation_key, expected_uid=user.uid
    )
    assert opened == share
    assert opened.key_material == share.key_material


def test_delivery_uses_fips203_sizes():
    require_kem()
    user = make_user()
    receipt = delivery_mod.seal_key_share(
        make_share(uid=user.uid), user.encapsulation_key, vid=0
    )
    assert len(user.encapsulation_key) == kem_mod.ENCAPSULATION_KEY_BYTES == 1184
    assert receipt.kem_ciphertext_bytes == kem_mod.CIPHERTEXT_BYTES == 1088
    assert receipt.total_bytes == receipt.delivery.size_bytes


def test_delivery_key_is_an_aes256_key():
    require_kem()
    key = delivery_mod.derive_delivery_key(
        bytes(range(32)), uid="DU-1", authority_id="AA1", vid=0
    )
    assert len(key) == delivery_mod.DELIVERY_KEY_BYTES == symmetric.KEY_BYTES == 32


def test_delivery_rejects_a_wrong_length_shared_secret():
    try:
        delivery_mod.derive_delivery_key(
            b"short", uid="DU-1", authority_id="AA1", vid=0
        )
    except delivery_mod.DeliveryError as exc:
        assert "FIPS 203" in str(exc)
        return
    raise AssertionError("a wrong-length shared secret should be refused")


def test_delivery_rejects_a_wrong_length_encapsulation_key():
    require_kem()
    try:
        delivery_mod.seal_key_share(make_share(), b"too-short", vid=0)
    except delivery_mod.DeliveryError as exc:
        assert "ML-KEM-768" in str(exc)
        return
    raise AssertionError("a wrong-length pk_U^KEM should be refused")


def test_delivery_is_fresh_on_every_call():
    """Reusing an encapsulation would reuse K_i, and AES-GCM would lose authenticity."""
    require_kem()
    user = make_user()
    share = make_share(uid=user.uid)
    first = delivery_mod.seal_key_share(share, user.encapsulation_key, vid=0)
    second = delivery_mod.seal_key_share(share, user.encapsulation_key, vid=0)
    assert first.delivery.kem_ciphertext != second.delivery.kem_ciphertext
    assert first.delivery.sealed_key != second.delivery.sealed_key
    # Both still open to the same share.
    for receipt in (first, second):
        assert (
            delivery_mod.open_key_delivery(receipt.delivery, user.decapsulation_key)
            == share
        )


def test_delivery_fails_under_a_wrong_decapsulation_key():
    require_kem()
    user, other = make_user("DU-1"), make_user("DU-2")
    receipt = delivery_mod.seal_key_share(
        make_share(uid=user.uid), user.encapsulation_key, vid=0
    )
    try:
        delivery_mod.open_key_delivery(receipt.delivery, other.decapsulation_key)
    except delivery_mod.DeliveryAuthenticationError:
        return
    raise AssertionError("a wrong decapsulation key must not open the delivery")


def test_delivery_detects_tampering():
    require_kem()
    user = make_user()
    receipt = delivery_mod.seal_key_share(
        make_share(uid=user.uid), user.encapsulation_key, vid=0
    )
    tampered = types.EncryptedKeyDelivery(
        authority_id=receipt.delivery.authority_id,
        uid=receipt.delivery.uid,
        vid=receipt.delivery.vid,
        kem_ciphertext=receipt.delivery.kem_ciphertext,
        sealed_key=receipt.delivery.sealed_key[:-1]
        + bytes([receipt.delivery.sealed_key[-1] ^ 0x01]),
    )
    try:
        delivery_mod.open_key_delivery(tampered, user.decapsulation_key)
    except delivery_mod.DeliveryAuthenticationError:
        return
    raise AssertionError("a tampered EncKey_i must be detected")


def test_delivery_binding_prevents_replay_to_another_version():
    """The AEAD associated data binds VID, so a version change breaks the tag."""
    require_kem()
    user = make_user()
    receipt = delivery_mod.seal_key_share(
        make_share(uid=user.uid), user.encapsulation_key, vid=0
    )
    replayed = types.EncryptedKeyDelivery(
        authority_id=receipt.delivery.authority_id,
        uid=receipt.delivery.uid,
        vid=1,                                   # claims a different version
        kem_ciphertext=receipt.delivery.kem_ciphertext,
        sealed_key=receipt.delivery.sealed_key,
    )
    try:
        delivery_mod.open_key_delivery(replayed, user.decapsulation_key)
    except delivery_mod.DeliveryAuthenticationError:
        return
    raise AssertionError("a delivery replayed across versions must be refused")


def test_delivery_binding_prevents_replay_to_another_authority():
    require_kem()
    user = make_user()
    receipt = delivery_mod.seal_key_share(
        make_share(authority_id="AA1", uid=user.uid), user.encapsulation_key, vid=0
    )
    replayed = types.EncryptedKeyDelivery(
        authority_id="AA2",                      # claims a different issuer
        uid=receipt.delivery.uid,
        vid=receipt.delivery.vid,
        kem_ciphertext=receipt.delivery.kem_ciphertext,
        sealed_key=receipt.delivery.sealed_key,
    )
    try:
        delivery_mod.open_key_delivery(replayed, user.decapsulation_key)
    except delivery_mod.DeliveryAuthenticationError:
        return
    raise AssertionError("a delivery replayed across authorities must be refused")


def test_delivery_refuses_a_delivery_for_another_user():
    require_kem()
    user = make_user("DU-1")
    receipt = delivery_mod.seal_key_share(
        make_share(uid=user.uid), user.encapsulation_key, vid=0
    )
    try:
        delivery_mod.open_key_delivery(
            receipt.delivery, user.decapsulation_key, expected_uid="DU-2"
        )
    except delivery_mod.DeliveryError:
        return
    raise AssertionError("a delivery addressed elsewhere should be refused")


def test_delivery_info_differs_per_recipient_and_version():
    """The HKDF info binding: one derived key must not serve two recipients."""
    infos = {
        delivery_mod.delivery_info("DU-1", "AA1", 0),
        delivery_mod.delivery_info("DU-2", "AA1", 0),
        delivery_mod.delivery_info("DU-1", "AA2", 0),
        delivery_mod.delivery_info("DU-1", "AA1", 1),
    }
    assert len(infos) == 4


def test_delivery_info_cannot_be_reframed():
    """(uid='a', authority='b1') must not collide with (uid='a1', authority='b')."""
    assert delivery_mod.delivery_info("a", "b1", 0) != delivery_mod.delivery_info(
        "a1", "b", 0
    )


def test_delivery_associated_data_differs_per_binding():
    """The AEAD binding must actually differentiate recipients and versions.

    Isolated from the HKDF binding on purpose. The replay tests above pass as
    soon as EITHER binding is present, so without this the associated data could
    be dropped entirely and every test would still be green — which is exactly
    what a mutation run showed before this test existed.
    """
    bindings = {
        delivery_mod.delivery_associated_data("DU-1", "AA1", 0),
        delivery_mod.delivery_associated_data("DU-2", "AA1", 0),
        delivery_mod.delivery_associated_data("DU-1", "AA2", 0),
        delivery_mod.delivery_associated_data("DU-1", "AA1", 1),
    }
    assert len(bindings) == 4
    assert all(binding for binding in bindings)   # never empty


def test_delivery_associated_data_is_enforced_under_one_key():
    """Sealing and opening with mismatched AD must fail even with the same key.

    Uses a single derived key for both operations, so the HKDF info binding
    cannot be what rejects it — only the associated data can.
    """
    key = delivery_mod.derive_delivery_key(
        bytes(range(32)), uid="DU-1", authority_id="AA1", vid=0
    )
    sealed = symmetric.encrypt(
        key,
        b"payload",
        associated_data=delivery_mod.delivery_associated_data("DU-1", "AA1", 0),
    )
    try:
        symmetric.decrypt(
            key,
            sealed,
            associated_data=delivery_mod.delivery_associated_data("DU-1", "AA1", 1),
        )
    except Exception:
        return
    raise AssertionError("mismatched associated data must reject the ciphertext")


def test_delivery_derived_keys_differ_per_binding():
    secret = bytes(range(32))
    keys = {
        delivery_mod.derive_delivery_key(secret, uid="DU-1", authority_id="AA1", vid=0),
        delivery_mod.derive_delivery_key(secret, uid="DU-2", authority_id="AA1", vid=0),
        delivery_mod.derive_delivery_key(secret, uid="DU-1", authority_id="AA1", vid=1),
    }
    assert len(keys) == 3


def test_delivery_does_not_leak_the_share_in_the_clear():
    require_kem()
    user = make_user()
    marker = b"UNIQUE-SK-MATERIAL-MARKER"
    receipt = delivery_mod.seal_key_share(
        make_share(uid=user.uid, key_material=marker), user.encapsulation_key, vid=0
    )
    assert marker not in receipt.delivery.sealed_key
    assert marker not in receipt.delivery.encode()


def test_delivery_records_the_kem_backend():
    """A figure measured on the pure-Python backend is not reportable."""
    require_kem()
    user = make_user()
    receipt = delivery_mod.seal_key_share(
        make_share(uid=user.uid), user.encapsulation_key, vid=0
    )
    assert receipt.kem_backend in {"cryptography", "liboqs", "kyber_py"}


def test_delivery_detects_an_envelope_that_contradicts_its_contents():
    """The sealed plaintext repeats issuer and recipient; a mismatch fails closed."""
    require_kem()
    user = make_user()
    share = make_share(authority_id="AA1", uid=user.uid)
    vid = 0
    # Seal AA1's share but derive/bind under AA1, then relabel nothing — instead
    # seal a share whose inner authority disagrees with the envelope's.
    inner = make_share(authority_id="AA9", uid=user.uid)
    kem = kem_mod.MLKEM768()
    encapsulation = kem.encapsulate(user.encapsulation_key)
    key = delivery_mod.derive_delivery_key(
        encapsulation.shared_secret, uid=user.uid, authority_id="AA1", vid=vid
    )
    sealed = symmetric.encrypt(
        key,
        inner.to_sealed_bytes(),
        associated_data=delivery_mod.delivery_associated_data(user.uid, "AA1", vid),
    )
    forged = types.EncryptedKeyDelivery(
        authority_id="AA1",
        uid=user.uid,
        vid=vid,
        kem_ciphertext=encapsulation.ciphertext,
        sealed_key=sealed.to_bytes(),
    )
    try:
        delivery_mod.open_key_delivery(forged, user.decapsulation_key)
    except delivery_mod.DeliveryAuthenticationError as exc:
        assert "AA9" in str(exc)
        return
    raise AssertionError("an envelope contradicting its contents must be refused")
    assert share  # unreachable; keeps the fixture referenced


# ===========================================================================
# user/registration.py — Phase III Step 1
# ===========================================================================
def test_registration_user_generates_its_own_kem_keypair():
    """The user holds sk_U^KEM — nobody else can."""
    require_kem()
    user = make_user()
    assert len(user.encapsulation_key) == kem_mod.ENCAPSULATION_KEY_BYTES
    assert len(user.decapsulation_key) == kem_mod.DECAPSULATION_KEY_BYTES
    assert user.encapsulation_key != user.decapsulation_key


def test_registration_request_carries_the_published_tuple():
    require_kem()
    user = make_user(uid="DO-1", domain="laboratory", role="specialist")
    request = user.request()
    assert (request.uid, request.domain, request.role) == (
        "DO-1",
        "laboratory",
        "specialist",
    )
    assert request.kem_encapsulation_key == user.encapsulation_key


def test_registration_user_repr_hides_the_decapsulation_key():
    require_kem()
    user = make_user()
    assert user.decapsulation_key.hex()[:32] not in repr(user)
    assert "redacted" in repr(user)


def test_registration_policy_grants_a_deterministic_subset():
    require_kem()
    request = make_user().request()
    namespace = [f"AA1:attr{i:02d}" for i in range(1, 11)]
    granted = reg_mod.validate_request(
        request,
        authority_id="AA1",
        available_attributes=namespace,
        policy=make_policy(per_role=4),
    )
    assert granted == tuple(sorted(namespace)[:4])
    # Deterministic: the same request yields the same grant.
    assert granted == reg_mod.validate_request(
        request,
        authority_id="AA1",
        available_attributes=namespace,
        policy=make_policy(per_role=4),
    )


def test_registration_policy_refuses_an_unknown_role():
    require_kem()
    request = make_user(role="janitor").request()
    try:
        reg_mod.validate_request(
            request,
            authority_id="AA1",
            available_attributes=[f"AA1:attr{i:02d}" for i in range(1, 11)],
            policy=make_policy(),
        )
    except reg_mod.CredentialRejected as exc:
        assert "janitor" in str(exc)
        return
    raise AssertionError("an unaccepted role must be refused")


def test_registration_authorities_reach_independent_verdicts():
    """Phase III Step 1: each authority validates independently, locally.

    One request, two policies, two different outcomes — and neither policy is
    consulted by the other.
    """
    require_kem()
    request = make_user(role="physician").request()
    namespace = [f"AA1:attr{i:02d}" for i in range(1, 11)]

    accepting = reg_mod.RolePrefixPolicy(
        accepted_roles=("physician",), attributes_per_role=3, domain="hospital"
    )
    refusing = reg_mod.RolePrefixPolicy(
        accepted_roles=("researcher",), attributes_per_role=3, domain="laboratory"
    )
    granted = reg_mod.validate_request(
        request,
        authority_id="AA1",
        available_attributes=namespace,
        policy=accepting,
    )
    assert len(granted) == 3
    try:
        reg_mod.validate_request(
            request,
            authority_id="AA2",
            available_attributes=namespace,
            policy=refusing,
        )
    except reg_mod.CredentialRejected:
        return
    raise AssertionError("the second authority should have refused independently")


def test_registration_rejects_a_domain_no_authority_administers():
    require_kem()
    request = make_user(domain="atlantis-general").request()
    try:
        reg_mod.validate_request(
            request,
            authority_id="AA1",
            available_attributes=[f"AA1:attr{i:02d}" for i in range(1, 11)],
            policy=make_policy(),
            allowed_domains=DOMAINS,
        )
    except reg_mod.CredentialRejected as exc:
        assert "atlantis-general" in str(exc)
        return
    raise AssertionError("an unknown domain must be refused")


def test_registration_policy_can_require_a_matching_domain():
    require_kem()
    request = make_user(domain="laboratory", role="physician").request()
    policy = reg_mod.RolePrefixPolicy(
        accepted_roles=("physician",),
        attributes_per_role=2,
        domain="hospital",
        require_domain_match=True,
    )
    try:
        reg_mod.validate_request(
            request,
            authority_id="AA1",
            available_attributes=["AA1:a", "AA1:b", "AA1:c"],
            policy=policy,
        )
    except reg_mod.CredentialRejected:
        return
    raise AssertionError("a domain-restricted policy should refuse a foreign domain")


def test_registration_refuses_an_empty_credential():
    require_kem()
    try:
        make_user(credential=b"")
    except ValueError:
        return
    raise AssertionError("an empty credential should be refused")


def test_registration_enforces_the_subset_rule():
    """S_{U,i} subseteq A_i — a policy cannot grant another authority's attributes."""

    class OverreachingPolicy:
        def evaluate(self, request, available_attributes):
            return ("AA2:not-mine",)

    require_kem()
    try:
        reg_mod.validate_request(
            make_user().request(),
            authority_id="AA1",
            available_attributes=["AA1:a", "AA1:b"],
            policy=OverreachingPolicy(),
        )
    except reg_mod.RegistrationError as exc:
        assert "outside the authority's namespace" in str(exc)
        return
    raise AssertionError("granting outside A_i must be refused")


def test_registration_refuses_a_policy_that_grants_nothing():
    class EmptyPolicy:
        def evaluate(self, request, available_attributes):
            return ()

    require_kem()
    try:
        reg_mod.validate_request(
            make_user().request(),
            authority_id="AA1",
            available_attributes=["AA1:a"],
            policy=EmptyPolicy(),
        )
    except reg_mod.CredentialRejected:
        return
    raise AssertionError("an empty grant must refuse rather than issue an empty key")


def test_registration_accumulates_shares_and_derives_the_attribute_set():
    """S_U = union of S_{U,i} — the input to H(S_U) in Step 4."""
    require_kem()
    user = make_user()
    user.accept_share(make_share("AA1", user.uid, ("AA1:a", "AA1:b")))
    user.accept_share(make_share("AA2", user.uid, ("AA2:c",)))
    assert user.authority_count == 2                      # N_U
    assert user.authorities == ("AA1", "AA2")
    assert user.attribute_set() == ("AA1:a", "AA1:b", "AA2:c")


def test_registration_refuses_a_share_for_another_user():
    require_kem()
    user = make_user("DU-1")
    try:
        user.accept_share(make_share("AA1", "DU-2"))
    except reg_mod.RegistrationError:
        return
    raise AssertionError("a share for another user must be refused")


def test_registration_refuses_a_silent_reissue():
    require_kem()
    user = make_user()
    user.accept_share(make_share("AA1", user.uid))
    try:
        user.accept_share(make_share("AA1", user.uid, ("AA1:different",)))
    except reg_mod.RegistrationError as exc:
        assert "already held" in str(exc)
        return
    raise AssertionError("a second share from one authority must not land silently")


# ===========================================================================
# user/profile.py — Phase III Step 4
# ===========================================================================
def test_profile_auth_root_binds_all_four_inputs():
    """AuthRoot_U = H(UID || H(S_U) || VID_U || H(C_U)): four assertions."""
    kwargs = dict(
        uid="DU-1",
        attribute_digest=profile_mod.attribute_set_digest(["a", "b"]),
        vid=0,
        commitment_digest=profile_mod.commitment_set_digest([bytes(32)]),
    )
    root = profile_mod.authorization_root(**kwargs)
    variants = {
        "uid": dict(kwargs, uid="DU-2"),
        "attributes": dict(
            kwargs, attribute_digest=profile_mod.attribute_set_digest(["a", "b", "c"])
        ),
        "vid": dict(kwargs, vid=1),
        "commitments": dict(
            kwargs,
            commitment_digest=profile_mod.commitment_set_digest(
                [bytes(range(32))]
            ),
        ),
    }
    for name, variant in variants.items():
        assert profile_mod.authorization_root(**variant) != root, f"{name} not bound"


def test_profile_digests_are_order_independent():
    """The AIM enumerates authorities in no guaranteed order."""
    assert profile_mod.attribute_set_digest(["b", "a"]) == (
        profile_mod.attribute_set_digest(["a", "b"])
    )
    first, second = bytes(32), bytes(range(32))
    assert profile_mod.commitment_set_digest([second, first]) == (
        profile_mod.commitment_set_digest([first, second])
    )


def test_profile_digests_are_membership_sensitive():
    assert profile_mod.attribute_set_digest(["a"]) != (
        profile_mod.attribute_set_digest(["a", "b"])
    )


def test_profile_attribute_digest_is_separated_from_the_namespace_digest():
    """H(S_U) must not equal H(A_i) over the same strings."""
    attributes = ["AA1:a", "AA1:b"]
    assert profile_mod.attribute_set_digest(attributes) != (
        base.authority_mod.namespace_digest(attributes)
    )


def test_profile_rejects_empty_and_duplicate_sets():
    for call in (
        lambda: profile_mod.attribute_set_digest([]),
        lambda: profile_mod.commitment_set_digest([]),
        lambda: profile_mod.commitment_set_digest([bytes(32), bytes(32)]),
    ):
        try:
            call()
        except profile_mod.ProfileError:
            continue
        raise AssertionError("an empty or duplicated set should be refused")


def test_profile_vid_is_the_minimum_across_authorities():
    """Must match FogSearchNode.vid, since Phase VI subtracts one from the other."""
    assert profile_mod.aggregate_vid([3, 7, 5]) == 3
    assert profile_mod.aggregate_vid([0]) == 0


def test_profile_vid_aggregation_matches_the_fsn_rule():
    """The coherence property: VID_U and VID_j on one scale."""
    node = base.fsn_mod.FogSearchNode.create("FSN1", ["hospital", "laboratory"])
    node.apply_meta("AA1", types.AuthorizationMeta("hospital", 7, bytes(32)))
    node.apply_meta("AA2", types.AuthorizationMeta("laboratory", 2, bytes(32)))
    assert node.vid() == profile_mod.aggregate_vid([7, 2]) == 2


def test_profile_built_from_the_aim_matches_its_registry():
    _, _, aim, authorities, _, _ = base.phase_i_ii_federation()
    participating = [authorities[0].authority_id, authorities[1].authority_id]
    vap = profile_mod.build_profile_from_aim(
        aim,
        uid="DU-1",
        authority_ids=participating,
        attributes=["AA1:a", "AA2:b"],
    )
    assert vap.uid == "DU-1"
    assert vap.authority_count == 2                       # N_U
    assert vap.domains == tuple(
        sorted({authorities[0].domain, authorities[1].domain})
    )
    assert vap.commitments == tuple(
        sorted([authorities[0].commitment(), authorities[1].commitment()])
    )
    assert vap.vid == 0


def test_profile_verifies_from_its_inputs_alone():
    """Phase VIII Step 2 recomputes AuthRoot_U without trusting the AIM."""
    _, _, aim, authorities, _, _ = base.phase_i_ii_federation()
    attributes = ["AA1:a", "AA2:b"]
    vap = profile_mod.build_profile_from_aim(
        aim,
        uid="DU-1",
        authority_ids=[authorities[0].authority_id, authorities[1].authority_id],
        attributes=attributes,
    )
    assert profile_mod.verify_profile(vap, attributes=attributes)
    # A different attribute set must not verify against the same root.
    assert not profile_mod.verify_profile(vap, attributes=attributes + ["AA1:extra"])


def test_profile_is_version_bound():
    """The property the profile is named for: an authority's VID change invalidates it."""
    _, chain, aim, authorities, _, _ = base.phase_i_ii_federation()
    participating = [authorities[0].authority_id, authorities[1].authority_id]
    attributes = ["AA1:a", "AA2:b"]
    vap = profile_mod.build_profile_from_aim(
        aim, uid="DU-1", authority_ids=participating, attributes=attributes
    )
    assert profile_mod.profile_matches_aim(vap, aim, participating)

    # Phase VII Step 3: one authority revokes, increments, republishes.
    authorities[1].revocation.revoke("patient-7")
    authorities[1].vid += 1
    chain.publish_authorization_state(authorities[1].state())
    aim.synchronize_from_ledger(chain, authorities[1].authority_id)

    assert not profile_mod.profile_matches_aim(vap, aim, participating)
    rebuilt = profile_mod.build_profile_from_aim(
        aim, uid="DU-1", authority_ids=participating, attributes=attributes
    )
    assert rebuilt.auth_root != vap.auth_root
    # VID_U stays at the minimum, so one advanced authority does not lift it.
    assert rebuilt.vid == 0


def test_profile_vid_tracks_the_stalest_authority():
    _, chain, aim, authorities, _, _ = base.phase_i_ii_federation()
    participating = [a.authority_id for a in authorities[:2]]
    for authority in authorities[:2]:
        authority.vid += 1
        chain.publish_authorization_state(authority.state())
        aim.synchronize_from_ledger(chain, authority.authority_id)
    vap = profile_mod.build_profile_from_aim(
        aim, uid="DU-1", authority_ids=participating, attributes=["a"]
    )
    assert vap.vid == 1        # both advanced, so the minimum advanced


def test_profile_rejects_an_unknown_authority():
    _, _, aim, _, _, _ = base.phase_i_ii_federation()
    try:
        profile_mod.build_profile_from_aim(
            aim, uid="DU-1", authority_ids=["AA-absent"], attributes=["a"]
        )
    except aim_mod.AIMError:
        return
    raise AssertionError("an unknown authority must not produce a profile")


def test_profile_rejects_empty_and_duplicate_authority_sets():
    _, _, aim, authorities, _, _ = base.phase_i_ii_federation()
    for authority_ids in ([], [authorities[0].authority_id] * 2):
        try:
            profile_mod.build_profile_from_aim(
                aim, uid="DU-1", authority_ids=authority_ids, attributes=["a"]
            )
        except profile_mod.ProfileError:
            continue
        raise AssertionError(f"authority_ids={authority_ids} should be refused")


def test_profile_rejects_a_domain_outside_the_federation():
    try:
        profile_mod.build_profile(
            uid="DU-1",
            domains=["atlantis-general"],
            attributes=["a"],
            vids=[0],
            commitments=[bytes(32)],
            allowed_domains=DOMAINS,
        )
    except profile_mod.ProfileError as exc:
        assert "atlantis-general" in str(exc)
        return
    raise AssertionError("a domain no authority administers must be refused")


def test_profile_carries_no_key_material():
    """The AIM maintains the VAP and is not trusted with keys."""
    require_kem()
    _, _, aim, authorities, _, _ = base.phase_i_ii_federation()
    user = make_user()
    marker = b"SECRET-SK-MATERIAL"
    user.accept_share(
        make_share(authorities[0].authority_id, user.uid, ("AA1:a",), marker)
    )
    vap = profile_mod.build_profile_from_aim(
        aim,
        uid=user.uid,
        authority_ids=[authorities[0].authority_id],
        attributes=user.attribute_set(),
    )
    encoded = vap.encode()
    assert marker not in encoded
    assert authorities[0].master_key.alpha not in encoded


# ===========================================================================
# Phase III end to end
# ===========================================================================
def test_phase_iii_end_to_end_for_a_data_user_and_a_data_owner():
    """Steps 1, 3 and 4 for both roles across 2 of 4 authorities.

    N_U = 2 rather than 4: §V does not fix N_U, and partial enrolment is what
    exercises the multi-authority path — full enrolment would hide any bug that
    only appears when a user lacks an authority.
    """
    require_kem()
    _, chain, aim, authorities, _, _ = base.phase_i_ii_federation()
    namespace_of = {a.authority_id: a.attributes for a in authorities}

    for uid, role, domain in (
        ("DU-1", "physician", "hospital"),
        ("DO-1", "specialist", "laboratory"),
    ):
        user = reg_mod.User.create(
            uid=uid, domain=domain, role=role, credential=b"credential-blob"
        )
        request = user.request()                                    # Step 1
        participating = [authorities[0], authorities[1]]

        for authority in participating:
            granted = reg_mod.validate_request(                     # Step 1 verdict
                request,
                authority_id=authority.authority_id,
                available_attributes=namespace_of[authority.authority_id],
                policy=reg_mod.RolePrefixPolicy(
                    accepted_roles=("physician", "specialist"),
                    attributes_per_role=3,
                    domain=authority.domain,
                ),
                allowed_domains=aim.domains(),
            )
            assert set(granted) <= set(namespace_of[authority.authority_id])

            # Step 2 is blocked, so the share carries an opaque placeholder.
            share = types.AttributeKeyShare(
                authority_id=authority.authority_id,
                uid=uid,
                attributes=granted,
                key_material=b"opaque-SK_U_i-" + uid.encode(),
            )
            receipt = delivery_mod.seal_key_share(                  # Step 3
                share, request.kem_encapsulation_key, vid=authority.vid
            )
            opened = delivery_mod.open_key_delivery(
                receipt.delivery, user.decapsulation_key, expected_uid=uid
            )
            assert opened == share
            user.accept_share(opened)

        assert user.authority_count == 2
        vap = profile_mod.build_profile_from_aim(                   # Step 4
            aim,
            uid=uid,
            authority_ids=list(user.authorities),
            attributes=user.attribute_set(),
        )
        assert profile_mod.verify_profile(vap, attributes=user.attribute_set())
        assert vap.authority_count == 2
        assert len(vap.domains) == 2
        assert vap.vid == 0

    # Phase III publishes nothing, so the chain is untouched by it: still the
    # 9 entries Phase I-II left (4 Reg_i + 4 State_i + 1 PP).
    assert chain.entry_count() == 9
    assert chain.verify_chain()
    aim.verify_against_ledger(chain)


def test_phase_iii_data_owner_profile_supplies_auth_root_for_phase_iv():
    """AuthRoot_DO is what Phase IV Step 5 binds into Commit_i."""
    require_kem()
    _, _, aim, authorities, _, _ = base.phase_i_ii_federation()
    owner_attributes = list(authorities[0].attributes[:2])
    vap = profile_mod.build_profile_from_aim(
        aim,
        uid="DO-1",
        authority_ids=[authorities[0].authority_id],
        attributes=owner_attributes,
    )
    assert len(vap.auth_root) == types.DIGEST_BYTES
    assert profile_mod.verify_profile(vap, attributes=owner_attributes)


# ===========================================================================
# Runner
# ===========================================================================
def _collect(selector: str | None) -> List[Tuple[str, Callable[[], None]]]:
    tests = [
        (name, obj)
        for name, obj in globals().items()
        if name.startswith("test_") and callable(obj)
    ]
    if selector:
        tests = [(n, f) for n, f in tests if selector in n]
    return sorted(tests)


def main(argv: List[str]) -> int:
    selector = argv[1] if len(argv) > 1 else None
    tests = _collect(selector)
    if not tests:
        print(f"no tests match {selector!r}")
        return 2

    passed: List[str] = []
    skipped: List[Tuple[str, str]] = []
    failed: List[Tuple[str, str]] = []

    for name, fn in tests:
        try:
            fn()
        except Skip as exc:
            skipped.append((name, str(exc)))
            print(f"SKIP  {name}  ({exc})")
        except Exception:
            failed.append((name, traceback.format_exc()))
            print(f"FAIL  {name}")
        else:
            passed.append(name)
            print(f"ok    {name}")

    print(
        f"\n{len(passed)} passed, {len(skipped)} skipped, {len(failed)} failed "
        f"out of {len(tests)}"
    )
    for name, tb in failed:
        print(f"\n{'=' * 70}\nFAILED: {name}\n{'=' * 70}\n{tb}")
    if skipped:
        print("\nSkipped (optional backends not installed):")
        for name, reason in skipped:
            print(f"  {name}: {reason}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
