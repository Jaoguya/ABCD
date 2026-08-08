#!/usr/bin/env python3
"""Verification tests for MA-LB-PQ-VDSE Phase I-II modules.

Each test checks a DEFINING PROPERTY of the construction, not that a call
returns bytes of the right length. A commitment that is 32 bytes but does not
change when the authorization version changes has passed the shallow test and
failed the real one.

Runs standalone with no test framework::

    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase1_2.py         # all
    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase1_2.py ledger  # one module

and is also collectible by pytest if it is installed.

Covers ``types.py`` (canonical encoding, protocol records) and
``chain/ledger.py``. Modules not written yet have no tests here yet.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Schemes.ma_lb_pq_vdse.src import types  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.chain import ledger as ledger_mod  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


# ===========================================================================
# Fixtures — no pairing backend required (see types.py module docstring: group
# elements are bytes at this layer, so Phase I-II is testable on a host with no
# charm-crypto build).
# ===========================================================================
def make_suite(**overrides) -> types.PrimitiveSuite:
    kwargs = dict(
        hash_algorithm="sha256",
        aead_algorithm="aes-256-gcm",
        kdf_algorithm="hkdf-sha256",
        kem_algorithm="ml-kem-768",
        kem_backend="liboqs",
        pairing_type="type-3",
        pairing_curve="BN254",
        pairing_backend="charm_type3",
    )
    kwargs.update(overrides)
    return types.PrimitiveSuite(**kwargs)


def make_public_key(seed: bytes = b"aa1") -> types.AuthorityPublicKey:
    return types.AuthorityPublicKey(
        g1=b"g1", g2=b"g2", e_g1g2_alpha=seed + b"-egt", g1_beta=seed + b"-g1b"
    )


def make_registration(
    authority_id: str = "AA1", domain: str = "hospital"
) -> types.AuthorityRegistration:
    return types.AuthorityRegistration(
        authority_id=authority_id,
        domain=domain,
        public_key=make_public_key(authority_id.encode()),
    )


def make_state(
    authority_id: str = "AA1", vid: int = 0, commitment: bytes | None = None
) -> types.AuthorityState:
    # `is None`, not `or`: b"" is falsy, and `or` would silently substitute the
    # default, so the zero-length case would never reach the validator under
    # test.
    return types.AuthorityState(
        authority_id=authority_id,
        public_key=make_public_key(authority_id.encode()),
        commitment=bytes(range(32)) if commitment is None else commitment,
        vid=vid,
    )


def fresh_ledger() -> ledger_mod.InProcessLedger:
    # Deterministic clock: entry hashes then depend only on committed content,
    # so a test asserting on the chain is not asserting on the wall clock.
    counter = {"t": 0}

    def clock() -> int:
        counter["t"] += 1
        return counter["t"]

    return ledger_mod.InProcessLedger(clock=clock)


# ===========================================================================
# types.py — canonical encoding
# ===========================================================================
def test_canonical_is_deterministic():
    value = ["a", 1, b"x", True, ["nested", 2]]
    assert types.canonical(value) == types.canonical(value)


def test_canonical_separates_types_that_share_a_representation():
    """b"", "" and 0 must not share an encoding.

    Length-prefixing alone would map all three to a zero length prefix; the
    type tag is what separates them.
    """
    encodings = {
        types.canonical(b""),
        types.canonical(""),
        types.canonical(0),
        types.canonical([]),
    }
    assert len(encodings) == 4


def test_canonical_prevents_framing_collision():
    """("ab","c") and ("a","bc") must not collide — the reason for the prefixes."""
    assert types.canonical(["ab", "c"]) != types.canonical(["a", "bc"])


def test_canonical_distinguishes_bool_from_int():
    """bool is a subclass of int; True must not encode as 1."""
    assert types.canonical(True) != types.canonical(1)
    assert types.canonical(False) != types.canonical(0)


def test_canonical_integer_encoding_is_minimal_and_signed():
    assert types.canonical(5) != types.canonical(-5)
    # Distinct magnitudes stay distinct across the byte-length boundary.
    assert types.canonical(255) != types.canonical(256)


def test_canonical_rejects_dict():
    """A dict has no inherent order, so encoding one would hide an ordering choice."""
    try:
        types.canonical({"a": 1})
    except types.EncodingError:
        return
    raise AssertionError("dict should not be canonically encodable")


def test_canonical_rejects_unsupported_type():
    try:
        types.canonical(object())
    except types.EncodingError:
        return
    raise AssertionError("arbitrary objects should not be encodable")


def test_record_domain_separation():
    """Two records with identical field bytes must not share a digest.

    AuthorizationMeta(domain, vid, commitment) and a hypothetical record with
    the same three fields differ only by their domain tag; that tag is what
    stops a Meta digest from being replayed as another record's digest.
    """
    meta = types.AuthorizationMeta(domain="hospital", vid=3, commitment=bytes(32))
    assert meta.digest() != types.hashes.sha256(meta.encode())
    assert meta.digest() == types.hashes.sha256(
        meta.encode(), domain=types.AuthorizationMeta.DOMAIN
    )


# ===========================================================================
# types.py — Phase I records
# ===========================================================================
def test_suite_refuses_symmetric_pairing():
    """Phase I Step 1 publishes e : G_1 x G_2 -> G_T.

    A Type-I curve changes group-element sizes and pairing cost, so accepting
    one would silently report numbers from a different construction
    (crypto.yaml: allow_symmetric_backend: false).
    """
    try:
        make_suite(pairing_type="type-1", pairing_curve="SS512")
    except ValueError:
        return
    raise AssertionError("a Type-I pairing must be refused for this scheme")


def test_public_parameters_digest_is_order_independent():
    """PP's digest must not depend on the order authorities registered in."""
    suite = make_suite()
    keys = [("AA2", make_public_key(b"AA2")), ("AA1", make_public_key(b"AA1"))]
    forward = types.PublicParameters.build(suite, b"g1", b"g2", keys)
    reverse = types.PublicParameters.build(suite, b"g1", b"g2", list(reversed(keys)))
    assert forward.digest() == reverse.digest()
    assert forward.authority_count == 2


def test_public_parameters_digest_changes_with_any_authority_key():
    suite = make_suite()
    base = types.PublicParameters.build(
        suite, b"g1", b"g2", [("AA1", make_public_key(b"AA1"))]
    )
    changed = types.PublicParameters.build(
        suite, b"g1", b"g2", [("AA1", make_public_key(b"different"))]
    )
    assert base.digest() != changed.digest()


def test_public_parameters_digest_changes_with_the_curve():
    """A run on a different curve must not present the same PP."""
    keys = [("AA1", make_public_key(b"AA1"))]
    on_bn254 = types.PublicParameters.build(make_suite(), b"g1", b"g2", keys)
    on_mnt224 = types.PublicParameters.build(
        make_suite(pairing_curve="MNT224"), b"g1", b"g2", keys
    )
    assert on_bn254.digest() != on_mnt224.digest()


def test_public_parameters_rejects_unsorted_and_duplicate_ids():
    suite = make_suite()
    try:
        types.PublicParameters(
            suite=suite,
            g1=b"g1",
            g2=b"g2",
            authority_public_keys=(
                ("AA2", make_public_key(b"AA2")),
                ("AA1", make_public_key(b"AA1")),
            ),
        )
    except ValueError:
        pass
    else:
        raise AssertionError("unsorted authority keys should be rejected")

    try:
        types.PublicParameters(
            suite=suite,
            g1=b"g1",
            g2=b"g2",
            authority_public_keys=(
                ("AA1", make_public_key(b"a")),
                ("AA1", make_public_key(b"b")),
            ),
        )
    except ValueError:
        return
    raise AssertionError("duplicate authority IDs should be rejected")


def test_public_parameters_lookup():
    pp = types.PublicParameters.build(
        make_suite(), b"g1", b"g2", [("AA1", make_public_key(b"AA1"))]
    )
    assert pp.public_key("AA1").e_g1g2_alpha == b"AA1-egt"
    try:
        pp.public_key("AA9")
    except KeyError:
        return
    raise AssertionError("an unknown authority should raise")


# ===========================================================================
# types.py — master secret key containment
# ===========================================================================
def test_master_key_cannot_be_encoded_or_digested():
    """MSK_i = (alpha_i, beta_i) must have no published form."""
    msk = types.AuthorityMasterKey(alpha=b"alpha-secret", beta=b"beta-secret")
    for method in (msk.encode, msk.digest):
        try:
            method()
        except types.SecretMaterialError:
            continue
        raise AssertionError(f"{method.__name__} should refuse secret material")


def test_master_key_is_not_a_record():
    """Not being a Record is what keeps MSK off the ledger, which only takes Records."""
    msk = types.AuthorityMasterKey(alpha=b"a", beta=b"b")
    assert not isinstance(msk, types.Record)


def test_master_key_repr_redacts():
    """A stack trace or debug log must not print alpha_i."""
    msk = types.AuthorityMasterKey(alpha=b"alpha-secret", beta=b"beta-secret")
    assert "alpha-secret" not in repr(msk)
    assert "beta-secret" not in str(msk)
    assert "redacted" in repr(msk)


def test_master_key_bytes_never_appear_in_published_records():
    """Assert on the encoded bytes, not by inspection of the field list."""
    alpha = b"ALPHA-SECRET-MATERIAL"
    beta = b"BETA-SECRET-MATERIAL"
    types.AuthorityMasterKey(alpha=alpha, beta=beta)  # exists, but is not published
    pp = types.PublicParameters.build(
        make_suite(), b"g1", b"g2", [("AA1", make_public_key(b"AA1"))]
    )
    registration = make_registration()
    state = make_state()
    for record in (pp, registration, state):
        assert alpha not in record.encode()
        assert beta not in record.encode()


# ===========================================================================
# types.py — Phase II records
# ===========================================================================
def test_authority_state_validates_commitment_width():
    """A truncated digest must fail at construction, not at verification time."""
    for bad in (b"", bytes(31), bytes(33)):
        try:
            make_state(commitment=bad)
        except ValueError:
            continue
        raise AssertionError(f"commitment of {len(bad)} bytes should be rejected")


def test_authority_state_rejects_negative_vid():
    """Phase VII defines VID' = VID + 1; a negative version is a bug."""
    try:
        make_state(vid=-1)
    except ValueError:
        return
    raise AssertionError("a negative VID should be rejected")


def test_authority_state_digest_binds_every_field():
    """Changing ANY field must change the digest — the record's binding property."""
    base = make_state()
    variants = [
        make_state(authority_id="AA2"),
        make_state(vid=1),
        make_state(commitment=bytes(range(1, 33))),
        types.AuthorityState(
            authority_id=base.authority_id,
            public_key=make_public_key(b"other"),
            commitment=base.commitment,
            vid=base.vid,
        ),
    ]
    for variant in variants:
        assert variant.digest() != base.digest()


def test_authorization_meta_is_smaller_than_state():
    """Meta_i carries no authority public key — the AIM does not forward it."""
    meta = types.AuthorizationMeta(domain="hospital", vid=0, commitment=bytes(32))
    state = make_state()
    assert b"AA1-egt" in state.encode()
    assert b"AA1-egt" not in meta.encode()


def test_records_are_immutable():
    """A published record must not change after its digest was anchored."""
    state = make_state()
    try:
        state.vid = 7  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("records must be frozen")


# ===========================================================================
# chain/ledger.py
# ===========================================================================
def test_ledger_initializes_all_namespaces_empty():
    """Phase I Step 4: the metadata repository exists before anything writes to it."""
    chain = fresh_ledger()
    sizes = chain.namespace_sizes()
    assert set(sizes) == set(ledger_mod.NAMESPACES)
    assert all(count == 0 for count in sizes.values())
    assert chain.entry_count() == 0
    assert chain.verify_chain()


def test_ledger_refuses_non_records():
    """The type gate is what keeps AuthorityMasterKey off the chain."""
    chain = fresh_ledger()
    msk = types.AuthorityMasterKey(alpha=b"a", beta=b"b")
    try:
        chain.append(ledger_mod.NS_AUTHORITY_REGISTRATIONS, "AA1", msk)  # type: ignore[arg-type]
    except TypeError:
        return
    raise AssertionError("only Record instances may be committed")


def test_ledger_refuses_unknown_namespace():
    chain = fresh_ledger()
    try:
        chain.append("invented_namespace", "k", make_registration())
    except ledger_mod.LedgerError:
        return
    raise AssertionError("an unknown namespace should raise")


def test_ledger_is_append_only():
    """Re-registering an authority ID must be rejected (Phase II Step 1)."""
    chain = fresh_ledger()
    chain.register_authority(make_registration("AA1", "hospital"))
    try:
        chain.register_authority(make_registration("AA1", "laboratory"))
    except ledger_mod.ImmutabilityError:
        return
    raise AssertionError("a second registration for one ID should be rejected")


def test_ledger_read_back_is_identical():
    chain = fresh_ledger()
    registration = make_registration("AA1", "hospital")
    entry = chain.register_authority(registration)
    assert chain.get_registration("AA1") == registration
    assert entry.payload == registration.encode()
    assert entry.domain == types.AuthorityRegistration.DOMAIN


def test_ledger_missing_record_raises_not_found():
    chain = fresh_ledger()
    try:
        chain.get_registration("AA-absent")
    except ledger_mod.NotFoundError:
        pass
    else:
        raise AssertionError("an absent registration should raise NotFoundError")
    assert not chain.exists(ledger_mod.NS_AUTHORITY_REGISTRATIONS, "AA-absent")


def test_ledger_state_requires_prior_registration():
    """Phase II Step 1 precedes Step 4: an unauthenticatable state is refused."""
    chain = fresh_ledger()
    try:
        chain.publish_authorization_state(make_state("AA1", 0))
    except ledger_mod.NotFoundError:
        return
    raise AssertionError("a state for an unregistered authority should be refused")


def test_ledger_retains_state_history_and_finds_the_latest():
    """Phase VII publishes VID+1 rather than overwriting; history must survive."""
    chain = fresh_ledger()
    chain.register_authority(make_registration("AA1"))
    for vid in range(3):
        chain.publish_authorization_state(
            make_state("AA1", vid, commitment=bytes([vid]) + bytes(31))
        )
    assert chain.latest_authorization_state("AA1").vid == 2
    assert [s.vid for s in chain.authorization_state_history("AA1")] == [0, 1, 2]
    assert chain.get_authorization_state("AA1", 0).vid == 0


def test_ledger_latest_state_survives_the_key_padding_boundary():
    """Zero-padded keys mean lexicographic order equals numeric order.

    Without padding, "AA1#9" would sort after "AA1#10" and the latest state
    would be wrong precisely once the version count crossed a power of ten.
    """
    chain = fresh_ledger()
    chain.register_authority(make_registration("AA1"))
    for vid in (9, 10, 11):
        chain.publish_authorization_state(make_state("AA1", vid))
    assert chain.latest_authorization_state("AA1").vid == 11


def test_ledger_state_keys_do_not_collide_across_authorities():
    chain = fresh_ledger()
    for authority_id in ("AA1", "AA11"):
        chain.register_authority(make_registration(authority_id))
        chain.publish_authorization_state(make_state(authority_id, 0))
    # "AA1#..." must not be matched by the prefix scan for "AA11".
    assert len(chain.keys(ledger_mod.NS_AUTHORIZATION_STATES, prefix="AA1#")) == 1
    assert len(chain.keys(ledger_mod.NS_AUTHORIZATION_STATES, prefix="AA11#")) == 1


def test_ledger_latest_state_absent_raises():
    chain = fresh_ledger()
    chain.register_authority(make_registration("AA1"))
    try:
        chain.latest_authorization_state("AA1")
    except ledger_mod.NotFoundError:
        return
    raise AssertionError("no published state should raise NotFoundError")


def test_ledger_chain_links_every_entry():
    """Each entry commits to its predecessor — the tamper-evidence property."""
    chain = fresh_ledger()
    chain.register_authority(make_registration("AA1"))
    chain.publish_authorization_state(make_state("AA1", 0))
    entries = chain.entries()
    assert entries[0].sequence == 0
    assert entries[1].previous_hash == entries[0].entry_hash
    assert chain.chain_head() == entries[-1].entry_hash
    assert chain.verify_chain()


def test_ledger_detects_a_tampered_entry():
    """verify_chain must FAIL on tampering, which is the whole point of Exp. 4."""
    chain = fresh_ledger()
    chain.register_authority(make_registration("AA1"))
    chain.publish_authorization_state(make_state("AA1", 0))
    assert chain.verify_chain()

    # Substitute a different payload at position 0, keeping its stored hash —
    # exactly what an adversary rewriting history would attempt.
    original = chain._entries[0]
    chain._entries[0] = ledger_mod.LedgerEntry(
        sequence=original.sequence,
        namespace=original.namespace,
        key=original.key,
        payload=make_registration("AA1", "laboratory").encode(),
        domain=original.domain,
        timestamp_ns=original.timestamp_ns,
        previous_hash=original.previous_hash,
        entry_hash=original.entry_hash,
        record=original.record,
    )
    assert not chain.verify_chain()


def test_ledger_publish_public_parameters_is_keyed_by_digest():
    """Republishing identical PP is a duplicate; changed PP lands under a new key."""
    chain = fresh_ledger()
    pp = types.PublicParameters.build(
        make_suite(), b"g1", b"g2", [("AA1", make_public_key(b"AA1"))]
    )
    entry = chain.publish_public_parameters(pp)
    assert entry.key == pp.digest().hex()
    try:
        chain.publish_public_parameters(pp)
    except ledger_mod.ImmutabilityError:
        pass
    else:
        raise AssertionError("republishing identical PP should be an overwrite")

    changed = types.PublicParameters.build(
        make_suite(pairing_curve="MNT224"), b"g1", b"g2", [("AA1", make_public_key(b"AA1"))]
    )
    assert chain.publish_public_parameters(changed).key != entry.key
    assert len(chain.keys(ledger_mod.NS_SYSTEM_PARAMETERS)) == 2


def test_ledger_state_key_rejects_negative_vid():
    try:
        ledger_mod.state_key("AA1", -1)
    except ValueError:
        return
    raise AssertionError("a negative VID should not produce a key")


def test_ledger_registered_authorities_is_sorted():
    chain = fresh_ledger()
    for authority_id in ("AA3", "AA1", "AA2"):
        chain.register_authority(make_registration(authority_id))
    assert chain.registered_authorities() == ["AA1", "AA2", "AA3"]


def test_ledger_four_authorities_one_per_domain():
    """The topology fixed on 2026-08-08: N_AA = 4, one AA per domain."""
    chain = fresh_ledger()
    domains = ("hospital", "laboratory", "insurance", "emergency")
    for index, domain in enumerate(domains, start=1):
        authority_id = f"AA{index}"
        chain.register_authority(make_registration(authority_id, domain))
        chain.publish_authorization_state(make_state(authority_id, 0))
    assert len(chain.registered_authorities()) == 4
    assert {chain.get_registration(a).domain for a in chain.registered_authorities()} == set(
        domains
    )
    assert chain.entry_count() == 8
    assert chain.verify_chain()


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
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
