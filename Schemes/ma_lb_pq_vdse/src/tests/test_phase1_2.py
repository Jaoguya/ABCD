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

import dataclasses
import sys
import traceback
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Schemes.ma_lb_pq_vdse.src import config as config_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import types  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.authority import authority as authority_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.authority import initializer  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.authority import revocation as revocation_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.aim import aim as aim_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.chain import ledger as ledger_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.fsn import fsn as fsn_mod  # noqa: E402


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


def kem_available() -> bool:
    """Whether an ML-KEM-768 backend is live, so KEM tests skip rather than fail."""
    from Common.crypto import kem

    return any(kem.available_backends().values())


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
# config.py
# ===========================================================================
def test_config_loads_and_validates():
    """The committed configuration must be self-consistent as it stands."""
    config = config_mod.load(reload=True)
    assert config.defaults.keywords_per_query == 5      # §VI
    assert config.defaults.domains == 4                 # §VI
    assert config.topology.fog_search_nodes == 4        # §VI
    assert config.measurement.repetitions == 10         # §VI (was 30, 2026-09-03)
    assert config.measurement.confidence_interval == 0.95


def test_config_every_experiment_includes_us():
    """The proposed scheme participates in all 8 experiments of Section VI.

    EIGHT, not nine. Exp. 9 was folded into Exp. 4 on 2026-09-12: Section VI
    defines no Experiment 9, it defines one Exp. 4 whose figure has two panels
    over two variables, and those are ARMS of Exp. 4 rather than a separate
    experiment.
    """
    config = config_mod.load()
    assert len(config.our_experiments()) == 8


def test_config_authority_topology_matches_the_decision():
    """N_AA = 4, one per domain, |A_i| = 10 (both `benchmark` provenance)."""
    authorities = config_mod.load().authorities
    assert authorities.count == 4
    assert authorities.authority_to_domain == "one_to_one"
    assert authorities.attributes_per_authority == 10
    assert authorities.initial_vid == 0
    assert authorities.disjoint_attribute_universes


def test_config_scheduler_weights_are_fixed_and_internally_consistent():
    """The sweep ran 2026-08-28, so scheduler.yaml's weights are fixed.

    Was test_config_scheduler_weights_are_still_pending, which asserted the
    weights could never be fixed -- it encoded an open TODO as an invariant.
    What must actually hold is that `status` and `provisional` agree with each
    other and that the vector is a valid simplex point; a config claiming
    `fixed` while still flagged provisional, or weights not summing to 1,
    would let an untuned scheduler be reported as AASS.
    """
    scheduler = config_mod.load().scheduler
    assert scheduler.weights.is_fixed
    assert not scheduler.weights.provisional
    assert scheduler.refuse_reportable_runs_while_pending  # gate stays armed
    total = sum(scheduler.weights.as_tuple())
    assert abs(total - 1.0) < 1e-9, f"weights sum to {total}, not 1.0"
    assert all(w >= 0 for w in scheduler.weights.as_tuple())


def test_config_refuses_reportable_run_on_pending_weights():
    """The gate that stops Exp. 7-8 reporting an untuned scheduler as AASS.

    The live config now carries swept weights, so the gate is exercised against
    a deliberately pending copy rather than against whatever the config happens
    to say today. That keeps this testing the MECHANISM -- which must survive
    the weights being fixed -- instead of the current state.
    """
    import dataclasses

    scheduler = config_mod.load().scheduler
    # Fixed weights must pass.
    scheduler.require_fixed(context="exp7")
    # Pending weights must still refuse, with an actionable message.
    pending = dataclasses.replace(
        scheduler,
        weights=dataclasses.replace(
            scheduler.weights, status="pending_sweep", provisional=True
        ),
    )
    try:
        pending.require_fixed(context="exp7")
    except config_mod.SchedulerWeightsPendingError as exc:
        assert "pending_sweep" in str(exc)
        assert "scheduler.yaml" in str(exc), (
            "the message must name where the fix lives; it used to cite "
            "an issue number in the deleted operator guide, whose numbering "
            "no longer exists"
        )
        return
    raise AssertionError("provisional weights must refuse a reportable run")


def test_config_scheduler_has_exactly_the_four_ablation_variants():
    assert set(config_mod.load().scheduler.variants) == {
        "no_lb",
        "round_robin",
        "least_loaded",
        "aass",
    }


def test_config_workload_holdout_is_distinct_and_not_reportable():
    """The hold-out must differ in seed, or the weights are fitted in-sample."""
    config = config_mod.load()
    reported, holdout = config.reported_workload, config.holdout_workload
    assert reported.reportable and not holdout.reportable
    assert reported.trace_seed != holdout.trace_seed
    assert reported.trace_path != holdout.trace_path


def test_config_workload_inheritance_resolves():
    """The hold-out overrides only seed and run counts; the rest is inherited."""
    holdout = config_mod.load_workload("exp78_sweep_holdout.yaml")
    # Overridden.
    assert holdout.repetitions == 3
    assert holdout.concurrency == (1000, 5000)
    # Inherited from the reported workload rather than restated.
    assert holdout.ramp_seconds == 30
    assert holdout.verify_sha256
    assert holdout.replay_identical_to_all_variants
    # meta must NOT be inherited, or the hold-out would claim role `reported`.
    assert holdout.role == "sweep_holdout"


def test_config_exp7_and_exp8_are_the_same_runs():
    """global.yaml: both metric sets come from one set of runs."""
    config = config_mod.load()
    exp7, exp8 = config.experiment("exp7"), config.experiment("exp8")
    assert exp8.shares_runs_with == exp7.name
    assert exp7.values == exp8.values == config.reported_workload.concurrency


def test_config_validation_catches_an_fsn_mismatch():
    """A validator that never fails is not a validator."""
    config = config_mod.load()
    broken = dataclasses.replace(
        config, topology=dataclasses.replace(config.topology, fog_search_nodes=7)
    )
    try:
        broken.validate()
    except config_mod.ConfigError as exc:
        assert "FSN count" in str(exc)
        return
    raise AssertionError("an FSN count mismatch should fail validation")


def test_config_validation_catches_authority_domain_mismatch():
    config = config_mod.load()
    broken = dataclasses.replace(
        config, authorities=dataclasses.replace(config.authorities, count=3)
    )
    try:
        broken.validate()
    except config_mod.ConfigError:
        return
    raise AssertionError("N_AA != domains under one_to_one should fail")


def test_config_validation_catches_outlier_dropping():
    """global.yaml requires outliers kept; a config saying otherwise must fail."""
    config = config_mod.load()
    broken = dataclasses.replace(
        config, measurement=dataclasses.replace(config.measurement, drop_outliers=True)
    )
    try:
        broken.validate()
    except config_mod.ConfigError as exc:
        assert "outlier" in str(exc).lower()
        return
    raise AssertionError("drop_outliers must fail validation")


def test_config_validation_catches_wrong_repetition_count():
    config = config_mod.load()
    broken = dataclasses.replace(
        config, measurement=dataclasses.replace(config.measurement, repetitions=30)
    )
    try:
        broken.validate()
    except config_mod.ConfigError:
        return
    raise AssertionError("repetitions != 10 must fail validation")


def test_config_missing_key_names_the_full_path():
    """A typo must fail loudly rather than default to something plausible."""
    try:
        config_mod._require({"a": {"b": 1}}, "a", "c", source="test.yaml")
    except config_mod.ConfigError as exc:
        assert "a.c" in str(exc) and "test.yaml" in str(exc)
        return
    raise AssertionError("an absent key should raise naming its path")


def test_config_hashes_include_the_workload_files():
    """The workload trace determines Exp. 7-8, so it belongs in provenance."""
    hashes = config_mod.config_hashes()
    assert "global.yaml" in hashes
    assert "scheduler.yaml" in hashes
    assert any(name.startswith("workload/") for name in hashes)
    assert all(len(value) == 64 for value in hashes.values())


def test_config_corpus_reference_detects_manifest_drift():
    """Catches exactly the stale-manifest case found in the tree on 2026-08-08."""
    stale = {
        "records": 1206159,          # corpus v1
        "keyword_universe_size": 2102,
        "keyword_document_pairs": 18785334,
        "domains": 4,
    }
    try:
        config_mod.verify_corpus_reference(stale)
    except config_mod.CorpusReferenceError as exc:
        assert "records" in str(exc)
        return
    raise AssertionError("a v1 manifest must not validate against index.yaml")


def test_config_corpus_reference_accepts_the_frozen_corpus():
    config = config_mod.load()
    reference = config.index.corpus_reference
    config_mod.verify_corpus_reference(
        {
            "records": reference["records"],
            "keyword_universe_size": reference["keyword_universe"],
            "keyword_document_pairs": reference["keyword_document_pairs"],
            "domains": reference["domains"],
        }
    )


def test_config_thread_pinning_reports_without_raising():
    """A dev host that has not sourced provision.sh must still run tests."""
    report = config_mod.thread_pinning_report()
    assert "OMP_NUM_THREADS" in report
    config_mod.verify_thread_pinning(require=False)


# ===========================================================================
# authority/initializer.py — Phase I Steps 1 and 3
# ===========================================================================
def stub_group(**overrides) -> initializer.GroupDescription:
    """A group NOT from a real backend, hence faithful=False.

    Lives in the test file, not in src: the scheme must contain no code path
    that could produce a group without a real pairing backend.
    """
    params = dict(
        curve="BN254",
        backend="stub-not-a-backend",
        g1=b"g1-element",
        g2=b"g2-element",
        e_g1_g2=b"egt-element",
        faithful=False,
    )
    params.update(overrides)
    return initializer.GroupDescription(**params)


def stub_provider(_pairing_params) -> initializer.GroupDescription:
    return stub_group()


def test_initializer_resolves_a_genuinely_type_3_group_or_says_why_not():
    """Step 1 must resolve a real Type-III group, and must NEVER substitute SS512.

    Was test_initializer_refuses_to_resolve_a_group_today, which asserted
    resolve_group always raised. CharmType3Backend landed 2026-08-28, so that
    assertion now encodes a state that no longer exists. The invariant worth
    keeping is not "it refuses" but "it never silently downgrades to Type-I":
    on a host with charm it resolves a type-3 group, and anywhere else it
    raises with an actionable reason rather than falling back.
    """
    params = config_mod.load().crypto["pairing"]
    try:
        group = initializer.resolve_group(params)
    except initializer.PairingBackendMissingError as exc:
        # Acceptable only off the experiment host (charm is Linux-only). The
        # message must still be actionable.
        assert str(exc)
        return
    assert group.faithful is True
    assert group.backend == "charm_type3"
    assert group.curve == params.get("curve", "BN254")
    # The failure this guards against: a Type-I curve silently standing in.
    assert "ss512" not in group.backend.lower()
    assert group.g1 and group.g2 and group.e_g1_g2
    # G1 and G2 must be genuinely different groups, not the same one twice.
    assert group.g1 != group.g2


def test_initializer_step1_builds_the_primitive_set():
    """Phase I Step 1: P = {H, SHA-256, AES-256-GCM, HKDF, ML-KEM}."""
    context = initializer.initialize(group_provider=stub_provider)
    assert context.suite.hash_algorithm == "sha256"
    assert context.suite.aead_algorithm == "aes-256-gcm"
    assert context.suite.kdf_algorithm == "hkdf-sha256"
    assert context.suite.kem_algorithm == "ml-kem-768"
    assert context.suite.pairing_type == "type-3"
    assert context.primitive_set() == (
        "H",
        "sha256",
        "aes-256-gcm",
        "hkdf-sha256",
        "ml-kem-768",
    )


def test_initializer_step1_self_tests_the_primitives():
    """A broken ML-KEM backend must fail at Phase I, not in Phase III."""
    if not kem_available():
        raise Skip("no ML-KEM-768 backend available")
    context = initializer.initialize(group_provider=stub_provider, self_test=True)
    assert context.kem.self_test()
    assert context.suite.kem_backend == context.kem.backend


def test_initializer_records_the_live_kem_backend():
    """run_meta.json must show whether a number came from liboqs or pure Python."""
    if not kem_available():
        raise Skip("no ML-KEM-768 backend available")
    context = initializer.initialize(group_provider=stub_provider)
    assert context.suite.kem_backend in {"cryptography", "liboqs", "kyber_py"}


def test_initializer_stub_group_is_not_reportable():
    """The seam must not become a route to a reportable number."""
    context = initializer.initialize(group_provider=stub_provider)
    assert not context.reportable
    try:
        context.assert_reportable()
    except initializer.UnfaithfulGroupError:
        return
    raise AssertionError("an unfaithful group must refuse a reportable run")


def test_initializer_rejects_a_faithful_group_on_the_wrong_curve():
    """A provider must not deliver a curve other than the configured one."""

    def wrong_curve(_params):
        return stub_group(curve="SS512", faithful=True)

    try:
        initializer.initialize(group_provider=wrong_curve)
    except initializer.UnfaithfulGroupError as exc:
        assert "SS512" in str(exc)
        return
    raise AssertionError("an unconfigured curve should be refused")


def test_initializer_accepts_the_configured_fallback_curve():
    """MNT224 is the recorded fallback, so a faithful MNT224 group is allowed."""

    def fallback(_params):
        return stub_group(curve="MNT224", backend="charm_type3", faithful=True)

    context = initializer.initialize(group_provider=fallback)
    assert context.reportable
    context.assert_reportable()
    assert context.suite.pairing_curve == "MNT224"


def test_initializer_group_precomputes_the_pairing_generator():
    """e(g_1,g_2) is computed once, not once per authority (Phase I Step 2)."""
    context = initializer.initialize(group_provider=stub_provider)
    assert context.group.e_g1_g2


def test_initializer_group_rejects_empty_elements():
    try:
        stub_group(g1=b"")
    except ValueError:
        return
    raise AssertionError("an empty group element should be rejected")


def test_initializer_step3_publishes_pp_to_the_ledger():
    """Phase I Step 3: PP is assembled and anchored."""
    context = initializer.initialize(group_provider=stub_provider)
    chain = fresh_ledger()
    keys = [
        (f"AA{i}", make_public_key(f"AA{i}".encode())) for i in range(1, 5)
    ]
    pp = initializer.publish_public_parameters(chain, context, keys)
    assert pp.authority_count == 4
    assert chain.keys(ledger_mod.NS_SYSTEM_PARAMETERS) == [pp.digest().hex()]
    assert chain.verify_chain()


def test_initializer_step3_requires_every_authority_in_pp():
    """PP carries {PK_i} for i = 1..N_AA; a short set is a setup bug."""
    context = initializer.initialize(group_provider=stub_provider)
    try:
        initializer.build_public_parameters(
            context, [("AA1", make_public_key(b"AA1"))]
        )
    except initializer.InitializationError as exc:
        assert "N_AA=4" in str(exc)
        return
    raise AssertionError("PP with fewer than N_AA authority keys should be refused")


def test_initializer_step3_pp_carries_the_suite_and_generators():
    context = initializer.initialize(group_provider=stub_provider)
    pp = initializer.build_public_parameters(context)
    assert pp.suite == context.suite
    assert pp.g1 == context.group.g1
    assert pp.g2 == context.group.g2
    # PP must not contain the precomputed pairing generator: Phase I Step 3
    # lists e itself, and each PK_i carries e(g_1,g_2)^{alpha_i}.
    assert context.group.e_g1_g2 not in pp.encode()


def test_initializer_pp_digest_is_stable_across_contexts():
    """Two identical initializations must agree on PP, or provenance is useless."""
    keys = [(f"AA{i}", make_public_key(f"AA{i}".encode())) for i in range(1, 5)]
    first = initializer.build_public_parameters(
        initializer.initialize(group_provider=stub_provider), keys
    )
    second = initializer.build_public_parameters(
        initializer.initialize(group_provider=stub_provider), keys
    )
    assert first.digest() == second.digest()


def test_initializer_kem_setup_cost_is_reported_separately():
    """Exp. 1 excludes encapsulation; it is a one-time figure with a backend tag."""
    if not kem_available():
        raise Skip("no ML-KEM-768 backend available")
    cost = initializer.measure_kem_setup_cost(repetitions=3)
    for key in ("keygen_ms", "encapsulate_ms", "decapsulate_ms", "backend"):
        assert key in cost
    assert cost["repetitions"] == 3
    assert all(
        cost[k] > 0 for k in ("keygen_ms", "encapsulate_ms", "decapsulate_ms")
    )


# ===========================================================================
# authority/revocation.py — RevRoot_i
# ===========================================================================
def test_revocation_empty_list_has_the_sentinel_root():
    """Every authority starts empty at Phase II Step 3, so the root must exist."""
    revocation = revocation_mod.RevocationList()
    assert revocation.is_empty
    assert revocation.root() == revocation_mod.EMPTY_REVOCATION_ROOT
    assert len(revocation.root()) == 32


def test_revocation_sentinel_is_not_all_zeros():
    """bytes(32) would collide with a contrived tree and read as 'not computed'."""
    assert revocation_mod.EMPTY_REVOCATION_ROOT != bytes(32)


def test_revocation_sentinel_cannot_collide_with_a_populated_root():
    """The sentinel must be distinguishable from every real tree root.

    A populated root comes from merkle.hash_leaf/hash_node, which prefix their
    inputs with 0x00/0x01; the sentinel is a domain-tagged sha256. Checked here
    against a one-leaf tree, which is the closest case.
    """
    single = revocation_mod.RevocationList(["user-1"])
    assert single.root() != revocation_mod.EMPTY_REVOCATION_ROOT
    from Common.crypto import merkle

    assert (
        revocation_mod.EMPTY_REVOCATION_ROOT
        != merkle.hash_leaf(revocation_mod.revocation_leaf("user-1"))
    )


def test_revocation_root_is_order_independent():
    """RevRoot_i is over the SET, so a verifier holding it can recompute it."""
    forward = revocation_mod.RevocationList(["u1", "u2", "u3"])
    reverse = revocation_mod.RevocationList(["u3", "u1", "u2"])
    assert forward.root() == reverse.root()


def test_revocation_root_is_membership_sensitive():
    base = revocation_mod.RevocationList(["u1", "u2"])
    extra = revocation_mod.RevocationList(["u1", "u2", "u3"])
    assert base.root() != extra.root()


def test_revocation_is_idempotent():
    revocation = revocation_mod.RevocationList(["u1"])
    root = revocation.root()
    revocation.revoke("u1")
    assert revocation.root() == root
    assert len(revocation) == 1


def test_revocation_restore_returns_to_the_previous_root():
    """The root is a function of the current set, not of its history."""
    revocation = revocation_mod.RevocationList(["u1", "u2"])
    before = revocation.root()
    revocation.revoke("u3")
    assert revocation.root() != before
    revocation.restore("u3")
    assert revocation.root() == before


def test_revocation_restore_rejects_an_unrevoked_identifier():
    try:
        revocation_mod.RevocationList(["u1"]).restore("u2")
    except revocation_mod.RevocationError:
        return
    raise AssertionError("restoring an unrevoked identifier should raise")


def test_revocation_updates_one_path_per_revocation():
    """Phase VII Step 2 updates RevRoot incrementally, and Exp. 6 sweeps to 1e5.

    A rebuild per revocation is O(delta^2) hashing and makes Exp. 6 measure this
    class instead of the DIAS mechanism — which is exactly what happened, at a
    measured O(n^2.02). Assert the mechanism, not just the root: a full rebuild
    would also change the root, so a root-only test cannot tell the two apart.
    """
    revocation = revocation_mod.RevocationList()
    revocation.revoke_many(f"user-{i}" for i in range(500))
    assert revocation.path_updates == 500     # one path per revocation
    revocation.root()
    revocation.root()
    assert revocation.path_updates == 500     # reading the root costs nothing


def test_revocation_cost_per_update_does_not_grow_with_the_list():
    """The property Exp. 6 needs: revocation 10,000 costs what revocation 1 did.

    Timed rather than counted, because the counter above would still pass if the
    per-path work itself grew. Compares the second half of a 4,000-revocation
    run against the first half; a rebuild-per-update implementation makes the
    second half ~3x the first, so the 2x bound fails loudly while leaving room
    for ordinary timing noise on a shared machine.
    """
    import time

    revocation = revocation_mod.RevocationList()

    def timed(lo: int, hi: int) -> float:
        start = time.perf_counter()
        for i in range(lo, hi):
            revocation.revoke(f"user-{i}")
            revocation.root()
        return time.perf_counter() - start

    # Retry a few times and accept the best attempt. A wall-clock ratio is
    # sensitive to whatever else the machine is doing, and this failed once in a
    # full-suite run while passing 3/3 in isolation — a flaky test that cries
    # wolf is worse than no test. A genuinely O(delta^2) implementation fails
    # every attempt (the ratio there is ~3x and grows), so retrying loses no
    # power against the defect this exists to catch.
    ratios = []
    for _ in range(3):
        revocation.__init__()          # fresh list, same closure
        first_half = timed(0, 2_000)
        second_half = timed(2_000, 4_000)
        ratios.append(second_half / max(first_half, 1e-4))
        if ratios[-1] < 2.0:
            return
    assert False, (
        f"per-update cost grew with list size on every attempt "
        f"(second-half/first-half ratios: {[round(r, 2) for r in ratios]}) — "
        f"RevRoot is not incremental"
    )


def test_revocation_mutation_invalidates_the_cached_root():
    revocation = revocation_mod.RevocationList(["u1"])
    first = revocation.root()
    revocation.revoke("u2")
    assert revocation.root() != first


def test_revocation_inclusion_proof_verifies():
    """'Authenticated' is why this is a Merkle tree rather than a flat digest."""
    revocation = revocation_mod.RevocationList([f"user-{i}" for i in range(9)])
    proof = revocation.prove("user-4")
    assert revocation.verify("user-4", proof)
    assert proof.path_length > 0


def test_revocation_proof_fails_against_a_changed_root():
    revocation = revocation_mod.RevocationList([f"user-{i}" for i in range(9)])
    proof = revocation.prove("user-4")
    revocation.revoke("user-99")
    assert not revocation.verify("user-4", proof)


def test_revocation_cannot_prove_an_unrevoked_identifier():
    revocation = revocation_mod.RevocationList(["u1"])
    try:
        revocation.prove("u2")
    except revocation_mod.RevocationError:
        return
    raise AssertionError("proving a non-member should raise")


def test_revocation_empty_list_has_no_tree():
    try:
        revocation_mod.RevocationList().tree()
    except revocation_mod.RevocationError as exc:
        assert "sentinel" in str(exc)
        return
    raise AssertionError("an empty list has no Merkle tree")


def test_revocation_leaf_rejects_empty_and_non_string():
    for bad in ("", 42, None):
        try:
            revocation_mod.revocation_leaf(bad)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        raise AssertionError(f"{bad!r} should not be a valid revoked identifier")


def test_revocation_leaf_does_not_carry_the_plaintext_identifier():
    """Leaves are hashed, so the tree does not expose user identifiers."""
    leaf = revocation_mod.revocation_leaf("patient-12345")
    assert b"patient-12345" not in leaf
    assert len(leaf) == 32


# ===========================================================================
# authority/authority.py — Phase I Step 2, Phase II Steps 1-3
# ===========================================================================
class StubGroupOperations:
    """Group arithmetic for tests only.

    NOT the published construction — it is a hash-based stand-in that is
    deterministic, distinct per exponent, and never in src/. Every key pair it
    produces belongs to a context whose group is faithful=False, so
    assert_reportable() refuses.
    """

    def __init__(self) -> None:
        self._counter = 0

    def random_exponent(self) -> bytes:
        self._counter += 1
        return types.hashes.sha256(
            self._counter.to_bytes(4, "big"), domain=b"test/exponent"
        )

    def exponentiate_gt(self, base: bytes, exponent: bytes) -> bytes:
        return types.hashes.sha256(base, exponent, domain=b"test/gt")

    def exponentiate_g1(self, base: bytes, exponent: bytes) -> bytes:
        return types.hashes.sha256(base, exponent, domain=b"test/g1")


# One shared exponent source for the whole suite, so successive authorities draw
# DIFFERENT exponents. A fresh stub per authority would restart its counter and
# hand every authority the same alpha_i and beta_i — which a real backend's RNG
# would never do, and which would quietly make the independence assertions
# vacuous.
_SHARED_OPERATIONS = StubGroupOperations()


def make_authority(
    authority_id: str = "AA1",
    domain: str = "hospital",
    registry: "authority_mod.AttributeNamespaceRegistry | None" = None,
    attributes=None,
    context=None,
    operations=None,
) -> authority_mod.Authority:
    context = context or initializer.initialize(group_provider=stub_provider)
    count = context.config.authorities.attributes_per_authority
    return authority_mod.Authority.create(
        context,
        authority_id=authority_id,
        domain=domain,
        attributes=attributes or authority_mod.default_attributes(authority_id, count),
        operations=operations or _SHARED_OPERATIONS,
        registry=registry,
    )


def test_authority_step2_is_blocked_without_a_pairing_backend():
    """Phase I Step 2 must refuse rather than invent group arithmetic."""
    context = initializer.initialize(group_provider=stub_provider)
    try:
        authority_mod.setup_authority_keys(context)  # no operations injected
    except authority_mod.GroupOperationsUnavailableError as exc:
        assert "backend_implemented" in str(exc)
        return
    raise AssertionError("Step 2 must raise with no group operations")


def test_authority_step2_produces_the_published_key_shape():
    """MSK_i = (alpha_i, beta_i); PK_i = (g1, g2, e(g1,g2)^alpha, g1^beta)."""
    context = initializer.initialize(group_provider=stub_provider)
    master_key, public_key = authority_mod.setup_authority_keys(
        context, StubGroupOperations()
    )
    assert master_key.alpha != master_key.beta
    assert public_key.g1 == context.group.g1
    assert public_key.g2 == context.group.g2
    assert public_key.e_g1g2_alpha and public_key.g1_beta
    assert public_key.e_g1g2_alpha != public_key.g1_beta


def test_authority_step2_rejects_a_degenerate_exponent_source():
    """alpha == beta means MSK_i has half the entropy it should."""

    class ConstantExponents(StubGroupOperations):
        def random_exponent(self) -> bytes:
            return b"same-exponent-every-time"

    context = initializer.initialize(group_provider=stub_provider)
    try:
        authority_mod.setup_authority_keys(context, ConstantExponents())
    except authority_mod.AuthorityError as exc:
        assert "uniform" in str(exc)
        return
    raise AssertionError("a constant exponent source should be rejected")


def test_authority_step2_keys_are_independent_across_authorities():
    context = initializer.initialize(group_provider=stub_provider)
    first = make_authority("AA1", context=context)
    second = make_authority("AA2", context=context)
    assert first.master_key.alpha != second.master_key.alpha
    assert first.public_key.e_g1g2_alpha != second.public_key.e_g1g2_alpha


def test_authority_keys_from_a_stub_group_are_never_reportable():
    context = initializer.initialize(group_provider=stub_provider)
    make_authority(context=context)
    assert not context.reportable


# -- Phase II Step 1 --------------------------------------------------------
def test_authority_step1_registers_and_anchors():
    chain = fresh_ledger()
    authority = make_authority("AA1", "hospital")
    authority.register(chain)
    stored = chain.get_registration("AA1")
    assert stored == authority.registration()
    assert stored.domain == "hospital"
    assert chain.verify_chain()


def test_authority_step1_rejects_a_second_registration():
    chain = fresh_ledger()
    authority = make_authority("AA1")
    authority.register(chain)
    try:
        authority.register(chain)
    except ledger_mod.ImmutabilityError:
        return
    raise AssertionError("re-registration must be refused")


def test_authority_registration_carries_no_secret_material():
    authority = make_authority()
    encoded = authority.registration().encode()
    assert authority.master_key.alpha not in encoded
    assert authority.master_key.beta not in encoded


# -- Phase II Step 2: disjoint namespaces -----------------------------------
def test_namespace_digest_is_order_independent():
    """H(A_i) is over a set, so insertion order must not change it."""
    assert authority_mod.namespace_digest(["b", "a", "c"]) == (
        authority_mod.namespace_digest(["a", "b", "c"])
    )


def test_namespace_digest_is_membership_sensitive():
    assert authority_mod.namespace_digest(["a", "b"]) != (
        authority_mod.namespace_digest(["a", "b", "c"])
    )


def test_namespace_digest_rejects_empty_and_duplicates():
    for bad in ([], ["a", "a"]):
        try:
            authority_mod.namespace_digest(bad)
        except authority_mod.AuthorityError:
            continue
        raise AssertionError(f"{bad!r} should not produce a namespace digest")


def test_namespace_digest_is_domain_separated_from_the_commitment():
    """A namespace digest must not be presentable as a C_i^auth."""
    attributes = ["a", "b"]
    assert authority_mod.namespace_digest(attributes) != types.hashes.sha256(
        types.canonical(sorted(attributes))
    )


def test_namespace_registry_enforces_disjointness():
    """Phase II Step 2: every attribute belongs exclusively to one authority."""
    registry = authority_mod.AttributeNamespaceRegistry()
    registry.claim("AA1", ["shared:attr", "aa1:only"])
    try:
        registry.claim("AA2", ["shared:attr", "aa2:only"])
    except authority_mod.NamespaceConflictError as exc:
        assert "shared:attr" in str(exc)
        assert "AA1" in str(exc)
        return
    raise AssertionError("an overlapping namespace claim must be refused")


def test_namespace_registry_allows_an_authority_to_reclaim_its_own():
    registry = authority_mod.AttributeNamespaceRegistry()
    registry.claim("AA1", ["aa1:x"])
    registry.claim("AA1", ["aa1:x", "aa1:y"])  # idempotent for the same owner
    assert registry.owner_of("aa1:x") == "AA1"
    assert registry.attribute_count == 2


def test_namespace_registry_conflict_leaves_no_partial_claim():
    """A refused claim must not have registered its non-conflicting attributes."""
    registry = authority_mod.AttributeNamespaceRegistry()
    registry.claim("AA1", ["aa1:x"])
    try:
        registry.claim("AA2", ["aa2:new", "aa1:x"])
    except authority_mod.NamespaceConflictError:
        pass
    assert registry.owner_of("aa2:new") is None


def test_namespace_registry_release():
    registry = authority_mod.AttributeNamespaceRegistry()
    registry.claim("AA1", ["aa1:x"])
    registry.release("AA1")
    assert registry.owner_of("aa1:x") is None
    registry.claim("AA2", ["aa1:x"])  # now free


def test_authority_create_claims_its_namespace_in_the_registry():
    registry = authority_mod.AttributeNamespaceRegistry()
    context = initializer.initialize(group_provider=stub_provider)
    make_authority("AA1", registry=registry, context=context)
    make_authority("AA2", registry=registry, context=context)
    per_authority = context.config.authorities.attributes_per_authority
    assert registry.attribute_count == 2 * per_authority


def test_authority_create_refuses_an_overlapping_namespace():
    registry = authority_mod.AttributeNamespaceRegistry()
    context = initializer.initialize(group_provider=stub_provider)
    shared = authority_mod.default_attributes(
        "SHARED", context.config.authorities.attributes_per_authority
    )
    make_authority("AA1", registry=registry, attributes=shared, context=context)
    try:
        make_authority("AA2", registry=registry, attributes=shared, context=context)
    except authority_mod.NamespaceConflictError:
        return
    raise AssertionError("two authorities must not share attributes")


def test_authority_create_enforces_the_configured_namespace_size():
    """Unequal namespaces would give one authority more of the policy space."""
    context = initializer.initialize(group_provider=stub_provider)
    try:
        make_authority("AA1", attributes=("only:one",), context=context)
    except authority_mod.AuthorityError as exc:
        assert "attributes_per_authority" in str(exc)
        return
    raise AssertionError("a namespace of the wrong size should be refused")


def test_default_attributes_are_disjoint_by_construction():
    first = set(authority_mod.default_attributes("AA1", 10))
    second = set(authority_mod.default_attributes("AA2", 10))
    assert len(first) == len(second) == 10
    assert not first & second


# -- Phase II Step 3: C_i^auth sensitivity ----------------------------------
def test_commitment_binds_all_five_inputs():
    """C_i^auth = H(ID || Dom || H(A_i) || VID || RevRoot).

    Five separate assertions: changing ANY input must change the commitment.
    This is the property the commitment exists to provide — a commitment that
    survived a VID change would let a stale authorization state pass as current.
    """
    base_kwargs = dict(
        authority_id="AA1",
        domain="hospital",
        namespace_digest_value=authority_mod.namespace_digest(["a", "b"]),
        vid=0,
        revocation_root=revocation_mod.EMPTY_REVOCATION_ROOT,
    )
    base = authority_mod.authorization_state_commitment(**base_kwargs)

    variants = {
        "authority_id": dict(base_kwargs, authority_id="AA2"),
        "domain": dict(base_kwargs, domain="laboratory"),
        "namespace": dict(
            base_kwargs,
            namespace_digest_value=authority_mod.namespace_digest(["a", "b", "c"]),
        ),
        "vid": dict(base_kwargs, vid=1),
        "revocation_root": dict(
            base_kwargs, revocation_root=revocation_mod.revocation_root(["u1"])
        ),
    }
    for name, kwargs in variants.items():
        assert (
            authority_mod.authorization_state_commitment(**kwargs) != base
        ), f"C_i^auth did not change when {name} changed"


def test_commitment_is_deterministic_and_recomputable():
    """A verifier must reproduce C_i^auth from the published State_i inputs."""
    authority = make_authority()
    assert authority.commitment() == authority.commitment()
    assert authority.commitment() == authority_mod.authorization_state_commitment(
        authority_id=authority.authority_id,
        domain=authority.domain,
        namespace_digest_value=authority.namespace_digest(),
        vid=authority.vid,
        revocation_root=authority.revocation_root(),
    )


def test_commitment_cannot_be_reframed_across_fields():
    """Length-prefixed fields: no two distinct states may share a commitment.

    Without prefixing, ID="AA" + Dom="1x" and ID="AA1" + Dom="x" would concatenate
    identically.
    """
    shared = dict(
        namespace_digest_value=authority_mod.namespace_digest(["a"]),
        vid=0,
        revocation_root=revocation_mod.EMPTY_REVOCATION_ROOT,
    )
    first = authority_mod.authorization_state_commitment(
        authority_id="AA", domain="1x", **shared
    )
    second = authority_mod.authorization_state_commitment(
        authority_id="AA1", domain="x", **shared
    )
    assert first != second


def test_commitment_tracks_a_revocation():
    """Phase VII Step 2 updates RevRoot; the commitment must follow."""
    authority = make_authority()
    before = authority.commitment()
    authority.revocation.revoke("patient-1")
    assert authority.commitment() != before


def test_commitment_tracks_a_version_increment():
    authority = make_authority()
    before = authority.commitment()
    authority.vid += 1
    assert authority.commitment() != before


def test_commitment_is_not_cached_across_state_changes():
    """A cached commitment would survive the drift it exists to prevent."""
    authority = make_authority()
    first = authority.commitment()
    authority.revocation.revoke("p1")
    second = authority.commitment()
    authority.revocation.restore("p1")
    assert authority.commitment() == first != second


def test_commitment_rejects_a_negative_vid():
    try:
        authority_mod.authorization_state_commitment(
            authority_id="AA1",
            domain="hospital",
            namespace_digest_value=bytes(32),
            vid=-1,
            revocation_root=bytes(32),
        )
    except ValueError:
        return
    raise AssertionError("a negative VID should be refused")


def test_authority_state_and_meta_agree_on_the_commitment():
    """State_i and Meta_i are two views of one authorization state."""
    authority = make_authority()
    state, meta = authority.state(), authority.meta()
    assert state.commitment == meta.commitment == authority.commitment()
    assert state.vid == meta.vid == authority.vid
    assert meta.domain == authority.domain


def test_authority_meta_omits_the_public_key():
    """The AIM forwards Dom/VID/C_auth to FSNs, not PK_i."""
    authority = make_authority()
    assert authority.public_key.e_g1g2_alpha not in authority.meta().encode()
    assert authority.public_key.e_g1g2_alpha in authority.state().encode()


def test_authority_repr_hides_key_material():
    authority = make_authority()
    text = repr(authority)
    assert authority.master_key.alpha.hex() not in text
    assert "redacted" in repr(authority.master_key)


def test_authority_rejects_an_empty_namespace_directly():
    context = initializer.initialize(group_provider=stub_provider)
    master_key, public_key = authority_mod.setup_authority_keys(
        context, StubGroupOperations()
    )
    try:
        authority_mod.Authority(
            authority_id="AA1",
            domain="hospital",
            attributes=(),
            public_key=public_key,
            master_key=master_key,
        )
    except authority_mod.AuthorityError:
        return
    raise AssertionError("an authority with no attributes should be refused")


def test_authority_initial_vid_comes_from_config():
    context = initializer.initialize(group_provider=stub_provider)
    authority = make_authority(context=context)
    assert authority.vid == context.config.authorities.initial_vid == 0


# -- Phase I-II end to end --------------------------------------------------
def test_four_authorities_end_to_end_through_phase_ii_step_3():
    """N_AA=4, one per domain: keygen, registration, namespaces, commitments.

    Stops at Step 3 — publishing State_i is Step 4, which the AIM drives.
    """
    context = initializer.initialize(group_provider=stub_provider)
    chain = fresh_ledger()
    registry = authority_mod.AttributeNamespaceRegistry()
    domains = ("hospital", "laboratory", "insurance", "emergency")

    authorities = [
        make_authority(f"AA{i}", domain, registry=registry, context=context)
        for i, domain in enumerate(domains, start=1)
    ]
    for authority in authorities:
        authority.register(chain)

    assert len(authorities) == context.config.authorities.count == 4
    assert chain.registered_authorities() == ["AA1", "AA2", "AA3", "AA4"]
    # Disjoint namespaces across the whole federation.
    assert registry.attribute_count == 4 * (
        context.config.authorities.attributes_per_authority
    )
    # Distinct commitments, all recomputable, all over empty revocation lists.
    commitments = {a.authority_id: a.commitment() for a in authorities}
    assert len(set(commitments.values())) == 4
    for authority in authorities:
        assert authority.revocation_root() == revocation_mod.EMPTY_REVOCATION_ROOT
        assert authority.state().commitment == commitments[authority.authority_id]

    # PP carries all four PK_i (Phase I Step 3).
    pp = initializer.publish_public_parameters(
        chain, context, [(a.authority_id, a.public_key) for a in authorities]
    )
    assert pp.authority_count == 4
    assert chain.verify_chain()

    # Only the affected authority's commitment moves when one revokes
    # (Phase VII Step 2: "all other authorities retain their existing states").
    authorities[1].revocation.revoke("patient-7")
    assert authorities[1].commitment() != commitments["AA2"]
    for authority in (authorities[0], authorities[2], authorities[3]):
        assert authority.commitment() == commitments[authority.authority_id]


# ===========================================================================
# fsn/fsn.py — Phase I Step 4
# ===========================================================================
DOMAINS = ("emergency", "hospital", "insurance", "laboratory")


def test_fsn_set_is_built_with_one_domain_per_node_at_the_defaults():
    """§VI: d=4 domains over m=4 nodes. One domain each makes selectivity visible."""
    config = config_mod.load()
    nodes = fsn_mod.build_fsn_set(DOMAINS, config.topology.fog_search_nodes)
    assert len(nodes) == 4
    assert [node.node_id for node in nodes] == ["FSN1", "FSN2", "FSN3", "FSN4"]
    assert all(len(node.domains) == 1 for node in nodes)
    # Every domain is served exactly once.
    served = [d for node in nodes for d in node.domains]
    assert sorted(served) == sorted(DOMAINS)


def test_fsn_fresh_node_state_is_empty():
    """Phase I Step 4: nodes start with no entries, no queue, no auth state."""
    node = fsn_mod.FogSearchNode.create("FSN1", ["hospital"])
    assert node.entry_count == 0
    assert node.queue_length == 0
    assert node.vid() == 0
    assert node.synced_authorities() == ()
    assert node.queue_wait_ns() == 0


def make_index_entry(token: bytes, policy_id: str = "p0", vid: int = 0):
    """A minimal IndexEntry for FSN-level tests (Phase IV owns the real ones)."""
    return types.IndexEntry(token=token, cid="cid-0", policy_id=policy_id, vid=vid)


def test_fsn_nodes_share_no_mutable_state():
    """Nodes become independent processes; shared state would break that quietly."""
    first, second = fsn_mod.build_fsn_set(("hospital", "laboratory"), 2)
    first.insert_entries([make_index_entry(b"t1")], domain="hospital")
    first.enqueue("q1")
    first.apply_meta("AA1", types.AuthorizationMeta("hospital", 3, bytes(32)))
    assert second.entry_count == 0
    assert second.queue_length == 0
    assert second.synced_authorities() == ()


def test_fsn_owns_its_shard_so_n_j_has_one_source():
    """N_j reads through to the index — no second counter to drift.

    An earlier revision tracked the count on the node AND in the index; a
    scheduler costing queries against a stale N_j would produce plausible, wrong
    Exp. 2 numbers.
    """
    node = fsn_mod.FogSearchNode.create("FSN1", ["hospital"])
    node.insert_entries(
        [make_index_entry(b"t%d" % i) for i in range(5)], domain="hospital"
    )
    assert node.entry_count == node.index.entry_count == 5
    node.index.delete(0)
    assert node.entry_count == node.index.entry_count == 4


def test_fsn_refuses_entries_for_a_domain_it_does_not_serve():
    node = fsn_mod.FogSearchNode.create("FSN1", ["hospital"])
    try:
        node.insert_entries([make_index_entry(b"t1")], domain="laboratory")
    except fsn_mod.FSNError:
        return
    raise AssertionError("a foreign-domain insert should be refused")


def test_fsn_queue_is_fifo_and_measures_wait_time():
    """T_j^queue is a measured time, not a queue-length proxy."""
    node = fsn_mod.FogSearchNode.create("FSN1", ["hospital"])
    node.enqueue("q1", now_ns=1_000)
    node.enqueue("q2", now_ns=2_000)
    assert node.queue_length == 2
    # Wait is measured from the OLDEST request.
    assert node.queue_wait_ns(now_ns=5_000) == 4_000
    assert node.dequeue().request_id == "q1"
    assert node.queue_wait_ns(now_ns=5_000) == 3_000
    assert node.dequeue().request_id == "q2"
    assert node.queue_wait_ns(now_ns=5_000) == 0


def test_fsn_dequeue_on_empty_raises():
    try:
        fsn_mod.FogSearchNode.create("FSN1", ["hospital"]).dequeue()
    except fsn_mod.FSNError:
        return
    raise AssertionError("dequeue on an empty queue should raise")


def test_fsn_utilization_is_a_busy_fraction():
    node = fsn_mod.FogSearchNode.create("FSN1", ["hospital"])
    node.record_service(30_000_000)          # 30 ms busy
    assert abs(node.utilization(100_000_000) - 0.3) < 1e-9   # in a 100 ms window
    assert node.served_count == 1
    # Cannot exceed 1.0 even if service time overruns the window.
    node.record_service(200_000_000)
    assert node.utilization(100_000_000) == 1.0


def test_fsn_applies_and_reports_authorization_state():
    node = fsn_mod.FogSearchNode.create("FSN1", ["hospital"])
    meta = types.AuthorizationMeta("hospital", 2, bytes(range(32)))
    assert node.apply_meta("AA1", meta) is True
    assert node.vid_for_authority("AA1") == 2
    assert node.commitment_for_authority("AA1") == bytes(range(32))
    # Re-applying identical state is not a change.
    assert node.apply_meta("AA1", meta) is False


def test_fsn_refuses_a_stale_authorization_version():
    """Versions only advance; an older Meta is a replay or a reorder."""
    node = fsn_mod.FogSearchNode.create("FSN1", ["hospital"])
    node.apply_meta("AA1", types.AuthorizationMeta("hospital", 5, bytes(32)))
    try:
        node.apply_meta("AA1", types.AuthorizationMeta("hospital", 4, bytes(32)))
    except fsn_mod.FSNError as exc:
        assert "only advance" in str(exc)
        return
    raise AssertionError("a stale version must be refused")


def test_fsn_vid_is_the_minimum_across_synced_authorities():
    """A node is only as fresh as its stalest authority (see fsn.vid docstring)."""
    node = fsn_mod.FogSearchNode.create("FSN1", ["hospital", "laboratory"])
    node.apply_meta("AA1", types.AuthorizationMeta("hospital", 7, bytes(32)))
    node.apply_meta("AA2", types.AuthorizationMeta("laboratory", 2, bytes(32)))
    assert node.vid() == 2
    assert node.vid_for_domains(["hospital"]) == 7
    assert node.vid_for_domains(["hospital", "laboratory"]) == 2


def test_fsn_unsynchronized_domain_is_not_version_zero():
    """An unsynchronized node must not read as merely being at version 0."""
    node = fsn_mod.FogSearchNode.create("FSN1", ["hospital", "laboratory"])
    node.apply_meta("AA1", types.AuthorizationMeta("hospital", 1, bytes(32)))
    try:
        node.vid_for_domains(["laboratory"])
    except fsn_mod.FSNError as exc:
        assert "no authorization state" in str(exc)
        return
    raise AssertionError("an unsynchronized domain should raise, not return 0")


def test_fsn_domain_assignment_packs_when_domains_exceed_nodes():
    """Exp. 3 sweeps d to 10 against m=4."""
    assignment = fsn_mod.assign_domains_to_fsns([f"dom{i}" for i in range(10)], 4)
    assert len(assignment) == 4
    assert sum(len(bucket) for bucket in assignment) == 10
    assert all(bucket for bucket in assignment)          # no idle node
    sizes = sorted(len(bucket) for bucket in assignment)
    assert sizes[-1] - sizes[0] <= 1                     # balanced within one


def test_fsn_assignment_rejects_more_nodes_than_domains():
    """An unassigned node would never be selected and would skew Exp. 8."""
    try:
        fsn_mod.assign_domains_to_fsns(["only-one"], 4)
    except fsn_mod.FSNError as exc:
        assert "never be selected" in str(exc)
        return
    raise AssertionError("idle nodes should be refused")


def test_fsn_assignment_rejects_duplicate_domains():
    try:
        fsn_mod.assign_domains_to_fsns(["a", "a", "b"], 2)
    except ValueError:
        return
    raise AssertionError("duplicate domains should be refused")


def test_fsn_requires_at_least_one_domain():
    try:
        fsn_mod.FogSearchNode.create("FSN1", [])
    except fsn_mod.FSNError:
        return
    raise AssertionError("a node serving no domain should be refused")


# ===========================================================================
# aim/aim.py — Phase II Step 4
# ===========================================================================
def phase_i_ii_federation():
    """Run Phase I and Phase II Steps 1-4 and return every participant.

    The shared fixture for the end-to-end and selective-synchronization tests.
    """
    context = initializer.initialize(group_provider=stub_provider)
    chain = fresh_ledger()
    registry = authority_mod.AttributeNamespaceRegistry()
    aim = aim_mod.AuthorizationIndexManager()

    authorities = [
        make_authority(f"AA{i}", domain, registry=registry, context=context)
        for i, domain in enumerate(DOMAINS, start=1)
    ]
    for authority in authorities:
        authority.register(chain)                       # Phase II Step 1
        chain.publish_authorization_state(authority.state())   # Phase II Step 4

    nodes = fsn_mod.build_fsn_set(DOMAINS, context.config.topology.fog_search_nodes)
    results = aim_mod.initial_synchronization(
        aim, chain, [a.authority_id for a in authorities], nodes
    )
    initializer.publish_public_parameters(
        chain, context, [(a.authority_id, a.public_key) for a in authorities]
    )
    return context, chain, aim, authorities, nodes, results


def test_aim_synchronizes_meta_from_the_ledger():
    """Meta_i is derived from the anchored Reg_i and State_i, not a side channel."""
    _, chain, aim, authorities, _, _ = phase_i_ii_federation()
    for authority in authorities:
        meta = aim.meta_for_authority(authority.authority_id)
        assert meta.domain == authority.domain
        assert meta.vid == authority.vid
        assert meta.commitment == authority.commitment()


def test_aim_requires_registration_before_synchronization():
    chain = fresh_ledger()
    aim = aim_mod.AuthorizationIndexManager()
    try:
        aim.synchronize_from_ledger(chain, "AA-absent")
    except aim_mod.AIMError as exc:
        assert "not registered" in str(exc)
        return
    raise AssertionError("an unregistered authority must not be synchronized")


def test_aim_requires_a_published_state_before_synchronization():
    """Phase II Step 3 must precede Step 4."""
    chain = fresh_ledger()
    aim = aim_mod.AuthorizationIndexManager()
    make_authority("AA1").register(chain)      # registered, but no State_i
    try:
        aim.synchronize_from_ledger(chain, "AA1")
    except aim_mod.AIMError as exc:
        assert "no authorization state" in str(exc)
        return
    raise AssertionError("an authority with no state must not be synchronized")


def test_aim_agrees_with_the_ledger():
    _, chain, aim, _, _, _ = phase_i_ii_federation()
    aim.verify_against_ledger(chain)            # must not raise


def test_aim_detects_drift_from_the_ledger():
    """The AIM is off-chain, so the check that it has not drifted must bite."""
    _, chain, aim, authorities, _, _ = phase_i_ii_federation()
    target = authorities[0].authority_id
    held = aim.meta_for_authority(target)
    # Forge a different commitment at the same version.
    aim._meta[target] = types.AuthorizationMeta(
        domain=held.domain, vid=held.vid, commitment=bytes(range(32))
    )
    try:
        aim.verify_against_ledger(chain)
    except aim_mod.AuthorizationStateMismatchError as exc:
        assert target in str(exc)
        return
    raise AssertionError("AIM/ledger divergence must be detected")


def test_aim_refuses_a_stale_meta():
    aim = aim_mod.AuthorizationIndexManager()
    aim.register_meta("AA1", types.AuthorizationMeta("hospital", 5, bytes(32)))
    try:
        aim.register_meta("AA1", types.AuthorizationMeta("hospital", 3, bytes(32)))
    except aim_mod.AIMError:
        return
    raise AssertionError("a stale Meta must be refused")


def test_aim_commitment_set_is_ordered_and_complete():
    """C_U feeds AuthRoot_U, so its order must not depend on enumeration order."""
    _, _, aim, authorities, _, _ = phase_i_ii_federation()
    ids = [a.authority_id for a in authorities]
    forward = aim.commitments(ids)
    reverse = aim.commitments(list(reversed(ids)))
    assert forward == reverse
    assert len(forward) == 4
    assert set(forward) == {a.commitment() for a in authorities}


def test_aim_commitments_reject_an_unknown_authority():
    _, _, aim, _, _, _ = phase_i_ii_federation()
    try:
        aim.commitments(["AA-absent"])
    except aim_mod.AIMError:
        return
    raise AssertionError("an unknown authority should raise")


def test_aim_maps_domains_to_authorities():
    """Phase VI Step 2 resolves authorized shards through this mapping."""
    _, _, aim, authorities, _, _ = phase_i_ii_federation()
    assert set(aim.domains()) == set(DOMAINS)
    for authority in authorities:
        assert aim.authorities_for_domain(authority.domain) == (
            authority.authority_id,
        )


def test_aim_version_table_covers_every_authority():
    """The AIM side of C_j^sync = |VID_U - VID_j|."""
    _, _, aim, authorities, _, _ = phase_i_ii_federation()
    table = aim.version_table()
    assert set(table) == {a.authority_id for a in authorities}
    assert all(vid == 0 for vid in table.values())


def test_aim_initial_synchronization_reaches_every_node():
    """Phase II Step 4 is the INITIAL sync: all nodes, legitimately."""
    _, _, _, authorities, nodes, results = phase_i_ii_federation()
    assert len(results) == len(authorities)
    for result in results:
        assert result.touched_count == len(nodes)
        assert result.updated_count == len(nodes)
    for node in nodes:
        assert len(node.synced_authorities()) == 4


def test_aim_affected_fsns_is_the_domain_holder_only():
    """Phase VII Step 4 selectivity: one domain per node means one node in four."""
    _, _, aim, authorities, nodes, _ = phase_i_ii_federation()
    for authority in authorities:
        affected = aim.affected_fsns(authority.authority_id, nodes)
        assert len(affected) == 1
        assert affected[0].serves_domain(authority.domain)


def test_aim_selective_propagation_touches_one_node_in_four():
    """The Exp. 6 claim: FSNs touched must be the affected subset, not all m."""
    _, chain, aim, authorities, nodes, _ = phase_i_ii_federation()
    target = authorities[1]

    # Phase VII Step 2: the authority revokes, increments, and republishes.
    target.revocation.revoke("patient-7")
    target.vid += 1
    chain.publish_authorization_state(target.state())
    aim.synchronize_from_ledger(chain, target.authority_id)

    result = aim.propagate_selectively(target.authority_id, nodes)
    assert result.touched_count == 1
    assert result.updated_count == 1
    assert result.vid == 1

    # Only the affected node advanced; the rest keep the old version.
    for node in nodes:
        if node.serves_domain(target.domain):
            assert node.vid_for_authority(target.authority_id) == 1
        else:
            assert node.vid_for_authority(target.authority_id) == 0


def test_aim_selective_propagation_leaves_other_nodes_stale():
    """Staleness is a normal condition the AASS scheduler routes around."""
    _, chain, aim, authorities, nodes, _ = phase_i_ii_federation()
    target = authorities[2]
    target.vid += 1
    chain.publish_authorization_state(target.state())
    aim.synchronize_from_ledger(chain, target.authority_id)
    aim.propagate_selectively(target.authority_id, nodes)

    stale = aim.verify_fsn_synchronization(nodes, authority_id=target.authority_id)
    # Only nodes SERVING that domain are considered for it, and that one is fresh.
    assert stale == ()

    # Before propagation, the domain holder would have been stale.
    other = authorities[3]
    other.vid += 1
    chain.publish_authorization_state(other.state())
    aim.synchronize_from_ledger(chain, other.authority_id)
    assert aim.verify_fsn_synchronization(
        nodes, authority_id=other.authority_id
    ) != ()


def test_aim_propagation_records_touched_and_updated_separately():
    """Touched is the cost; updated is the effect. Re-propagating changes nothing."""
    _, _, aim, authorities, nodes, _ = phase_i_ii_federation()
    again = aim.propagate(authorities[0].authority_id, nodes)
    assert again.touched_count == len(nodes)
    assert again.updated_count == 0          # already at that version


def test_aim_has_no_broadcast_method():
    """Phase VII's selectivity is the measured claim; a broadcast would void it."""
    forbidden = {"broadcast", "propagate_all", "sync_all"}
    assert not forbidden & set(dir(aim_mod.AuthorizationIndexManager))


# ===========================================================================
# Phase I + Phase II end to end
# ===========================================================================
def test_phase_i_ii_end_to_end():
    """Every step of Phases I and II, with the properties each one must hold."""
    context, chain, aim, authorities, nodes, results = phase_i_ii_federation()
    config = context.config

    # Phase I Step 1 — P and the group.
    assert context.primitive_set()[1:] == (
        "sha256",
        "aes-256-gcm",
        "hkdf-sha256",
        "ml-kem-768",
    )
    assert context.suite.pairing_type == "type-3"

    # Phase I Step 2 — N_AA authorities, independent keys.
    assert len(authorities) == config.authorities.count == 4
    assert len({a.public_key.e_g1g2_alpha for a in authorities}) == 4

    # Phase I Step 3 — PP anchored with every PK_i.
    pp_keys = chain.keys(ledger_mod.NS_SYSTEM_PARAMETERS)
    assert len(pp_keys) == 1
    published_pp = chain.get(ledger_mod.NS_SYSTEM_PARAMETERS, pp_keys[0]).record
    assert published_pp.authority_count == 4

    # Phase I Step 4 — F = {FSN_1..FSN_m}, all namespaces initialised.
    assert len(nodes) == config.topology.fog_search_nodes == 4
    assert set(chain.namespace_sizes()) == set(ledger_mod.NAMESPACES)

    # Phase II Step 1 — every Reg_i anchored, on a real corpus domain set.
    assert chain.registered_authorities() == ["AA1", "AA2", "AA3", "AA4"]
    assert {chain.get_registration(a).domain for a in chain.registered_authorities()} == set(DOMAINS)

    # Phase II Step 2 — disjoint namespaces of the configured size.
    all_attributes = [attr for a in authorities for attr in a.attributes]
    assert len(all_attributes) == 4 * config.authorities.attributes_per_authority
    assert len(set(all_attributes)) == len(all_attributes)

    # Phase II Step 3 — distinct, recomputable commitments over empty rev lists.
    assert len({a.commitment() for a in authorities}) == 4
    for authority in authorities:
        assert authority.revocation_root() == revocation_mod.EMPTY_REVOCATION_ROOT
        assert chain.latest_authorization_state(
            authority.authority_id
        ).commitment == authority.commitment()

    # Phase II Step 4 — AIM agrees with the chain; every node synchronized.
    aim.verify_against_ledger(chain)
    assert aim.verify_fsn_synchronization(nodes) == ()
    assert all(node.vid() == 0 for node in nodes)
    assert sum(r.touched_count for r in results) == 4 * len(nodes)

    # The chain is intact end to end: 4 Reg_i + 4 State_i + 1 PP.
    assert chain.entry_count() == 9
    assert chain.verify_chain()

    # No secret material anywhere on the chain.
    for entry in chain.entries():
        for authority in authorities:
            assert authority.master_key.alpha not in entry.payload
            assert authority.master_key.beta not in entry.payload


def test_phase_i_ii_is_reproducible_up_to_key_material():
    """Two runs must agree on every commitment, since those are derived state."""
    first = phase_i_ii_federation()
    second = phase_i_ii_federation()
    assert [a.commitment() for a in first[3]] == [a.commitment() for a in second[3]]


def test_phase_i_ii_end_state_is_not_reportable():
    """The whole federation runs on an unfaithful group, so nothing may be reported."""
    context, _, _, _, _, _ = phase_i_ii_federation()
    assert not context.reportable
    try:
        context.assert_reportable()
    except initializer.UnfaithfulGroupError:
        return
    raise AssertionError("a stub-group federation must not be reportable")


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


# ===========================================================================
# Shard replication — what gives the scheduler a choice to make
# ===========================================================================
def test_replication_puts_every_shard_on_that_many_nodes():
    """`replication=r` must mean r eligible holders per domain, not r-ish.

    This is the invariant Exp. 7-8 rest on. At replication 1 the eligible set
    for a shard is a singleton, Algorithm 1's `S notin S_j` guard pins AASS to
    the sole holder, and the ablation compares arms that cannot differ on
    merit -- `least_loaded` scored 7x better on Exp. 8's utilization spread
    purely by scattering work onto nodes that could not serve the shard.
    """
    domains = [f"dom{i}" for i in range(4)]
    for replication in (1, 2, 3, 4):
        assignment = fsn_mod.assign_domains_to_fsns(
            domains, 4, replication=replication
        )
        holders = {
            domain: sum(1 for bucket in assignment if domain in bucket)
            for domain in domains
        }
        assert set(holders.values()) == {replication}, (
            f"replication={replication} gave holder counts {holders}"
        )


def test_replication_keeps_the_placement_itself_balanced():
    """Every node must hold the same number of shards.

    If the placement were lopsided, Exp. 8 would credit the scheduler with
    removing an imbalance the topology created.
    """
    assignment = fsn_mod.assign_domains_to_fsns(
        [f"dom{i}" for i in range(4)], 4, replication=2
    )
    sizes = {len(bucket) for bucket in assignment}
    assert sizes == {2}, f"uneven shard counts per node: {sizes}"


def test_replication_never_places_a_domain_on_one_node_twice():
    """A repeated domain would double-count that node's `policy_pairs`."""
    assignment = fsn_mod.assign_domains_to_fsns(
        ["a", "b"], 2, replication=2
    )
    for bucket in assignment:
        assert len(bucket) == len(set(bucket)), bucket


def test_replication_cannot_exceed_the_node_count():
    try:
        fsn_mod.assign_domains_to_fsns(["a", "b", "c", "d"], 2, replication=3)
    except fsn_mod.FSNError as exc:
        assert "more holders than there are nodes" in str(exc)
        return
    raise AssertionError("replication above fsn_count should be refused")
