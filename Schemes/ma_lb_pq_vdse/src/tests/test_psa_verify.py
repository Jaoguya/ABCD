"""Phase VIII under the PSA commitment — the acceptance test, and what it rejects.

``verify/proof.py``'s suite covers Option D's ``H(Root ‖ PID ‖ VID ‖
AuthRoot_DO)``. This covers ``psa/verify.py``'s ``H(CID ‖ Root ‖ PID ‖ PV ‖
AuthState)`` (D3), where three things differ: ``CID_i`` is inside the
commitment, the DO's root is replaced by the governing authorities' state, and
freshness is a digest equality rather than a counter ordering.

Each rejection test names the step it must fail at. A bundle that fails for the
wrong reason is a verifier that would accept a different forgery.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

import pytest  # noqa: E402

from Common.crypto import merkle  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.psa import commit as psa_commit  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.psa import records as psa_records  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.psa import state as psa_state  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.psa import tokens as psa_tokens  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.psa import verify as psa_verify  # noqa: E402

KEYWORDS = 6


def _pv(a1: int = 1, a2: int = 1) -> bytes:
    return psa_state.PolicyVersionState(versions=(("AA1", a1), ("AA2", a2))).digest()


def _auth_state(byte: int = 1) -> bytes:
    return psa_state.PolicyAuthorityState(
        commitments=(("AA1", bytes([byte]) * 32), ("AA2", b"\x02" * 32))
    ).digest()


@pytest.fixture
def record():
    scheme = psa_tokens.PolicyStateTokenScheme.keyed(b"k" * 32)
    pv = _pv()
    entries = [
        psa_records.PolicyStateIndexEntry(
            token=scheme.index_token(
                f"w{i}", policy_id="hospital/pol0", pv=pv, domain="hospital"
            ),
            cid="bafyTEST0001", policy_id="hospital/pol0", pv=pv,
        )
        for i in range(KEYWORDS)
    ]
    commitment = psa_commit.commit_record(
        record_id=0, cid="bafyTEST0001", entries=entries,
        policy_id="hospital/pol0", pv=pv, auth_state=_auth_state(),
    )
    return commitment, entries, pv


# ===========================================================================
# The happy path
# ===========================================================================
def test_every_entry_of_a_record_verifies(record):
    commitment, entries, pv = record
    bundles = psa_verify.build_response(commitment, entries)
    assert len(bundles) == KEYWORDS
    for bundle in bundles:
        result = psa_verify.verify_bundle(bundle, pv_expected=pv)
        assert result.accepted, result.failed_step
        assert [s.step for s in result.steps] == ["merkle", "authorization"]


def test_chain_check_runs_as_a_third_step(record):
    commitment, entries, pv = record
    bundle = psa_verify.build_response(commitment, entries)[0]
    result = psa_verify.verify_bundle(
        bundle, pv_expected=pv,
        chain_check=lambda _: psa_verify.StepResult("chain", True),
    )
    assert result.accepted
    assert [s.step for s in result.steps] == ["merkle", "authorization", "chain"]


def test_ameta_is_self_checking(record):
    """Step 2 re-derives Commit_i from the other five fields."""
    commitment, _, _ = record
    assert commitment.meta.verify()


# ===========================================================================
# What it must reject, and where
# ===========================================================================
def test_a_tampered_entry_fails_at_merkle(record):
    commitment, entries, pv = record
    forged = psa_records.PolicyStateIndexEntry(
        token=b"\x99" * 32, cid=entries[0].cid,
        policy_id=entries[0].policy_id, pv=entries[0].pv,
    )
    bundle = psa_verify.PsaVerificationBundle(
        meta=commitment.meta, proof=commitment.prove(0), entry=forged
    )
    result = psa_verify.verify_bundle(bundle, pv_expected=pv)
    assert result.failed_step == "merkle"
    # Short-circuit: Step 2 must not have run, or Exp. 4's per-record cost
    # would include work a real client skips.
    assert len(result.steps) == 1


def test_a_forged_auth_state_fails_at_authorization(record):
    """AuthState_i is inside Commit_i, so it cannot be swapped."""
    commitment, entries, pv = record
    meta = commitment.meta
    forged = psa_commit.AuthenticatedMetadata(
        cid=meta.cid, policy_id=meta.policy_id, pv=meta.pv, root=meta.root,
        auth_state=_auth_state(byte=7), commit=meta.commit,
    )
    bundle = psa_verify.PsaVerificationBundle(
        meta=forged, proof=commitment.prove(0), entry=entries[0]
    )
    assert psa_verify.verify_bundle(bundle).failed_step == "authorization"


def test_a_stale_policy_state_fails_at_authorization(record):
    """PV_i != PV_U — the freshness check, as a digest equality (D2)."""
    commitment, entries, _ = record
    bundle = psa_verify.build_response(commitment, entries)[0]
    assert psa_verify.verify_bundle(
        bundle, pv_expected=_pv(a1=2)
    ).failed_step == "authorization"


def test_a_substituted_cid_is_refused_at_construction(record):
    """D3's point: CID_i is INSIDE the commitment.

    Under Option D the ciphertext reference is not covered, so binding a
    returned entry to the right object rests on the entry's own CID being under
    Root_i. Here the bundle cannot even be assembled inconsistently.
    """
    commitment, entries, _ = record
    elsewhere = psa_records.PolicyStateIndexEntry(
        token=entries[0].token, cid="bafyOTHER999",
        policy_id=entries[0].policy_id, pv=entries[0].pv,
    )
    with pytest.raises(psa_verify.VerificationError, match="Commit_i binds one"):
        psa_verify.PsaVerificationBundle(
            meta=commitment.meta, proof=commitment.prove(0), entry=elsewhere
        )


def test_steps_1_and_2_alone_do_not_pin_WHICH_auth_state_was_anchored(record):
    """A real limit of the bundle, pinned so it is not mistaken for a guarantee.

    Build a second, internally consistent ``AMeta_i`` over the SAME entries but
    a different ``AuthState_i``. Its root matches, so Step 1 passes; its commit
    is self-consistent, so Step 2 passes. The bundle is accepted.

    That is correct behaviour, not a hole: Steps 1-2 prove "this entry belongs
    to a record committed under SOME (CID, PID, PV, AuthState)". Proving it was
    the state the ledger anchored is Step 3's job, which is why §5 puts chain
    consistency inside Exp. 4's measurement boundary and why `verify_bundle`
    takes `chain_check`. Reporting an Exp. 4 number with Step 3 omitted would
    price a verification that does not establish freshness.
    """
    commitment, entries, pv = record
    other = psa_commit.commit_record(
        record_id=1, cid=entries[0].cid, entries=entries,
        policy_id=entries[0].policy_id, pv=pv, auth_state=_auth_state(byte=5),
    )
    assert other.root == commitment.root
    assert other.commit != commitment.commit
    bundle = psa_verify.PsaVerificationBundle(
        meta=other.meta, proof=commitment.prove(0), entry=entries[0]
    )
    assert psa_verify.verify_bundle(bundle, pv_expected=pv).accepted

    # With Step 3 supplied, the substitution is caught -- the anchored commit
    # is the one the ledger holds, and this is not it.
    def chain_check(b):
        return psa_verify.StepResult(
            "chain", b.meta.commit == commitment.commit, "not the anchored commit"
        )

    result = psa_verify.verify_bundle(
        bundle, pv_expected=pv, chain_check=chain_check
    )
    assert not result.accepted and result.failed_step == "chain"


def test_verification_without_a_profile_checks_consistency_only(record):
    """No pv_expected = an auditor's check. Must not be read as freshness."""
    commitment, entries, _ = record
    bundle = psa_verify.build_response(commitment, entries)[0]
    assert psa_verify.verify_bundle(bundle).accepted


# ===========================================================================
# Exp. 4's unit — the defect that has already cost two re-runs
# ===========================================================================
def test_build_response_emits_one_bundle_per_ENTRY(record):
    """So a caller counting RECORDS must not take them all.

    ``d1cdf9c`` and the 2026-09-05 Exp. 9 fix were both this: r counted index
    entries where the baselines counted records, inflating the sweep by |W_i|.
    """
    commitment, entries, _ = record
    assert len(psa_verify.build_response(commitment, entries)) == len(entries)
    assert len(entries) == KEYWORDS != 1


def test_proof_path_length_is_measured_not_log2(record):
    """Odd-node promotion makes log2(N) wrong; Exp. 4 reports the real length."""
    commitment, entries, _ = record
    bundle = psa_verify.build_response(commitment, entries)[0]
    assert bundle.proof_path_length == len(bundle.proof.path)
    assert bundle.proof_size_bytes > 0


def test_the_bundle_never_carries_a_search_token_it_did_not_prove(record):
    """The entry IS the proven leaf, so its token is the one that matched."""
    commitment, entries, _ = record
    for index, bundle in enumerate(psa_verify.build_response(commitment, entries)):
        assert bundle.entry.token == entries[index].token
        assert merkle.MerkleTree.verify_leaf(
            bundle.entry.leaf(), bundle.proof, commitment.root
        )


# ===========================================================================
# Like-for-like against Option D — Exp. 4's two curves share an axis
# ===========================================================================
def test_step_1_does_the_same_work_as_option_d_on_a_TAMPERED_record():
    """A tampered record must not be cheaper to reject here than under Option D.

    Exp. 4's second arm tampers `t` of `r` records, and a tampered record fails
    at Step 1. `verify/proof.py::verify_merkle_membership` computes the leaf
    check AND the path walk unconditionally; `MerkleTree.verify_leaf` returns
    early on a leaf mismatch. Using it here would let the PSA curve reject a
    tampered record without walking the path, so the two constructions' Exp. 4
    numbers would price different work under one caption.

    Asserted structurally rather than by timing: a wall-clock comparison on a
    laptop would be noise, and this must hold on the campaign host too.
    """
    import inspect

    def body_of(fn) -> str:
        """Source after the docstring -- the docstring NAMES verify_leaf to say
        why it is not used, so matching the whole source finds its own note."""
        return inspect.getsource(fn).split('"""')[-1]

    psa_body = body_of(psa_verify.verify_merkle_membership)
    assert "verify_leaf" not in psa_body, (
        "Step 1 must not use MerkleTree.verify_leaf: it short-circuits on a "
        "leaf mismatch, which is exactly the tampered-record path Exp. 4 times"
    )
    assert "MerkleTree.verify(" in psa_body and "hash_leaf(" in psa_body

    from Schemes.ma_lb_pq_vdse.src.verify import proof as option_d_proof

    # Both compute leaf_matches AND root_matches before branching on either.
    for body, who in (
        (psa_body, "psa"),
        (body_of(option_d_proof.verify_merkle_membership), "option_d"),
    ):
        assert body.index("MerkleTree.verify(") < body.index("if not"), (
            f"{who}: the path walk must happen before the branch, or a "
            f"tampered record skips it"
        )


def test_a_tampered_record_still_reports_a_usable_proof_size(record):
    """Exp. 4 reports proof size per returned result, rejected ones included."""
    commitment, entries, pv = record
    forged = psa_records.PolicyStateIndexEntry(
        token=b"\x99" * 32, cid=entries[0].cid,
        policy_id=entries[0].policy_id, pv=entries[0].pv,
    )
    bundle = psa_verify.PsaVerificationBundle(
        meta=commitment.meta, proof=commitment.prove(0), entry=forged
    )
    result = psa_verify.verify_bundle(bundle, pv_expected=pv)
    assert not result.accepted
    assert result.proof_size_bytes > 0 and result.proof_path_length > 0
