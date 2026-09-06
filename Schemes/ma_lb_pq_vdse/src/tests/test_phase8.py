#!/usr/bin/env python3
"""Verification tests for MA-LB-PQ-VDSE Phase VIII Steps 1-3.

Each test checks a DEFINING PROPERTY. A verifier that reconstructs the root from a
proof but never checks the proof started at the entry it claims has passed the
shallow test and proves membership of something else.

Runs standalone with no test framework::

    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase8.py           # all
    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase8.py chain     # one area

and is also collectible by pytest if it is installed.

Covers ``verify/proof.py`` (Steps 1-2) and ``verify/ledger.py`` (Step 3) — the
Exp. 4 measured path. Steps 4-6 (retrieval, decryption, audit logging) are outside
the measurement boundary and are not implemented.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Common.crypto import hashes, merkle  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import types  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.chain import ledger as ledger_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import commit as commit_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import extract as extract_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import tokens as tokens_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.shard import propagation as prop_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.sync import dias as dias_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.verify import ledger as vledger_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.verify import proof as proof_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.tests import test_phase4 as p4  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


SEARCH_KEY = hashes.sha256(b"phase8-search-key", domain=b"test/search-key")
#: The DATA OWNER's authorization root — what Phase IV Step 5 binds into Commit_i.
AUTH_ROOT_DO = hashes.sha256(b"AuthRoot_DO", domain=b"test/auth-root")
#: A DATA USER's root. Distinct, which is the whole point of the Step 2 finding.
AUTH_ROOT_DU = hashes.sha256(b"AuthRoot_DU", domain=b"test/auth-root")


# ===========================================================================
# Fixtures
# ===========================================================================
def scheme() -> tokens_mod.TokenScheme:
    return tokens_mod.TokenScheme.keyed(SEARCH_KEY)


def committed_record(keywords: int = 6, rid: int = 0):
    """One record indexed and committed, with its Phase VI Step 5 response."""
    token_scheme = scheme()
    record = extract_mod.extract(
        p4.make_corpus_record(
            rid=rid, patient=f"patient-{rid:04d}", dom=0, keywords=keywords
        ),
        assignment=p4.make_assignment(2),
    )
    cid = prop_mod.placeholder_cid(rid)
    entries = tuple(
        types.IndexEntry(
            token=token_scheme.index_token(kw),
            cid=cid,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
        )
        for kw in record.keywords
    )
    commitment = commit_mod.commit_record(
        record_id=rid,
        entries=entries,
        policy_id=record.policy_id,
        vid=record.metadata.vid,
        auth_root_do=AUTH_ROOT_DO,
    )
    bundles = proof_mod.build_response(commitment, entries)
    return record, entries, commitment, bundles, cid


def anchored_chain(commitment, cid: str, *, vid: int = 1):
    """A ledger holding BC_i for a record, written through Phase VII Step 5."""
    chain = ledger_mod.InProcessLedger()
    message = dias_mod.DIASMessage(
        cid=cid,
        delta_vid=1,
        authority_commitment=hashes.sha256(b"C_auth", domain=b"t"),
        entries=(),
        root=commitment.root,
        commit=commitment.commit,
        authority_id="AA-dom0",
        domain="dom0",
    )
    dias_mod.anchor_update(chain, message=message, vid=vid)
    return chain


# ===========================================================================
# The bundle — Phase VI Step 5
# ===========================================================================
def test_bundle_carries_the_published_tuple():
    """Pi_i = (CID_i, Root_i, Commit_i, pi_i)."""
    record, entries, commitment, bundles, cid = committed_record(keywords=6)
    assert len(bundles) == 6
    for bundle in bundles:
        assert bundle.cid == cid
        assert bundle.root == commitment.root
        assert bundle.commit == commitment.commit
        assert bundle.proof.path_length > 0


def test_bundle_names_the_entry_its_proof_is_about():
    """The tree's leaves are H(I_j), so a CID alone cannot identify a leaf."""
    _, entries, commitment, bundles, _ = committed_record()
    for index, bundle in enumerate(bundles):
        assert bundle.entry == entries[index]
        assert bundle.policy_id == entries[index].policy_id
        assert bundle.vid == entries[index].vid


def test_bundle_refuses_an_entry_from_another_record():
    _, entries, commitment, _, cid = committed_record()
    foreign = types.IndexEntry(
        token=entries[0].token,
        cid=prop_mod.placeholder_cid(99),
        policy_id=entries[0].policy_id,
        vid=entries[0].vid,
    )
    try:
        proof_mod.VerificationBundle(
            cid=cid,
            root=commitment.root,
            commit=commitment.commit,
            proof=commitment.prove(0),
            entry=foreign,
        )
    except proof_mod.VerificationError as exc:
        assert "references" in str(exc)
        return
    raise AssertionError("a bundle whose entry names another CID should be refused")


def test_bundle_digest_covers_the_evidence_not_only_the_claims():
    """A bundle's digest must change if the proof path changes."""
    _, entries, commitment, bundles, cid = committed_record()
    first, second = bundles[0], bundles[1]
    assert first.digest() != second.digest()
    tampered = proof_mod.VerificationBundle(
        cid=first.cid,
        root=first.root,
        commit=first.commit,
        proof=second.proof,          # same claims, different evidence
        entry=first.entry,
    )
    assert tampered.digest() != first.digest()


def test_build_response_refuses_a_mismatched_entry_count():
    _, entries, commitment, _, _ = committed_record(keywords=6)
    try:
        proof_mod.build_response(commitment, entries[:3])
    except proof_mod.VerificationError as exc:
        assert "wrong leaves" in str(exc)
        return
    raise AssertionError("a short entry list should be refused")


def test_bundle_reports_the_exp4_secondary_metrics():
    """Proof size and path length, measured — odd-node promotion breaks log2(N)."""
    _, _, _, bundles, _ = committed_record(keywords=6)
    bundle = bundles[0]
    assert bundle.proof_path_length == bundle.proof.path_length
    assert bundle.proof_size_bytes == bundle.proof_path_length * (
        merkle.DIGEST_BYTES + 1
    )


# ===========================================================================
# Step 1 — Merkle membership
# ===========================================================================
def test_step1_accepts_a_valid_proof():
    """VerifyMerkle(Root_i, pi_i, CID_i) = 1."""
    _, _, _, bundles, _ = committed_record()
    for bundle in bundles:
        result = proof_mod.verify_merkle_membership(bundle)
        assert result.passed
        assert result.name == "merkle"
        assert result.elapsed_ns > 0


def test_step1_rejects_a_wrong_root():
    _, entries, commitment, bundles, cid = committed_record()
    forged = proof_mod.VerificationBundle(
        cid=cid,
        root=hashes.sha256(b"not-the-root", domain=b"t"),
        commit=commitment.commit,
        proof=bundles[0].proof,
        entry=bundles[0].entry,
    )
    result = proof_mod.verify_merkle_membership(forged)
    assert not result.passed
    assert "does not reconstruct" in result.detail


def test_step1_rejects_a_proof_for_a_different_leaf():
    """The classic mistake: the path reconstructs the root but starts elsewhere.

    Swapping in another entry's proof still verifies against Root_i — both leaves
    ARE in the tree — so checking only the root would accept a bundle that proves
    membership of a record's OTHER entry.
    """
    _, entries, commitment, bundles, cid = committed_record(keywords=6)
    mismatched = proof_mod.VerificationBundle(
        cid=cid,
        root=commitment.root,
        commit=commitment.commit,
        proof=commitment.prove(3),      # a valid proof...
        entry=entries[0],               # ...for a different entry
    )
    # The proof does verify against the root on its own.
    assert merkle.MerkleTree.verify(mismatched.proof, commitment.root)
    # But the bundle must still be rejected.
    result = proof_mod.verify_merkle_membership(mismatched)
    assert not result.passed
    assert "not the entry this bundle names" in result.detail


def test_step1_rejects_a_tampered_entry():
    """An entry altered after commitment must fail — the integrity property."""
    _, entries, commitment, bundles, cid = committed_record()
    altered = entries[0].with_policy(policy_id="dom0/forged", vid=99)
    bundle = proof_mod.VerificationBundle(
        cid=cid,
        root=commitment.root,
        commit=commitment.commit,
        proof=commitment.prove(0),
        entry=altered,
    )
    assert not proof_mod.verify_merkle_membership(bundle).passed


# ===========================================================================
# Step 2 — authorization state
# ===========================================================================
def test_step2_accepts_with_the_owners_authorization_root():
    """Commit_i* = Commit_i when recomputed with AuthRoot_DO."""
    record, _, _, bundles, _ = committed_record()
    result = proof_mod.verify_authorization_state(
        bundles[0],
        auth_root=AUTH_ROOT_DO,
        vid_u=record.metadata.vid,
    )
    assert result.passed
    assert result.name == "authorization"


def test_step2_as_published_fails_for_every_non_owner():
    """THE Phase VIII Step 2 blocker, demonstrated.

    Step 2 (:1167) recomputes Commit_i* with AuthRoot_U, the DATA USER's root,
    while Phase IV Step 5 binds AuthRoot_DO, the DATA OWNER's. They differ for
    everyone who is not the owner, so Commit_i* = Commit_i can never hold and
    Exp. 4 would report a 0% acceptance rate.
    """
    record, _, _, bundles, _ = committed_record()
    assert AUTH_ROOT_DU != AUTH_ROOT_DO
    literal = proof_mod.verify_authorization_state(
        bundles[0],
        auth_root=AUTH_ROOT_DU,          # as written: the USER's root
        vid_u=record.metadata.vid,
    )
    assert not literal.passed
    assert "Commit_i*" in literal.detail


def test_step2_recomputation_uses_the_single_commitment_definition():
    """A verifier with its own copy of the concatenation would drift from Phase IV."""
    record, _, commitment, bundles, _ = committed_record()
    assert proof_mod.recompute_commitment(bundles[0], AUTH_ROOT_DO) == (
        commit_mod.policy_commitment(
            root=commitment.root,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
            auth_root_do=AUTH_ROOT_DO,
        )
    )
    assert proof_mod.recompute_commitment(bundles[0], AUTH_ROOT_DO) == commitment.commit


def test_step2_version_equality_is_checked_as_published():
    """VID_i = VID_U (:1167)."""
    record, _, _, bundles, _ = committed_record()
    assert proof_mod.check_version_equality(bundles[0], record.metadata.vid)
    assert not proof_mod.check_version_equality(bundles[0], record.metadata.vid + 1)


def test_step2_version_mismatch_rejects():
    record, _, _, bundles, _ = committed_record()
    result = proof_mod.verify_authorization_state(
        bundles[0], auth_root=AUTH_ROOT_DO, vid_u=record.metadata.vid + 5
    )
    assert not result.passed
    assert "VID_i" in result.detail


def test_step2_version_check_can_be_skipped():
    """The published check equates a record's version with a user's profile version.

    Two of the four VID namespaces, so the equality fails in the normal case;
    require_version_match=False is the path that does not depend on it.
    """
    record, _, _, bundles, _ = committed_record()
    result = proof_mod.verify_authorization_state(
        bundles[0], auth_root=AUTH_ROOT_DO, require_version_match=False
    )
    assert result.passed


def test_step2_requires_vid_u_when_the_version_check_is_on():
    _, _, _, bundles, _ = committed_record()
    try:
        proof_mod.verify_authorization_state(
            bundles[0], auth_root=AUTH_ROOT_DO, require_version_match=True
        )
    except proof_mod.VerificationError as exc:
        assert "VID_U" in str(exc)
        return
    raise AssertionError("the version check without VID_U should raise")


def test_step2_rejects_a_forged_policy_or_root():
    """Commit_i binds Root_i, PID_i, VID_i and AuthRoot — all four."""
    record, entries, commitment, bundles, cid = committed_record()
    forged_policy = types.IndexEntry(
        token=entries[0].token,
        cid=cid,
        policy_id="dom0/forged",
        vid=entries[0].vid,
    )
    bundle = proof_mod.VerificationBundle(
        cid=cid,
        root=commitment.root,
        commit=commitment.commit,
        proof=commitment.prove(0),
        entry=forged_policy,
    )
    result = proof_mod.verify_authorization_state(
        bundle, auth_root=AUTH_ROOT_DO, vid_u=entries[0].vid
    )
    assert not result.passed


# ===========================================================================
# Step 3 — blockchain consistency
# ===========================================================================
def test_step3_accepts_a_matching_anchor():
    """BC_i = (CID_i, Commit_i, Root_i, VID_i, TS_i) agrees with the bundle."""
    _, _, commitment, bundles, cid = committed_record()
    chain = anchored_chain(commitment, cid)
    result = vledger_mod.verify_blockchain_consistency(chain, bundles[0])
    assert result.passed
    assert result.name == "chain"


def test_step3_detects_an_index_state_never_published():
    """The attack Steps 1-2 cannot catch.

    Steps 1 and 2 are computed FROM the values the node supplied, so a node that
    served a well-formed bundle over an index state it never anchored passes both.
    Only Step 3 catches it.
    """
    _, entries, commitment, _, cid = committed_record(keywords=6)
    chain = anchored_chain(commitment, cid)

    # A second, internally consistent commitment the node never anchored.
    unpublished_entries = tuple(
        e.with_policy(policy_id="dom0/never-published", vid=e.vid) for e in entries
    )
    unpublished = commit_mod.commit_record(
        record_id=0,
        entries=unpublished_entries,
        policy_id="dom0/never-published",
        vid=entries[0].vid,
        auth_root_do=AUTH_ROOT_DO,
    )
    rogue = proof_mod.build_response(unpublished, unpublished_entries)[0]

    # Steps 1 and 2 both pass on the rogue bundle.
    assert proof_mod.verify_merkle_membership(rogue).passed
    assert proof_mod.verify_authorization_state(
        rogue, auth_root=AUTH_ROOT_DO, vid_u=entries[0].vid
    ).passed
    # Step 3 rejects it.
    result = vledger_mod.verify_blockchain_consistency(chain, rogue)
    assert not result.passed
    assert "anchored root" in result.detail


def test_step3_reports_an_unanchored_record():
    """Phase V Step 3 is not implemented, so this is a real condition."""
    _, _, commitment, bundles, cid = committed_record()
    empty = ledger_mod.InProcessLedger()
    result = vledger_mod.verify_blockchain_consistency(empty, bundles[0])
    assert not result.passed
    assert "no BC_i anchored" in result.detail


def test_step3_detects_a_tampered_chain():
    """"immutable blockchain commitment" must be verified, not assumed."""
    _, _, commitment, bundles, cid = committed_record()
    chain = anchored_chain(commitment, cid)
    assert vledger_mod.verify_blockchain_consistency(chain, bundles[0]).passed

    original = chain._entries[0]
    chain._entries[0] = ledger_mod.LedgerEntry(
        sequence=original.sequence,
        namespace=original.namespace,
        key=original.key,
        payload=original.payload + b"\x00",
        domain=original.domain,
        timestamp_ns=original.timestamp_ns,
        previous_hash=original.previous_hash,
        entry_hash=original.entry_hash,
        record=original.record,
    )
    result = vledger_mod.verify_blockchain_consistency(chain, bundles[0])
    assert not result.passed
    assert "hash chain" in result.detail


def test_step3_chain_integrity_can_be_separated_from_the_per_record_check():
    """Exp. 4 sweeps r; the per-record comparison scales with r, the chain does not."""
    _, _, commitment, bundles, cid = committed_record()
    chain = anchored_chain(commitment, cid)
    with_chain = vledger_mod.verify_blockchain_consistency(
        chain, bundles[0], check_chain_integrity=True
    )
    without = vledger_mod.verify_blockchain_consistency(
        chain, bundles[0], check_chain_integrity=False
    )
    assert with_chain.passed and without.passed


def test_step3_anchor_lookup_finds_the_latest_version():
    _, _, commitment, bundles, cid = committed_record()
    chain = ledger_mod.InProcessLedger()
    for vid in (1, 2, 3):
        dias_mod.anchor_update(
            chain,
            message=dias_mod.DIASMessage(
                cid=cid,
                delta_vid=1,
                authority_commitment=hashes.sha256(b"c", domain=b"t"),
                entries=(),
                root=commitment.root,
                commit=commitment.commit,
                authority_id="AA-dom0",
                domain="dom0",
            ),
            vid=vid,
        )
    lookup = vledger_mod.lookup_anchor(chain, cid)
    assert lookup.vid == 3
    assert lookup.versions_available == (1, 2, 3)
    assert vledger_mod.lookup_anchor(chain, cid, vid=2).vid == 2


def test_step3_anchor_lookup_reports_a_missing_version():
    _, _, commitment, _, cid = committed_record()
    chain = anchored_chain(commitment, cid, vid=1)
    try:
        vledger_mod.lookup_anchor(chain, cid, vid=7)
    except vledger_mod.ChainVerificationError as exc:
        assert "not at 7" in str(exc)
        return
    raise AssertionError("a missing version should raise")


def test_step3_anchor_history_detects_a_gap():
    """A gap means an update was never anchored — the chain cannot reveal that.

    Every anchor is individually valid and the hash chain verifies, because nothing
    was tampered with. Only the version sequence shows the history is incomplete.
    """
    _, _, commitment, _, cid = committed_record()
    chain = ledger_mod.InProcessLedger()
    for vid in (1, 2, 4):                       # 3 never anchored
        dias_mod.anchor_update(
            chain,
            message=dias_mod.DIASMessage(
                cid=cid,
                delta_vid=1,
                authority_commitment=hashes.sha256(b"c", domain=b"t"),
                entries=(),
                root=commitment.root,
                commit=commitment.commit,
                authority_id="AA-dom0",
                domain="dom0",
            ),
            vid=vid,
        )
    history = vledger_mod.anchor_history(chain, cid)
    assert history.versions == (1, 2, 4)
    assert not history.is_monotone()
    assert chain.verify_chain()               # the chain itself is intact
    assert history.latest.vid == 4


def test_step3_anchor_key_matches_phase_vii():
    """Both sides must agree, or Step 3 looks up keys Step 7 never wrote."""
    assert vledger_mod.anchor_key("cid-1", 5) == "cid-1#000000000005"
    try:
        vledger_mod.anchor_key("cid-1", -1)
    except ValueError:
        return
    raise AssertionError("a negative VID should not produce a key")


# ===========================================================================
# Steps 1-3 together — the Exp. 4 measurement
# ===========================================================================
def test_verify_bundle_runs_all_three_steps():
    record, _, commitment, bundles, cid = committed_record()
    chain = anchored_chain(commitment, cid)
    result = proof_mod.verify_bundle(
        bundles[0],
        auth_root=AUTH_ROOT_DO,
        vid_u=record.metadata.vid,
        chain_check=vledger_mod.chain_checker(chain),
    )
    assert result.accepted
    assert [step.name for step in result.steps] == ["merkle", "authorization", "chain"]
    assert result.failed_step is None
    assert result.elapsed_ns == sum(s.elapsed_ns for s in result.steps)


def test_verify_bundle_short_circuits_on_a_failed_merkle_proof():
    """":1143" — the ciphertext is "immediately rejected".

    The later steps must not run, and — for Exp. 4 — must not be timed: a verifier
    that always ran all three would report a cost no real client pays.
    """
    record, entries, commitment, bundles, cid = committed_record()
    chain = anchored_chain(commitment, cid)
    broken = proof_mod.VerificationBundle(
        cid=cid,
        root=hashes.sha256(b"wrong", domain=b"t"),
        commit=commitment.commit,
        proof=bundles[0].proof,
        entry=bundles[0].entry,
    )
    result = proof_mod.verify_bundle(
        broken,
        auth_root=AUTH_ROOT_DO,
        vid_u=record.metadata.vid,
        chain_check=vledger_mod.chain_checker(chain),
    )
    assert not result.accepted
    assert result.failed_step == "merkle"
    assert len(result.steps) == 1


def test_verify_response_reports_the_exp4_metrics():
    """Exp. 4: latency (ms) primary; proof size (KB) and path length secondary."""
    record, entries, commitment, bundles, cid = committed_record(keywords=6)
    chain = anchored_chain(commitment, cid)
    batch = proof_mod.verify_response(
        bundles,
        auth_root=AUTH_ROOT_DO,
        vid_u=record.metadata.vid,
        chain_check=vledger_mod.chain_checker(chain),
    )
    assert batch.record_count == 6
    assert batch.accepted_count == 6
    assert batch.rejected == ()
    assert batch.elapsed_ms > 0
    assert batch.total_proof_kb == batch.total_proof_bytes / 1024.0
    assert batch.mean_path_length > 0


def test_verify_response_checks_every_bundle_even_after_one_fails():
    """A client verifying r results must know WHICH are usable.

    Stopping at the first rejection would also make the measured cost depend on
    where in the batch the failure happened to fall.
    """
    record, entries, commitment, bundles, cid = committed_record(keywords=6)
    chain = anchored_chain(commitment, cid)
    broken = proof_mod.VerificationBundle(
        cid=cid,
        root=hashes.sha256(b"wrong", domain=b"t"),
        commit=commitment.commit,
        proof=bundles[2].proof,
        entry=bundles[2].entry,
    )
    mixed = bundles[:2] + (broken,) + bundles[3:]
    batch = proof_mod.verify_response(
        mixed,
        auth_root=AUTH_ROOT_DO,
        vid_u=record.metadata.vid,
        chain_check=vledger_mod.chain_checker(chain),
    )
    assert batch.record_count == 6
    assert batch.accepted_count == 5
    assert len(batch.rejected) == 1


def test_verify_response_refuses_an_empty_response():
    try:
        proof_mod.verify_response([], auth_root=AUTH_ROOT_DO, vid_u=0)
    except proof_mod.VerificationError:
        return
    raise AssertionError("an empty response should raise")


def test_verification_survives_a_phase_vii_update():
    """After DIAS, the re-anchored state verifies and the stale bundle does not."""
    record, entries, commitment, bundles, cid = committed_record(keywords=6)
    chain = ledger_mod.InProcessLedger()

    # Phase VII: repolicy the record, then anchor the new state.
    new_policy = "dom0/evolved"
    evolved_entries = tuple(
        e.with_policy(policy_id=new_policy, vid=e.vid) for e in entries
    )
    evolved = commit_mod.commit_record(
        record_id=0,
        entries=evolved_entries,
        policy_id=new_policy,
        vid=entries[0].vid,
        auth_root_do=AUTH_ROOT_DO,
    )
    dias_mod.anchor_update(
        chain,
        message=dias_mod.DIASMessage(
            cid=cid,
            delta_vid=1,
            authority_commitment=hashes.sha256(b"c", domain=b"t"),
            entries=evolved_entries,
            root=evolved.root,
            commit=evolved.commit,
            authority_id="AA-dom0",
            domain="dom0",
        ),
        vid=1,
    )

    checker = vledger_mod.chain_checker(chain)
    # The evolved response verifies end to end.
    fresh = proof_mod.build_response(evolved, evolved_entries)
    assert proof_mod.verify_bundle(
        fresh[0],
        auth_root=AUTH_ROOT_DO,
        vid_u=entries[0].vid,
        chain_check=checker,
    ).accepted
    # The pre-update bundle now disagrees with the anchor — Step 3 catches it.
    stale = proof_mod.verify_bundle(
        bundles[0],
        auth_root=AUTH_ROOT_DO,
        vid_u=entries[0].vid,
        chain_check=checker,
    )
    assert not stale.accepted
    assert stale.failed_step == "chain"


def test_phase_viii_excludes_retrieval_and_decryption():
    """README §5: "IPFS fetch and decryption excluded" from Exp. 4.

    Checked structurally, so a later addition cannot quietly widen the measured
    boundary.
    """
    for module in (proof_mod, vledger_mod):
        names = {n for n in dir(module) if not n.startswith("_")}
        assert not {
            "retrieve",
            "fetch_ciphertext",
            "decrypt",
            "decrypt_record",
            "ipfs_get",
        } & names


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
