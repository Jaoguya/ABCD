"""Steps 2-3 are amortised over the record. Prove that hides nothing.

``verify_response`` computes Phase VIII Steps 2 and 3 once per RECORD rather than
once per returned entry, because both depend only on
``proof._record_identity(bundle)`` and ``build_response`` emits one bundle per
entry. At the published ``keywords_per_record`` that is ~6 bundles per record, and
the redundant work was 67% of Exp. 4's runtime.

The risk an optimisation like this carries is that a cache answers for a bundle it
was never asked about. Every test below is aimed at that: same verdicts as
per-bundle verification, no sharing across records, and a tampered bundle still
rejected when its record-mates pass.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Common.crypto import merkle  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.verify import ledger as vledger_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.verify import proof as proof_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.tests.test_phase8 import (  # noqa: E402
    AUTH_ROOT_DO,
    anchored_chain,
    committed_record,
)


def _response(keywords: int = 6, rid: int = 0):
    _, _, commitment, bundles, cid = committed_record(keywords=keywords, rid=rid)
    chain = anchored_chain(commitment, cid, vid=bundles[0].vid)
    checker = vledger_mod.chain_checker(chain, check_chain_integrity=False)
    return bundles, checker


def _verify(bundles, checker):
    return proof_mod.verify_response(
        bundles,
        auth_root=AUTH_ROOT_DO,
        require_version_match=False,
        chain_check=checker,
    )


# ===========================================================================
# The key covers exactly what the cached steps read
# ===========================================================================
def test_identity_includes_cid_because_step3_looks_the_anchor_up_by_it():
    """Step 2 never reads ``cid``; Step 3 does. The key must cover both."""
    bundles, _ = _response()
    assert proof_mod._record_identity(bundles[0])[0] == bundles[0].cid


def test_one_record_has_one_identity_across_all_its_entries():
    bundles, _ = _response(keywords=6)
    assert len({proof_mod._record_identity(b) for b in bundles}) == 1


def test_two_records_never_share_an_identity():
    first, _ = _response(rid=0)
    second, _ = _response(rid=1)
    assert proof_mod._record_identity(first[0]) != proof_mod._record_identity(second[0])


# ===========================================================================
# Same verdicts as verifying each bundle on its own
# ===========================================================================
def test_verdicts_match_per_bundle_verification():
    bundles, checker = _response()
    batch = _verify(bundles, checker)
    for bundle, got in zip(bundles, batch.results):
        alone = proof_mod.verify_bundle(
            bundle,
            auth_root=AUTH_ROOT_DO,
            require_version_match=False,
            chain_check=checker,
        )
        assert got.accepted == alone.accepted
        assert got.failed_step == alone.failed_step


def test_every_bundle_still_gets_its_own_verdict():
    bundles, checker = _response()
    batch = _verify(bundles, checker)
    assert batch.record_count == len(bundles)
    assert batch.accepted_count == len(bundles)


# ===========================================================================
# The security property: a bad bundle is not covered by a good record-mate
# ===========================================================================
def test_a_tampered_leaf_is_rejected_though_its_record_mates_pass():
    """The whole point. Step 1 is per bundle and must stay that way."""
    bundles, checker = _response(keywords=6)
    victim = bundles[3]
    forged = proof_mod.VerificationBundle(
        cid=victim.cid,
        root=victim.root,
        commit=victim.commit,
        proof=bundles[1].proof,      # another entry's path, same record
        entry=victim.entry,
    )
    mixed = bundles[:3] + (forged,) + bundles[4:]
    batch = _verify(mixed, checker)
    assert batch.accepted_count == len(bundles) - 1
    assert batch.results[3].failed_step == "merkle"
    assert not batch.results[3].accepted


def test_a_wrong_auth_root_rejects_every_bundle_not_just_the_first():
    """A cached Step 2 must be reused as a REJECTION too, never dropped."""
    bundles, checker = _response()
    batch = proof_mod.verify_response(
        bundles,
        auth_root=b"\x00" * merkle.DIGEST_BYTES,   # not AuthRoot_DO
        require_version_match=False,
        chain_check=checker,
    )
    assert batch.accepted_count == 0
    assert all(r.failed_step == "authorization" for r in batch.results)


# ===========================================================================
# Honest accounting
# ===========================================================================
def test_reused_steps_are_marked_and_carry_no_time():
    bundles, checker = _response(keywords=6)
    batch = _verify(bundles, checker)
    reused = [s for r in batch.results for s in r.steps if s.amortised]
    assert reused, "with 6 entries on one record, steps 2-3 must be reused"
    assert all(s.elapsed_ns == 0 for s in reused)


def test_the_first_bundle_pays_and_is_not_marked():
    bundles, checker = _response(keywords=6)
    batch = _verify(bundles, checker)
    first = batch.results[0]
    assert not any(s.amortised for s in first.steps)
    assert first.step("authorization").elapsed_ns > 0


def test_batch_elapsed_counts_work_done_once():
    """Summing must not bill one computation to every bundle that consumed it."""
    bundles, checker = _response(keywords=6)
    batch = _verify(bundles, checker)
    authz = [r.step("authorization") for r in batch.results]
    assert sum(1 for s in authz if not s.amortised) == 1
    assert sum(s.elapsed_ns for s in authz) == authz[0].elapsed_ns
