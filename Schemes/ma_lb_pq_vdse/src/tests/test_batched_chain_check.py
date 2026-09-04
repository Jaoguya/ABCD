"""Batching Step 3's anchor fetch must change the COST and nothing else.

``lookup_anchor`` walks and sorts the whole version-identifier namespace on every
call, so verifying ``r`` records walked it ``r`` times: O(r^2), and measured at
99.6% of the chain step against 0.4% for the three comparisons the step exists to
make. ``batched_chain_checker`` resolves every anchor in one pass instead.

The risk in a change like this is that it quietly verifies LESS. Every test here
is aimed at that: the batched path must reach the same accept/reject decision as
the per-record path on the same input, must still check each record against its
OWN anchor at the latest anchored version, and must still fail a record whose
anchor is absent rather than passing it or abandoning the rest of the response.
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from Schemes.ma_lb_pq_vdse.src import config as config_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as exp_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.verify import ledger as vledger_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.verify import proof as proof_mod  # noqa: E402

CONFIG = config_mod.load()
SOURCE = exp_mod.SyntheticRecordSource()

RECORDS = 40


@pytest.fixture(scope="module")
def prepared():
    experiment = exp_mod.Exp4Verification(
        config=CONFIG, source=SOURCE, values=(RECORDS,)
    )
    return experiment.prepare(RECORDS)


def _verify(prepared, checker):
    return proof_mod.verify_response(
        prepared["bundles"],
        auth_root=prepared["auth_root"],
        require_version_match=False,
        chain_check=checker,
    )


def _batched(prepared, **kwargs):
    return vledger_mod.batched_chain_checker(
        prepared["deployment"].ledger,
        [b.cid for b in prepared["bundles"]],
        check_chain_integrity=False,
        **kwargs,
    )


def _per_record(prepared):
    return vledger_mod.chain_checker(
        prepared["deployment"].ledger, check_chain_integrity=False
    )


def test_both_paths_accept_the_same_response(prepared):
    one = _verify(prepared, _per_record(prepared))
    many = _verify(prepared, _batched(prepared))
    assert one.accepted_count == many.accepted_count == prepared["bundles"].__len__()
    assert one.rejected == many.rejected == ()


def test_both_paths_agree_per_record_not_just_in_total(prepared):
    """A batched check that accepted one extra and rejected one other would
    still match on totals. Compare the decisions record by record."""
    one = _verify(prepared, _per_record(prepared))
    many = _verify(prepared, _batched(prepared))
    assert [(r.cid, r.accepted) for r in one.results] == \
           [(r.cid, r.accepted) for r in many.results]


def test_a_tampered_root_is_still_rejected_by_the_batched_path(prepared):
    """The comparison is what Step 3 is for; batching must not skip it."""
    bundles = list(prepared["bundles"])
    victim = bundles[len(bundles) // 2]
    bundles[len(bundles) // 2] = dataclasses.replace(
        victim, root=bytes(32)
    )
    batch = proof_mod.verify_response(
        tuple(bundles),
        auth_root=prepared["auth_root"],
        require_version_match=False,
        chain_check=_batched(prepared),
    )
    assert batch.accepted_count == len(bundles) - 1
    rejected = [r for r in batch.results if not r.accepted]
    assert len(rejected) == 1
    # Rejected at Step 1, because the root is also what the Merkle path
    # reconstructs -- the point is that ONE record fell out, not the batch.
    assert rejected[0].cid == victim.cid


def test_each_record_is_checked_against_its_own_anchor(prepared):
    """Batching resolves many anchors at once; it must not let one record's
    anchor stand in for another's."""
    ledger = prepared["deployment"].ledger
    cids = [b.cid for b in prepared["bundles"]]
    anchors, missing = vledger_mod.lookup_anchors(ledger, cids)
    assert not missing
    for cid, lookup in anchors.items():
        assert lookup.anchor.cid == cid


def test_batched_lookup_matches_the_per_record_lookup(prepared):
    """Same anchor, same version, for every CID."""
    ledger = prepared["deployment"].ledger
    cids = [b.cid for b in prepared["bundles"]]
    anchors, _ = vledger_mod.lookup_anchors(ledger, cids)
    for cid in cids:
        single = vledger_mod.lookup_anchor(ledger, cid)
        assert anchors[cid].anchor == single.anchor
        assert anchors[cid].key == single.key


def test_an_unanchored_record_fails_and_the_rest_still_verify(prepared):
    """An unanchored record is a verification failure for THAT record. It must
    not raise and abandon the other r-1, which is what the per-record path's
    ChainVerificationError would do if it escaped."""
    ledger = prepared["deployment"].ledger
    cids = [b.cid for b in prepared["bundles"]]
    anchors, missing = vledger_mod.lookup_anchors(
        ledger, cids + ["cid-that-was-never-anchored"]
    )
    assert missing == ("cid-that-was-never-anchored",)
    assert len(anchors) == len(cids)


def test_the_fetch_is_lazy_so_a_harness_cannot_hide_it_in_prepare(prepared):
    """The one-off walk must land inside whatever region the caller times.

    Building the checker must touch nothing; the cost appears on the first
    bundle checked.
    """
    ledger = prepared["deployment"].ledger
    walks = []
    original = ledger.keys

    def counting_keys(namespace, *, prefix=""):
        walks.append(namespace)
        return original(namespace, prefix=prefix)

    ledger.keys = counting_keys  # type: ignore[method-assign]
    try:
        checker = vledger_mod.batched_chain_checker(
            ledger, [b.cid for b in prepared["bundles"]],
            check_chain_integrity=False,
        )
        assert walks == [], "constructing the checker already walked the ledger"
        checker(prepared["bundles"][0])
        assert len(walks) == 1
        # ... and only once, however many records follow.
        for bundle in prepared["bundles"][1:]:
            checker(bundle)
        assert len(walks) == 1
    finally:
        ledger.keys = original  # type: ignore[method-assign]


def test_one_walk_for_the_whole_response_not_one_per_record(prepared):
    """The property the change exists for, stated as a test rather than a
    benchmark: r records, one namespace walk."""
    ledger = prepared["deployment"].ledger
    walks = []
    original = ledger.keys

    def counting_keys(namespace, *, prefix=""):
        walks.append(prefix)
        return original(namespace, prefix=prefix)

    ledger.keys = counting_keys  # type: ignore[method-assign]
    try:
        _verify(prepared, _batched(prepared))
        batched_walks = len(walks)
        walks.clear()
        _verify(prepared, _per_record(prepared))
        per_record_walks = len(walks)
    finally:
        ledger.keys = original  # type: ignore[method-assign]

    assert batched_walks == 1
    assert per_record_walks == len(prepared["bundles"])
