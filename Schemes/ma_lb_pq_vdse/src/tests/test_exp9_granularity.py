"""Exp. 9 measures a claim that is easy to state and easy to fake.

The claim is that a Merkle-path verifier discards only the records that were
tampered with, where an accumulator-based verifier discards the whole response.
Two ways to produce that figure dishonestly, and a test for each:

* Count the tampered records instead of the rejected ones. Then the figure is
  the sweep variable plotted against itself and would look identical for a
  scheme with no granularity at all. ``measure`` therefore reports
  ``len(batch.rejected)`` and cross-checks it against the number tampered --
  the tests below drive that cross-check from both sides.
* Tamper in a way that trips ``VerificationError`` (a malformed bundle) rather
  than ``accepted = False`` (a detected tamper). Those are different code paths;
  only the second is what Phase VIII Step 1 exists to catch.

The t=0 case is pinned here rather than swept, because the figure is log-log.
It is also where a false-positive rejection would first show up.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from Schemes.ma_lb_pq_vdse.src import config as config_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as exp_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.verify import proof as proof_mod  # noqa: E402

CONFIG = config_mod.load()
SOURCE = exp_mod.SyntheticRecordSource()

#: Small enough to keep the suite fast, large enough that the sweep points
#: below are all reachable. The pinned 20,000 is exercised by the campaign, not
#: by every test run.
TEST_RETURNED = 600


def _experiment(returned: int = TEST_RETURNED):
    return exp_mod.Exp9VerificationGranularity(
        config=CONFIG, source=SOURCE, returned_results=returned
    )


def test_one_bundle_per_record_not_one_per_index_entry():
    """The unit is a RECORD. Regression guard for the d1cdf9c class of defect.

    ``build_response`` emits one bundle per INDEX ENTRY, so the easy way to
    assemble ``returned_results`` bundles is to ``extend`` over records until the
    count is reached -- which is what this arm did until 2026-09-05. At the
    frozen corpus's |W_i| ~= 32 that made the pinned 20,000 into ~632 records
    carrying 20,000 entries, while both baselines returned ~20,000 RECORDS: guo
    picks a keyword matching ~19,975 documents, yue_ge returns 20,000 result ids.

    Exp. 4 had already been re-run once for exactly this ("r counted index
    entries, not returned records"), and the two are now panels of one figure,
    so a mismatch would put panel (a) in records and panel (b) in entries under
    a single caption.

    One record yields one CID, so distinct CIDs is the sharp form of the check:
    it fails under the old code even if the bundle COUNT happens to be right.
    """
    prepared = _experiment().prepare(0)
    bundles = prepared["bundles"]
    assert len(bundles) == TEST_RETURNED
    assert len({b.cid for b in bundles}) == len(bundles), (
        "bundles share a CID, so they are index entries of the same record "
        "rather than distinct returned records"
    )


def test_step3_is_batched_like_exp4s():
    """Both panels of fig:exp4 must use the same Step 3 path.

    `lookup_anchor` sorts the whole version-identifier namespace per call, so a
    per-record checker makes Step 3 O(r^2) -- fixed for Exp. 4 in `e252cc9` and
    not for Exp. 9. It stayed invisible while this arm measured 20,000 bundles
    against a ~632-anchor namespace; correcting the unit to one bundle per record
    put 20,000 anchors in that namespace and the quadratic term surfaced, at
    192 us/record for r=2,000 against 1,561 us/record for r=20,000. Batching
    restored linearity and took r=20,000 from 31.2 s to 0.95 s.

    Panel (a) and panel (b) latencies are only comparable if both pay the same
    Step 3, which is the reason this is pinned rather than left to review.
    """
    import inspect

    src = inspect.getsource(exp_mod.Exp9VerificationGranularity.measure)
    assert "batched_chain_checker" in src, (
        "Exp. 9 must batch the anchor fetch; the per-record checker is O(r^2) "
        "at this arm's result-set size"
    )
    exp4_src = inspect.getsource(exp_mod.Exp4Verification.measure)
    assert "batched_chain_checker" in exp4_src


def test_the_denominator_is_the_record_count_the_deployment_built():
    """No silent top-up from a second record's entries."""
    experiment = _experiment()
    prepared = experiment.prepare(0)
    assert len(prepared["deployment"].records) >= TEST_RETURNED


def test_exp4_and_exp9_agree_on_what_one_returned_result_is():
    """Both panels of fig:exp4 must sweep the same unit.

    Compared through the built bundles rather than by reading the source, so a
    future refactor of either ``prepare`` cannot drift them apart while still
    looking similar.
    """
    r = 40
    exp4 = exp_mod.Exp4Verification(config=CONFIG, source=SOURCE)
    exp4_bundles = exp4.prepare(r)["bundles"]
    exp9_bundles = _experiment(returned=r).prepare(0)["bundles"]
    assert len(exp4_bundles) == len(exp9_bundles) == r
    assert len({b.cid for b in exp4_bundles}) == r
    assert len({b.cid for b in exp9_bundles}) == r


def test_registered_as_experiment_nine():
    built = exp_mod.build_experiment(9, CONFIG, SOURCE)
    assert isinstance(built, exp_mod.Exp9VerificationGranularity)
    assert built.name == "exp9_verification_granularity"


def test_returned_results_comes_from_global_yaml_not_a_runner_constant():
    """All three schemes discard from the same denominator or the figure lies."""
    spec = CONFIG.experiment("exp9")
    assert spec.held_constant["returned_results"] == 20_000
    assert _experiment(returned=0).returned_results == 20_000


def test_untampered_response_discards_nothing():
    sample = _experiment().measure(_experiment().prepare(0))
    assert sample.primary == 0.0
    assert sample.secondaries["usable_recovered"] == TEST_RETURNED


@pytest.mark.parametrize("tampered", [1, 2, 5, 50])
def test_exactly_the_tampered_records_are_discarded(tampered):
    experiment = _experiment()
    sample = experiment.measure(experiment.prepare(tampered))
    assert sample.primary == tampered
    assert sample.secondaries["usable_recovered"] == TEST_RETURNED - tampered
    assert sample.secondaries["tampered_localised"] == tampered


def test_discarded_is_measured_not_echoed_from_the_sweep_variable():
    """The primary must come from the verifier, not from the input.

    If ``measure`` returned the sweep value, this passes trivially for any
    scheme. Verifying a batch nobody tampered with must therefore report zero
    even though the experiment was prepared for a non-zero t.
    """
    experiment = _experiment()
    prepared = experiment.prepare(5)
    untouched = dict(prepared)
    untouched["bundles"] = tuple(
        b for i, b in enumerate(prepared["bundles"])
    )
    # Rebuild a clean batch and claim 5 were tampered: the cross-check must
    # fire rather than the figure quietly reporting 5.
    clean = experiment.prepare(0)
    untouched["bundles"] = clean["bundles"]
    untouched["deployment"] = clean["deployment"]
    untouched["auth_root"] = clean["auth_root"]
    with pytest.raises(RuntimeError, match="neither sound nor complete"):
        experiment.measure(untouched)


def test_the_tamper_is_detected_not_malformed():
    """A tampered bundle must FAIL verification, not fail to parse.

    ``VerificationError`` is a protocol error and travels a different path;
    counting it would measure parse failure and call it tamper detection.
    """
    experiment = _experiment()
    prepared = experiment.prepare(1)
    tampered = [
        b for b in prepared["bundles"]
        if b.entry.token != b.proof.leaf_hash
    ]
    assert tampered, "the sweep prepared no tampered bundle"

    batch = proof_mod.verify_response(
        prepared["bundles"],
        auth_root=prepared["auth_root"],
        require_version_match=False,
    )
    rejected = [r for r in batch.results if not r.accepted]
    assert len(rejected) == 1
    step = rejected[0].step("merkle")
    assert not step.passed
    assert "not the entry this bundle names" in step.detail


def test_tamper_leaves_the_bundle_well_formed():
    """CID_i is untouched, so the bundle's own consistency check still holds."""
    experiment = _experiment()
    prepared = experiment.prepare(1)
    for bundle in prepared["bundles"]:
        assert bundle.entry.cid == bundle.cid


def test_every_returned_record_is_verified_even_after_one_fails():
    """A client checking r results must learn which are usable, not just that
    one was not. Stopping at the first rejection would make the discarded count
    depend on where the tamper happened to land."""
    experiment = _experiment()
    prepared = experiment.prepare(10)
    batch = proof_mod.verify_response(
        prepared["bundles"],
        auth_root=prepared["auth_root"],
        require_version_match=False,
    )
    assert len(batch.results) == TEST_RETURNED
    assert batch.accepted_count == TEST_RETURNED - 10


def test_cannot_tamper_more_records_than_were_returned():
    with pytest.raises(ValueError, match="cannot tamper"):
        _experiment(returned=10).prepare(50)


def test_primary_is_a_count_not_a_timing():
    """Exp. 9's headline is what verification BUYS. Latency rides along as a
    secondary so the price stays visible, but it is not the figure."""
    experiment = _experiment()
    assert experiment.primary.name == "records_discarded"
    assert not experiment.primary.is_timing
    assert any(m.name == "latency" and m.is_timing
               for m in experiment.secondaries)
