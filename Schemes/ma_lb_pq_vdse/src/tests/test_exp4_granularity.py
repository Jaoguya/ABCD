"""Exp. 4's `granularity` arm measures a claim that is easy to state and easy to fake.

The claim is that a Merkle-path verifier discards only the records that were
tampered with, where an accumulator-based verifier discards the whole response.
There are two ways to produce that figure dishonestly, and a test for each:

* **Count the tampered records instead of the rejected ones.** Then the figure is
  the sweep variable plotted against itself, and would look identical for a
  scheme with no granularity at all. ``measure`` therefore reports the number
  actually rejected and cross-checks it against the number tampered -- the tests
  below drive that cross-check from both sides.
* **Tamper in a way that trips a malformed-bundle path** rather than a detected
  tamper. Those are different code paths; only the second is what Phase VIII
  Step 1 exists to catch.

The t=0 case is pinned here rather than swept, because the figure is log-log.
It is also where a false-positive rejection would first show up.

This file replaces ``test_exp9_granularity.py``. Experiment 9 was folded into
Experiment 4 on 2026-09-12: Section VI defines no Experiment 9, it defines one
Experiment 4 whose figure has two panels over two variables.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from Schemes.ma_lb_pq_vdse.src import config as config_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as exp_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import psa_experiments as psa  # noqa: E402

CONFIG = config_mod.load()

#: Small enough to build in a test, large enough that "discard everything" and
#: "discard exactly t" are distinguishable. The campaign's pinned 20,000 is
#: exercised by the run, not by every test.
TEST_RETURNED = 200


def _arm(returned: int = TEST_RETURNED):
    """The granularity arm with its result-set size shrunk for testing."""
    arm = psa.PsaExp4Granularity(
        config=CONFIG, source=exp_mod.SyntheticRecordSource()
    )
    # `result_set_size` reads global.yaml's pinned 20,000; override the instance
    # so a test does not spend a campaign's worth of setup.
    object.__setattr__(arm, "_test_returned", returned)
    type(arm).result_set_size = property(lambda self: self._test_returned)
    return arm


# ---------------------------------------------------------------------------
# The arm is registered as part of Experiment 4, not as an experiment
# ---------------------------------------------------------------------------
def test_granularity_is_an_arm_of_experiment_four():
    assert "granularity" in psa.PSA_EXP4_VARIANTS
    arm = psa.build(4, CONFIG, variant="granularity",
                    source=exp_mod.SyntheticRecordSource())
    assert isinstance(arm, psa.PsaExp4Granularity)
    assert arm.number == 4, "the arm must not claim an experiment number of its own"


def test_there_is_no_experiment_nine():
    """Section VI defines eight experiments. Nine would be one we invented."""
    from Schemes.ma_lb_pq_vdse.src import main as main_mod

    assert 9 not in main_mod.FOLDERS
    assert 9 not in psa.PSA_EXPERIMENTS


def test_the_two_arms_sweep_different_variables():
    """One figure, two panels, two variables — that is why they are two arms."""
    default = psa.build(4, CONFIG, source=exp_mod.SyntheticRecordSource())
    arm = psa.build(4, CONFIG, variant="granularity",
                    source=exp_mod.SyntheticRecordSource())
    assert default.variable == "returned_results"
    assert arm.variable == "tampered_records"
    assert default.values != arm.values


# ---------------------------------------------------------------------------
# What the arm reports
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("tampered", [1, 3, 17])
def test_discards_exactly_the_tampered_records(tampered):
    """The headline claim, driven from the sweep side."""
    arm = _arm()
    prepared = arm.prepare(tampered)
    sample = arm.measure(prepared)
    assert sample.primary == float(tampered), (
        "records discarded must equal records tampered: fewer is an undetected "
        "tamper, more is a discarded intact record"
    )
    assert sample.secondaries["tampered_localised"] == float(tampered)


@pytest.mark.parametrize("tampered", [1, 3, 17])
def test_retains_every_untampered_record(tampered):
    """The other half: granularity is worthless if it discards the good ones."""
    arm = _arm()
    prepared = arm.prepare(tampered)
    sample = arm.measure(prepared)
    assert sample.secondaries["usable_recovered"] == float(
        TEST_RETURNED - tampered
    )


def test_zero_tampering_rejects_nothing():
    """Pinned rather than swept: the figure is log-log and cannot draw t=0.

    This is where a false-positive rejection would first appear.
    """
    arm = _arm()
    sample = arm.measure(arm.prepare(0))
    assert sample.primary == 0.0
    assert sample.secondaries["usable_recovered"] == float(TEST_RETURNED)


def test_reports_rejections_not_the_sweep_variable():
    """Guard against plotting the variable against itself.

    If ``measure`` returned the tamper count it was handed, the figure would be
    a straight line for ANY scheme, including one with no granularity at all.
    Tampering with a count the arm was not told about must still be detected.
    """
    arm = _arm()
    prepared = arm.prepare(2)
    # Corrupt two MORE bundles behind the arm's back. `prepared["tampered"]`
    # still says 2, so a faithful `measure` now sees 4 and must raise rather
    # than report the 2 it was told.
    bundles = list(prepared["bundles"])
    extra = [i for i in range(len(bundles))][-2:]
    for i in extra:
        bundles[i] = psa._flip_token_byte(bundles[i])
    prepared["bundles"] = tuple(bundles)
    with pytest.raises(RuntimeError, match="neither sound nor complete"):
        arm.measure(prepared)


def test_the_tamper_is_detected_not_merely_malformed():
    """A corrupted token must fail verification, not fail to parse.

    Phase VIII Step 1 exists to catch a bundle whose leaf does not match the
    entry it names. A tamper that instead produced an unparseable bundle would
    exercise a different code path and measure the wrong thing.
    """
    from Schemes.ma_lb_pq_vdse.src.psa import verify as psa_verify

    arm = _arm(returned=8)
    prepared = arm.prepare(0)
    good = prepared["bundles"][0]
    bad = psa._flip_token_byte(good)
    assert bad.cid == good.cid, "the tamper must leave the bundle well-formed"
    checker = psa._psa_batched_chain_checker(
        prepared["ledger"], prepared["cids"]
    )
    result = psa_verify.verify_bundle(bad, chain_check=checker)
    assert not result.accepted, "a flipped token byte must be rejected"


def test_secondaries_match_the_declared_metric_names():
    """The plotter checks panel labels against these names before drawing."""
    arm = _arm(returned=8)
    sample = arm.measure(arm.prepare(1))
    assert set(sample.secondaries) == {m.name for m in arm.secondaries}
