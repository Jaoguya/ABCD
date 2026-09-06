"""D6-D9 — the policy-state-aware experiment track.

These pin the SHAPE of each experiment, not its latency: timings depend on the
host, and the whole point of the track is to be run on the campaign host where
the Option D numbers were taken. What is asserted here is what a number means —
that ``|T_Q| = q·|P_U|`` really is the token count, that Exp. 6's arms differ in
the way §V says they do, that non-interference actually excludes work.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

import pytest  # noqa: E402

from Schemes.ma_lb_pq_vdse.src import config as scheme_config  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import psa_experiments as psa  # noqa: E402


@pytest.fixture(scope="module")
def config():
    return scheme_config.load()


def _run(experiment, value):
    return experiment.measure(experiment.prepare(value))


# ===========================================================================
# D7 — |T_Q| = q·|P_U|
# ===========================================================================
def test_exp1_token_count_is_the_product(config):
    """|T_Q| = q*|P_U| on every point of every arm."""
    for variant in psa.PSA_EXP1_VARIANTS:
        experiment = psa.build(1, config, variant=variant)
        scope = psa.policy_scope_of(variant)
        for q in experiment.values:
            sample = _run(experiment, q)
            assert sample.secondaries["tokens"] == q * scope
            assert sample.secondaries["keywords"] == q
            assert sample.secondaries["policies"] == scope


def test_exp1_sweeps_both_manuscript_dimensions(config):
    """§V: "q is varied as {1,5,10,15,20} while |P_U| is varied as {1,2,4,8}".

    q is the sweep and |P_U| is the ARM, so the two dimensions are the sweep
    values and the variant list respectively -- one curve per scope, which is
    how a reader expects a two-variable sweep to be drawn.
    """
    experiment = psa.PsaExp1TokenGeneration(config=config)
    assert experiment.variable == "keywords"
    assert set(experiment.values) == set(config.experiment("exp1").values)
    assert {psa.policy_scope_of(v) for v in psa.PSA_EXP1_VARIANTS} == set(
        psa.POLICY_SCOPES
    )


def test_exp1_arms_scale_the_curve_by_exactly_their_scope(config):
    """The identity, read across arms rather than along one.

    At a fixed q, doubling |P_U| must double |T_Q|. That is the whole content
    of |T_Q| = q|P_U|, and it is what makes the four curves parallel on the
    log axis instead of converging.
    """
    baseline = psa.build(1, config, variant="pu1")
    for variant in psa.PSA_EXP1_VARIANTS:
        experiment = psa.build(1, config, variant=variant)
        scope = psa.policy_scope_of(variant)
        for q in experiment.values:
            one = _run(baseline, q).secondaries["tokens"]
            many = _run(experiment, q).secondaries["tokens"]
            assert many == one * scope


def test_exp1_default_arm_is_the_singleton_scope(config):
    """An unparameterised build must not silently pick a scope."""
    assert psa.PsaExp1TokenGeneration(config=config).policy_scope == 1


def test_exp1_rejects_an_unknown_arm(config):
    with pytest.raises(ValueError, match="unknown PSA Exp. 1 variant"):
        psa.build(1, config, variant="round_robin")


def test_exp1_tokens_are_distinct(config):
    """q·|P_U| COLLIDING tokens would be q·|P_U| lookups of the same posting list."""
    experiment = psa.build(1, config, variant=psa.PSA_EXP1_VARIANTS[-1])
    prepared = experiment.prepare(max(experiment.values))
    from Schemes.ma_lb_pq_vdse.src.psa import tokens as psa_tokens

    produced = psa_tokens.generate_query_tokens(
        prepared["scheme"], prepared["keywords"], prepared["scopes"]
    )
    assert len(set(produced)) == len(produced)


# ===========================================================================
# D9 — the single-trapdoor property does not survive
# ===========================================================================
def test_exp3_token_count_grows_with_domains(config):
    experiment = psa.PsaExp3CrossDomainTokens(config=config)
    issued = [
        _run(experiment, d).secondaries["tokens_issued"] for d in experiment.values
    ]
    assert issued == sorted(issued)
    assert issued[-1] > issued[0], (
        "under eq:policy-bound-token a token names its domain, so a query over "
        "more domains cannot reuse one trapdoor"
    )


def test_exp3_reports_the_option_d_baseline_alongside(config):
    """The panel's whole content is the contrast with a constant 1."""
    experiment = psa.PsaExp3CrossDomainTokens(config=config)
    for d in experiment.values:
        sample = _run(experiment, d)
        assert sample.secondaries["option_d_tokens_issued"] == 1.0
        assert sample.secondaries["tokens_issued"] >= sample.secondaries["policies"]


# ===========================================================================
# D1 — re-tokenization is real work
# ===========================================================================
def test_exp5_retokenizes_and_rebuilds(config):
    experiment = psa.PsaExp5ReTokenization(config=config)
    sample = _run(experiment, experiment.values[0])
    assert sample.secondaries["entries_retokenized"] > 0
    assert sample.secondaries["commitments_rebuilt"] > 0
    assert sample.secondaries["merkle_nodes_recomputed"] > 0


def test_exp5_work_grows_with_k(config):
    experiment = psa.PsaExp5ReTokenization(config=config)
    small = _run(experiment, experiment.values[0])
    large = _run(experiment, experiment.values[1])
    assert (
        large.secondaries["entries_retokenized"]
        > small.secondaries["entries_retokenized"]
    )


def test_exp5_skips_records_no_governing_authority_touched(config):
    """eq:unaffected-policy, as an absence of work rather than an assertion."""
    experiment = psa.PsaExp5ReTokenization(config=config)
    prepared = experiment.prepare(experiment.values[-1])
    world = prepared["world"]
    moved = sorted(world.authorities.values())[0]
    dependent = sum(
        1 for r in prepared["records"]
        if moved in world.governance.governing(r["policy"])
    )
    assert 0 < dependent < len(prepared["records"]), (
        "the fixture must contain BOTH dependent and independent records, or "
        "the skip path is never exercised"
    )


# ===========================================================================
# D8 — Exp. 6 over the affected-policy ratio
# ===========================================================================
def test_exp6_sweeps_the_ratio_not_an_update_count(config):
    """The axis that D8 is about."""
    experiment = psa.PsaExp6AffectedRatio(config=config)
    assert experiment.variable == "affected_policy_ratio"
    assert experiment.values == psa.AFFECTED_RATIOS
    assert min(experiment.values) == pytest.approx(0.1)
    assert max(experiment.values) == pytest.approx(1.0)


def test_exp6_dias_evolves_only_the_affected_fraction(config):
    experiment = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_DIAS)
    for ratio in experiment.values:
        sample = _run(experiment, ratio)
        evolved = sample.secondaries["policies_evolved"]
        expected = round(ratio * experiment.policy_population)
        assert evolved == pytest.approx(expected, abs=1)


def test_exp6_full_state_ignores_the_ratio(config):
    """Its cost is flat because it re-evolves everything however little changed."""
    experiment = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_FULL_STATE)
    evolved = {
        _run(experiment, ratio).secondaries["policies_evolved"]
        for ratio in experiment.values
    }
    assert evolved == {float(experiment.policy_population)}


def test_exp6_dias_and_incremental_all_do_equal_work_but_differ_on_the_wire(config):
    """The two halves of the claim, separated.

    Incremental-All ablates SELECTIVE delivery only: it evolves exactly the same
    policies as DIAS and differs solely in fan-out. If the two ever differ in
    `policies_evolved`, the arm has stopped being an ablation of one variable.
    """
    dias = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_DIAS)
    everyone = psa.PsaExp6AffectedRatio(
        config=config, variant=psa.VARIANT_INCREMENTAL_ALL
    )
    for ratio in dias.values:
        a, b = _run(dias, ratio), _run(everyone, ratio)
        assert a.secondaries["policies_evolved"] == b.secondaries["policies_evolved"]
        assert a.secondaries["entries_retokenized"] == b.secondaries["entries_retokenized"]
        assert b.secondaries["delivered_kb"] > a.secondaries["delivered_kb"]


def test_exp6_dias_advantage_over_full_state_narrows_toward_one(config):
    """§V: the advantage "narrows because a larger portion becomes dependency
    relevant". At 100% the two must coincide in work."""
    dias = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_DIAS)
    full = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_FULL_STATE)

    def advantage(ratio):
        """How many times more policies Full-State evolves than DIAS."""
        return (
            _run(full, ratio).secondaries["policies_evolved"]
            / _run(dias, ratio).secondaries["policies_evolved"]
        )

    low, high = advantage(0.1), advantage(1.0)
    assert low > high, "the DIAS advantage must shrink as the ratio grows"
    assert high == pytest.approx(1.0), "at 100% every policy is dependency-relevant"


def test_exp6_rejects_an_unknown_arm(config):
    with pytest.raises(ValueError, match="unknown PSA Exp. 6 variant"):
        psa.PsaExp6AffectedRatio(config=config, variant="round_robin")


# ===========================================================================
# Registry
# ===========================================================================
def test_build_refuses_an_experiment_with_no_psa_form(config):
    with pytest.raises(KeyError, match="no policy-state-aware experiment"):
        psa.build(2, config)


@pytest.mark.parametrize("number", sorted(psa.PSA_EXPERIMENTS))
def test_every_registered_experiment_runs(number, config):
    experiment = psa.build(number, config)
    sample = _run(experiment, experiment.values[0])
    assert sample.primary >= 0.0
    assert set(sample.secondaries) == {m.name for m in experiment.secondaries}
