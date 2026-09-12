"""D6-D9 — the policy-state-aware experiment track.

These pin the SHAPE of each experiment, not its latency: timings depend on the
host, and the whole point of the track is to be run on the campaign host where
the Option D numbers were taken. What is asserted here is what a number means —
that ``|T_Q| = q·|P_U|`` really is the token count, that Exp. 6's arms differ in
the way §VI says they do, that non-interference actually excludes work.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

import pytest  # noqa: E402

from Schemes.ma_lb_pq_vdse.src import config as scheme_config  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import psa_experiments as psa  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import main as main_mod  # noqa: E402


@pytest.fixture(scope="module")
def config():
    return scheme_config.load()


@pytest.fixture
def source():
    """The record source every corpus-backed PSA experiment needs.

    Exp. 1 became corpus-backed when it stopped inventing `kw:00000` keywords
    and `hospital/pol0` policies, so it now takes the same source Exp. 2 does.
    """
    from Schemes.ma_lb_pq_vdse.src.harness import experiments as option_d_mod

    return option_d_mod.SyntheticRecordSource()


def _run(experiment, value):
    return experiment.measure(experiment.prepare(value))


# ===========================================================================
# D7 — |T_Q| = q·|P_U|
# ===========================================================================
def test_exp1_token_count_is_the_product(config, source):
    """|T_Q| = q*|P_U| on every point of every arm."""
    for variant in psa.PSA_EXP1_VARIANTS:
        experiment = psa.build(1, config, variant=variant, source=source)
        scope = psa.policy_scope_of(variant)
        for q in experiment.values:
            sample = _run(experiment, q)
            assert sample.secondaries["tokens"] == q * scope
            assert sample.secondaries["keywords"] == q
            assert sample.secondaries["policies"] == scope


def test_exp1_sweeps_both_manuscript_dimensions(config, source):
    """§VI: "q is varied as {1,5,10,15,20} while |P_U| is varied as {1,2,4,8}".

    q is the sweep and |P_U| is the ARM, so the two dimensions are the sweep
    values and the variant list respectively -- one curve per scope, which is
    how a reader expects a two-variable sweep to be drawn.
    """
    experiment = psa.PsaExp1TokenGeneration(config=config, source=source)
    assert experiment.variable == "keywords"
    assert set(experiment.values) == set(config.experiment("exp1").values)
    assert {psa.policy_scope_of(v) for v in psa.PSA_EXP1_VARIANTS} == set(
        psa.POLICY_SCOPES
    )


def test_exp1_arms_scale_the_curve_by_exactly_their_scope(config, source):
    """The identity, read across arms rather than along one.

    At a fixed q, doubling |P_U| must double |T_Q|. That is the whole content
    of |T_Q| = q|P_U|, and it is what makes the four curves parallel on the
    log axis instead of converging.
    """
    baseline = psa.build(1, config, variant="pu1", source=source)
    for variant in psa.PSA_EXP1_VARIANTS:
        experiment = psa.build(1, config, variant=variant, source=source)
        scope = psa.policy_scope_of(variant)
        for q in experiment.values:
            one = _run(baseline, q).secondaries["tokens"]
            many = _run(experiment, q).secondaries["tokens"]
            assert many == one * scope


def test_exp1_default_arm_is_the_singleton_scope(config, source):
    """An unparameterised build must not silently pick a scope."""
    assert psa.PsaExp1TokenGeneration(config=config, source=source).policy_scope == 1


def test_exp1_rejects_an_unknown_arm(config, source):
    with pytest.raises(ValueError, match="unknown PSA Exp. 1 variant"):
        psa.build(1, config, variant="round_robin", source=source)


def test_exp1_tokens_are_distinct(config, source):
    """q·|P_U| COLLIDING tokens would be q·|P_U| lookups of the same posting list.

    Takes `source` because Exp. 1 became corpus-backed in 5143ee7 -- it reads
    the corpus for its policies and keyword vocabulary instead of inventing
    them. Every other test in this file was given the fixture in that commit;
    this one was missed and raised `ValueError: psa experiment 1 reads the
    corpus and needs a record source`.
    """
    experiment = psa.build(
        1, config, variant=psa.PSA_EXP1_VARIANTS[-1], source=source
    )
    prepared = experiment.prepare(max(experiment.values))
    from Schemes.ma_lb_pq_vdse.src.psa import tokens as psa_tokens

    produced = psa_tokens.generate_query_tokens(
        prepared["scheme"], prepared["keywords"], prepared["scopes"]
    )
    assert len(set(produced)) == len(produced)


# ===========================================================================
# §VI Exp. 3 — the LATENCY figure the manuscript includes
# ===========================================================================
def test_psa_exp3_latency_is_the_registered_experiment_3(config):
    """§VI Fig. 3 plots latency, so experiment 3 must be the latency one.

    The track once registered a token-count experiment at 3, which left the
    manuscript's Fig. 3 with no source. That companion was removed entirely on
    2026-09-12 -- Section VI does not define it, and with the `psa_` prefix gone
    it would have needed a name implying it was one of the paper's experiments.
    The property it measured is still covered, on the search path, by
    ``test_psa_exp3_latency_issues_q_times_d_tokens``.
    """
    assert psa.PSA_EXPERIMENTS[3] is psa.PsaExp3CrossDomainLatency
    assert main_mod.PSA_FOLDERS[3] == "exp3_crossdomain_scalability"
    # Section VI defines eight experiments. Anything past 8 is one we invented.
    assert max(psa.PSA_EXPERIMENTS) == 8
    assert 9 not in psa.PSA_EXPERIMENTS


def test_psa_exp3_latency_issues_q_times_d_tokens(config, source):
    """|T_Q| = q*|P_U| with one authorized policy per participating domain.

    This is D9 priced on the search path rather than asserted: Option D issues
    q tokens whatever d is, the policy-bound token issues q*d.
    """
    experiment = psa.PsaExp3CrossDomainLatency(
        config=config, source=source
    )
    q = config.defaults.keywords_per_query
    issued = {}
    for d in (2, 4):
        prepared = experiment.prepare(d)
        sample = experiment.measure(prepared)
        issued[d] = sample.secondaries["tokens_issued"]
        assert sample.secondaries["nodes_searched"] >= 1
    assert issued[2] == q * 2, issued
    assert issued[4] == q * 4, issued
    assert issued[4] > issued[2], (
        "a policy-bound token names its domain, so a wider cross-domain query "
        "cannot reuse one trapdoor"
    )




# ===========================================================================
# D1 — re-tokenization is real work
# ===========================================================================
def test_exp5_retokenizes_and_rebuilds(config, source):
    experiment = psa.PsaExp5ReTokenization(config=config, source=source)
    sample = _run(experiment, experiment.values[0])
    assert sample.secondaries["entries_retokenized"] > 0
    assert sample.secondaries["commitments_rebuilt"] > 0
    assert sample.secondaries["merkle_nodes_recomputed"] > 0


def test_exp5_work_grows_with_k(config, source):
    experiment = psa.PsaExp5ReTokenization(config=config, source=source)
    small = _run(experiment, experiment.values[0])
    large = _run(experiment, experiment.values[1])
    assert (
        large.secondaries["entries_retokenized"]
        > small.secondaries["entries_retokenized"]
    )


def test_exp5_skips_records_no_governing_authority_touched(config, source):
    """eq:unaffected-policy, as an absence of work rather than an assertion."""
    experiment = psa.PsaExp5ReTokenization(config=config, source=source)
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
def test_exp6_sweeps_the_ratio_not_an_update_count(config, source):
    """The axis that D8 is about."""
    experiment = psa.PsaExp6AffectedRatio(config=config, source=source)
    assert experiment.variable == "affected_policy_ratio"
    assert experiment.values == psa.AFFECTED_RATIOS
    assert min(experiment.values) == pytest.approx(0.1)
    assert max(experiment.values) == pytest.approx(1.0)


def _records_under_affected(experiment, ratio):
    """The records the dependency chain reaches at this ratio, counted exactly.

    `AA_k -> P_k^aff -> R_k^aff`. Derived from the prepared state rather than
    from `ratio * policy_population`, which was only the record count while the
    arm synthesised one record per policy.
    """
    prepared = experiment.prepare(ratio)
    policies = sorted({r["policy"] for r in prepared["records"]})
    affected = set(policies[: prepared["affected_count"]])
    return sum(1 for r in prepared["records"] if r["policy"] in affected)


def test_exp6_dias_evolves_only_the_affected_fraction(config, source):
    """DIAS touches exactly the records under the affected policies.

    Was `round(ratio * policy_population)` -- true only when each policy held
    one synthetic record. On real corpus records the policies carry different
    numbers of records (the patient-hash buckets are uneven), so the expected
    count is the actual size of `R_k^aff` and not a fraction of the policy
    count.
    """
    experiment = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_DIAS, source=source)
    for ratio in experiment.values:
        evolved = _run(experiment, ratio).secondaries["records_evolved"]
        assert evolved == pytest.approx(_records_under_affected(experiment, ratio), abs=1)


def test_exp6_full_state_ignores_the_ratio(config, source):
    """Its cost is flat because it re-evolves everything however little changed."""
    experiment = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_FULL_STATE, source=source)
    evolved = {
        _run(experiment, ratio).secondaries["records_evolved"]
        for ratio in experiment.values
    }
    # One value across every ratio -- that flatness IS the property. The value
    # is the whole drawn population; it was `policy_population` only while the
    # arm held one record per policy.
    assert len(evolved) == 1, f"full_state must be flat in the ratio, got {evolved}"
    assert evolved == {float(len(experiment.prepare(0.1)["records"]))}


def test_exp6_dias_and_incremental_all_do_equal_work_but_differ_on_the_wire(config, source):
    """The two halves of the claim, separated.

    Incremental-All ablates SELECTIVE delivery only: it evolves exactly the same
    policies as DIAS and differs solely in fan-out. If the two ever differ in
    `records_evolved`, the arm has stopped being an ablation of one variable.
    """
    dias = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_DIAS, source=source)
    everyone = psa.PsaExp6AffectedRatio(
        config=config, variant=psa.VARIANT_INCREMENTAL_ALL, source=source
    )
    for ratio in dias.values:
        a, b = _run(dias, ratio), _run(everyone, ratio)
        assert a.secondaries["records_evolved"] == b.secondaries["records_evolved"]
        assert a.secondaries["entries_retokenized"] == b.secondaries["entries_retokenized"]
        assert b.secondaries["delivered_kb"] > a.secondaries["delivered_kb"]


def test_exp6_dias_advantage_over_full_state_narrows_toward_one(config, source):
    """§VI: the advantage "narrows because a larger portion becomes dependency
    relevant". At 100% the two must coincide in work."""
    dias = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_DIAS, source=source)
    full = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_FULL_STATE, source=source)

    def advantage(ratio):
        """How many times more policies Full-State evolves than DIAS."""
        return (
            _run(full, ratio).secondaries["records_evolved"]
            / _run(dias, ratio).secondaries["records_evolved"]
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
def test_corpus_backed_experiments_refuse_to_run_without_a_source(config):
    """Exp. 2 reads the corpus, so it cannot be built from config alone.

    Silently falling back to an invented world is exactly the defect the
    corpus seam exists to close -- it would produce a plausible curve from
    data the paper never claims.
    """
    for number in (1, 2):
        with pytest.raises(ValueError, match="needs a record source"):
            psa.build(number, config)


def test_build_refuses_an_unknown_experiment(config):
    # Every experiment Section VI defines now has a psa form -- Exp. 9 was the
    # last holdout and was folded into Exp. 4 on 2026-09-12. So the subject is
    # no longer "which number lacks a form" but "an unknown number is refused",
    # which is what the guard is actually for.
    uncovered = sorted(set(main_mod.FOLDERS) - set(psa.PSA_EXPERIMENTS))
    assert not uncovered, (
        f"experiments {uncovered} have no psa form; every number main.py "
        f"offers must be buildable"
    )
    # A number that is not in the registry at all must be refused rather than
    # silently building something else.
    unknown = max(psa.PSA_EXPERIMENTS) + 1
    with pytest.raises(KeyError, match="no policy-state-aware experiment"):
        psa.build(unknown, config)


@pytest.mark.parametrize("number", sorted(psa.PSA_EXPERIMENTS))
def test_every_registered_experiment_runs(number, config):
    from Schemes.ma_lb_pq_vdse.src.harness import experiments as option_d_mod

    experiment = psa.build(
        number, config, source=option_d_mod.SyntheticRecordSource()
    )
    sample = _run(experiment, experiment.values[0])
    assert sample.primary >= 0.0
    assert set(sample.secondaries) == {m.name for m in experiment.secondaries}
