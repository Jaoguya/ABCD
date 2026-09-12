"""What a PSA sweep value MEANS — the unit checks the shape tests do not make.

``test_psa_experiments.py`` pins that each experiment reports the right
quantities and that the arms differ in the right direction. It does not pin
that the x-axis value is the amount of work actually done, and that is exactly
where this track went wrong once already: ``PsaExp5ReTokenization`` sized its
record pool at ``ceil(k / |W_i|)`` while ``measure`` skipped every record no
governing authority touched, so a point labelled ``k`` retokenized ``0.500 k``
entries at every sweep point under the default 2-of-4 ``AA(PID)``.

That is the same class of defect as ``d1cdf9c`` (Exp. 4's ``r`` counted index
entries, not returned records) and the 2026-09-05 Exp. 9 fix (the sweep counted
entries where the baselines counted documents): the number is plausible, the
figure renders, and the axis quietly means something other than what the
caption says. global.yaml records both. These tests are the guard for the third
instance.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

import pytest  # noqa: E402

from Schemes.ma_lb_pq_vdse.src import config as scheme_config  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as option_d  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import psa_experiments as psa  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.psa import records as psa_records  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.psa import verify as psa_verify_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import psa_experiments as psa_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.scheduler import aass as aass_mod  # noqa: E402


@pytest.fixture(scope="module")
def config():
    return scheme_config.load()


@pytest.fixture
def source():
    """The record source the corpus-backed PSA experiments need.

    Exps. 3, 4 and 5 became corpus-backed on 2026-09-10 when they stopped
    inventing `kw:00042` keywords and `hospital/pol0` policies. Exp. 6 takes one
    for its vocabulary but stipulates its policy topology, so it is not
    CORPUS_BACKED — see `PsaExp6AffectedRatio.policy_population`.
    """
    from Schemes.ma_lb_pq_vdse.src.harness import experiments as option_d_mod

    return option_d_mod.SyntheticRecordSource()


# ===========================================================================
# Exp. 5 — the swept k must be the work done, in BOTH constructions
# ===========================================================================
@pytest.mark.parametrize("k", [100, 1000])
def test_psa_exp5_retokenizes_the_k_it_was_asked_for(config, source, k):
    """The x-axis is (keyword, document) pairs; so must the work be.

    Sized by affected entries rather than by total entries: records whose
    policy no governing authority touches are still built (the skip path is
    part of what Exp. 5 times) but do not count toward ``k``.
    """
    experiment = psa.PsaExp5ReTokenization(config=config, source=source)
    sample = experiment.measure(experiment.prepare(k))
    applied = sample.secondaries["entries_retokenized"]
    assert applied >= k, (
        f"the sweep asked for k={k} but only {applied:.0f} entries were "
        f"retokenized; the curve is plotted against k, so the point would "
        f"understate the cost of D1 by k/{applied:.0f}x"
    )
    # One record's worth of overshoot is unavoidable: entries arrive |W_i| at
    # a time. More than that means the pool is being oversized.
    assert applied < k + experiment.keywords_per_record


def test_psa_exp5_still_exercises_the_unaffected_path(config, source):
    """Sizing by affected entries must not turn the pool all-dependent.

    If every record were governed by the moved authority, eq:unaffected-policy
    would never be taken and Exp. 5 would silently stop measuring the skip.
    """
    experiment = psa.PsaExp5ReTokenization(config=config, source=source)
    prepared = experiment.prepare(experiment.values[0])
    world = prepared["world"]
    moved = sorted(world.authorities.values())[0]
    dependent = sum(
        1 for r in prepared["records"]
        if moved in world.governance.governing(r["policy"])
    )
    assert 0 < dependent < len(prepared["records"])


@pytest.mark.parametrize("k", [100, 1000])
def test_both_constructions_agree_on_what_one_pair_of_exp5_is(config, source, k):
    """The cross-check that makes the two Exp. 5 curves comparable.

    ``psa/__init__.py`` says the two curves "against the same ``k``" are the
    price of D1. They are only that if ``k`` buys the same amount of work in
    both.

    COMPARED AGAINST `replica_writes`, NOT `entries_retokenized`. Option D's
    `entries_rewritten` comes from `dias.synchronize()`, which writes every
    node holding the shard, so at replication 2 it counts 204 physical writes
    at k=100. The PSA arm recomputes `T'` once per entry -- the token does not
    depend on which node stores it -- so its LOGICAL count is 102. Comparing
    those two was comparing physical work with logical work, and it only looked
    right while replication was 1 and the two coincided.
    """
    theirs = option_d.build_experiment(
        5, config, option_d.SyntheticRecordSource()
    )
    ours = psa.PsaExp5ReTokenization(config=config, source=source)
    rewritten = theirs.measure(theirs.prepare(k)).secondaries["entries_rewritten"]
    mine = ours.measure(ours.prepare(k)).secondaries
    assert abs(rewritten - mine["replica_writes"]) <= ours.keywords_per_record, (
        f"at k={k} Option D rewrites {rewritten:.0f} entries and the PSA arm "
        f"writes {mine['replica_writes']:.0f}; the two Exp. 5 curves share an "
        f"x-axis and would be compared at different amounts of work"
    )
    # And the logical count must stay BELOW the physical one at replication > 1,
    # or the replica fan-out has been folded into the token recomputation.
    if config.index.replication > 1:
        assert mine["entries_retokenized"] < mine["replica_writes"], (
            "entries_retokenized should count T' recomputations (once per "
            "entry) and replica_writes the per-holder stores; equal values mean "
            "one has been substituted for the other"
        )


# ===========================================================================
# Exp. 6 — what the PRIMARY metric can and cannot separate
# ===========================================================================
def test_psa_exp6_arms_rank_the_way_the_manuscript_says(config, source):
    """§VI Exp. 6, as an ordering the figure must show.

    The manuscript defines three configurations and claims a strict ranking:
    Full-State "processes substantially more state"; Incremental-All "reduces
    state-reconstruction overhead but still incurs unnecessary propagation";
    DIAS does neither. So DIAS <= Incremental-All <= Full-State at a low ratio.

    This did not hold when the arms differed only by a MULTIPLIER on a byte
    counter: `dias` and `incremental_all` then did identical timed work and
    their curves coincided, leaving the selective half of the claim with no
    evidence in the primary metric. The arms now deliver to real `_PsaShard`
    recipients that ingest the message, so the extra fan-out is work.
    """
    def arm(variant, ratio):
        import statistics
        experiment = psa.PsaExp6AffectedRatio(config=config, variant=variant, source=source)
        prepared = experiment.prepare(ratio)
        for _ in range(2):
            experiment.measure(prepared)          # warm
        latency = statistics.median(
            experiment.measure(prepared).primary for _ in range(9)
        )
        return latency, experiment.measure(prepared).secondaries["delivered_kb"]

    dias, dias_kb = arm(psa.VARIANT_DIAS, 0.1)
    everyone, everyone_kb = arm(psa.VARIANT_INCREMENTAL_ALL, 0.1)
    full, full_kb = arm(psa.VARIANT_FULL_STATE, 0.1)

    # SELECTIVE PROPAGATION, asserted on DELIVERED PAYLOAD -- where the claim
    # actually holds. Measured: 3.52 / 14.06 / 141.05 KB, i.e. a clean 4x from
    # the 1-vs-4 FSN fan-out and 40x for full reconstruction, identical across
    # repeated runs.
    assert dias_kb < everyone_kb < full_kb, (
        f"selective propagation must send less: DIAS {dias_kb:.2f} KB vs "
        f"Incremental-All {everyone_kb:.2f} KB vs Full-State {full_kb:.2f} KB"
    )

    # INCREMENTAL EVOLUTION, asserted on latency -- an 11x gap that reproduces.
    assert everyone < full, (
        f"full state reconstruction must dominate: Incremental-All "
        f"{everyone:.3f} ms vs Full-State {full:.3f} ms"
    )

    # DIAS vs Incremental-All in LATENCY is deliberately NOT asserted.
    #
    # It used to be, and the test failed ~15% of the time (measured: 8/10 and
    # 9/10 passes over ten isolated runs at two different commits) -- because
    # the two do the same sender-side work and differ only in how many local
    # recipients they hand a message to. The measured gap is ~2%
    # (0.9425 vs 0.9645 ms), i.e. noise, which `generate_plots.py` also records
    # ("the campaign measured +2%, a local rerun measured -4.5%").
    #
    # A 15%-flaky assertion is worse than none: it makes every regression run
    # ambiguous and trains a reader to re-run until green. The claim it was
    # trying to make is real, and it is the payload assertion above.
    # SV must therefore say the selective advantage is in BYTES, not in time.


def test_psa_exp6_dias_advantage_narrows_toward_a_full_ratio(config, source):
    """§VI: the advantage "narrows because a larger portion of the system
    becomes dependency relevant".

    Asserted on the WORK DONE, which is exact, rather than on latency, which is
    not. This compared median latencies with `rel=0.35` and failed ~7% of the
    time (14/15 in isolation) — the second timing-ratio assertion in this file
    to do so. Measured, the work ratios are integers:

        records_evolved     full/dias = 10.000 @0.1  ->  1.000 @1.0
        entries_retokenized  full/dias = 10.000 @0.1  ->  1.000 @1.0

    At ratio 1.0 the two arms evolve exactly the same set (40 policies, 240
    entries), so the ratio is exactly 1 — which is what §VI's sentence claims,
    stated as a fact about work rather than a hope about a clock.

    NOTE FOR §V: the narrowing is NOT total. `delivered_kb` goes 40.1x -> 4.0x,
    because at 100% DIAS still delivers selectively where Full-State republishes
    every authority's commitment to every FSN. The INCREMENTAL advantage
    vanishes at a full ratio; the SELECTIVE advantage does not.
    """
    def work_at(affected):
        out = {}
        for variant in (psa.VARIANT_DIAS, psa.VARIANT_FULL_STATE):
            experiment = psa.PsaExp6AffectedRatio(config=config, variant=variant, source=source)
            prepared = experiment.prepare(affected)
            out[variant] = experiment.measure(prepared).secondaries
        return out

    sparse, full = work_at(0.1), work_at(1.0)
    for metric in ("records_evolved", "entries_retokenized"):
        sparse_ratio = (sparse[psa.VARIANT_FULL_STATE][metric]
                        / sparse[psa.VARIANT_DIAS][metric])
        full_ratio = (full[psa.VARIANT_FULL_STATE][metric]
                      / full[psa.VARIANT_DIAS][metric])
        assert sparse_ratio > full_ratio, (
            f"{metric}: the DIAS advantage must narrow as the affected ratio "
            f"grows, got {sparse_ratio:.3f} at 0.1 and {full_ratio:.3f} at 1.0"
        )
        assert full_ratio == pytest.approx(1.0), (
            f"{metric}: at a full ratio both arms evolve the same set, so the "
            f"ratio must be exactly 1, got {full_ratio}"
        )

    # The selective advantage SURVIVES a full ratio -- see the note above.
    assert (full[psa.VARIANT_FULL_STATE]["delivered_kb"]
            > full[psa.VARIANT_DIAS]["delivered_kb"]), (
        "at ratio 1.0 DIAS still delivers selectively where Full-State "
        "republishes to every FSN; that advantage does not narrow"
    )


def test_psa_exp6_fsns_touched_is_the_affected_node_set(config, source):
    """``F_k^aff``, the last link of the dependency chain — DISTINCT nodes.

    It accumulated `fan_out` per evolved policy before, reporting 160 "FSNs
    touched" on a four-node deployment. Option D's metric of the same name
    counts nodes, so the two were not the same quantity under one label.
    """
    dias = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_DIAS, source=source)
    everyone = psa.PsaExp6AffectedRatio(
        config=config, variant=psa.VARIANT_INCREMENTAL_ALL, source=source
    )
    for ratio in dias.values:
        selective = dias.measure(dias.prepare(ratio)).secondaries["fsns_touched"]
        broadcast = everyone.measure(
            everyone.prepare(ratio)
        ).secondaries["fsns_touched"]
        assert selective <= dias.fog_search_nodes
        assert broadcast == dias.fog_search_nodes, (
            "Incremental-All propagates to every FSN by definition"
        )
        assert selective <= broadcast
    # At the sparsest ratio the selective set must be a STRICT subset, or
    # "propagates only to FSNs maintaining affected shards" claims nothing.
    assert dias.measure(dias.prepare(0.1)).secondaries["fsns_touched"] < (
        dias.fog_search_nodes
    )


def test_psa_exp6_full_state_redistributes_authority_state(config, source):
    """§VI: Full-State propagates the authorization/index state to ALL FSNs.

    The index half is the policy loop. The authorization half is every OTHER
    authority recomputing C_k^auth and the AIM republishing it to every node --
    what `experiments.py`'s `full_rebuild` arm does. Without it this arm was
    named after something it only half did, `FS/DIAS` was a lower bound, and
    the two Exp. 6 figures defined `full_state` differently.

    Asserted against the OTHER two arms rather than a literal: the redistributed
    payload is small next to 40 policies' entries, so a hardcoded KB figure
    would be brittle without being any more informative.
    """
    full = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_FULL_STATE, source=source)
    everyone = psa.PsaExp6AffectedRatio(
        config=config, variant=psa.VARIANT_INCREMENTAL_ALL, source=source
    )
    at_one = full.measure(full.prepare(1.0)).secondaries
    other = everyone.measure(everyone.prepare(1.0)).secondaries
    # At a 100% ratio both arms evolve every policy and deliver to every node,
    # so the ONLY thing separating them is the authority-state republish.
    assert at_one["records_evolved"] == other["records_evolved"]
    assert at_one["delivered_kb"] > other["delivered_kb"], (
        "Full-State must put more on the wire than Incremental-All even at a "
        "100% ratio; if it does not, the authorization half is not happening"
    )


def test_psa_exp6_full_state_stays_flat_across_the_ratio(config, source):
    """Its cost does not depend on how little changed — that is the point."""
    full = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_FULL_STATE, source=source)
    delivered = {
        round(full.measure(full.prepare(r)).secondaries["delivered_kb"], 3)
        for r in full.values
    }
    assert len(delivered) == 1, f"Full-State payload varied with the ratio: {delivered}"


def test_psa_exp6_delivered_bytes_are_summed_per_delivery(config, source):
    """Never `payload x fan_out` — the derivation experiments.py records as wrong.

    Measured per delivery, so an arm whose messages differ in size cannot be
    charged an average one. Incremental-All sends the same delta to `m` nodes
    where DIAS sends it to the affected ones, so the ratio must track the node
    counts the run actually reports.
    """
    dias = psa.PsaExp6AffectedRatio(config=config, variant=psa.VARIANT_DIAS, source=source)
    everyone = psa.PsaExp6AffectedRatio(
        config=config, variant=psa.VARIANT_INCREMENTAL_ALL, source=source
    )
    a = dias.measure(dias.prepare(0.1)).secondaries
    b = everyone.measure(everyone.prepare(0.1)).secondaries
    assert b["delivered_kb"] > a["delivered_kb"]
    assert b["delivered_kb"] / a["delivered_kb"] == pytest.approx(
        everyone.fog_search_nodes / a["fsns_touched"], rel=0.01
    )


# ===========================================================================
# D5 — the VAP must not be assembled from halves that disagree
# ===========================================================================
def test_build_profile_refuses_a_partial_overlap():
    """A one-sided authority is a caller error, not a set to intersect.

    ``PolicyVersionState.build`` already refuses a missing version rather than
    defaulting it to 0, and ``PolicyStateProfile`` refuses halves that cover
    different authorities. ``build_profile`` intersected instead, so a profile
    built from a V_U of three authorities and a C_U of one came back covering
    one — complete-looking, and denied at Phase VI Step 2 for every policy the
    other two govern.
    """
    with pytest.raises(psa_records.RecordError, match="disagree on the authority"):
        psa_records.build_profile(
            uid="DU-1", domains=["hospital"], attributes=["AA1:doc"],
            versions={"AA1": 1, "AA2": 1, "AA3": 1},
            commitments={"AA1": b"\x01" * 32},
        )


def test_build_profile_keeps_every_authority_when_the_halves_agree():
    profile = psa_records.build_profile(
        uid="DU-1", domains=["hospital"], attributes=["AA1:doc"],
        versions={"AA1": 1, "AA2": 2},
        commitments={"AA1": b"\x01" * 32, "AA2": b"\x02" * 32},
    )
    assert profile.authority_ids == ("AA1", "AA2")


# ===========================================================================
# The PSA track must reach a FIGURE, and its axes must be readable
# ===========================================================================
def _plots_module():
    """`Plots/generate_plots.py` is a script, not a package member."""
    import importlib.util

    if "_generate_plots" in sys.modules:
        return sys.modules["_generate_plots"]
    path = REPO / "Plots" / "generate_plots.py"
    spec = importlib.util.spec_from_file_location("_generate_plots", path)
    module = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec: `dataclasses` resolves a field's annotation via
    # `sys.modules[cls.__module__]`, so a module that defines dataclasses
    # cannot be executed while absent from the table.
    sys.modules["_generate_plots"] = module
    spec.loader.exec_module(module)
    return module


def test_every_experiment_has_a_figure_spec():
    """A measured experiment with no figure is a result nobody can read.

    Was written against `PSA_EXPERIMENTS` and `main.PSA_FOLDERS`, the second
    figure family. The proposed scheme implements one construction as of
    2026-09-12, so both are gone and every scheme writes `exp<N>_*`. The
    invariant survives the collapse: whatever the runner writes, the plotter
    must draw.
    """
    from Schemes.ma_lb_pq_vdse.src import main as main_mod

    plots = _plots_module()
    drawn = {spec.number for spec in plots.EXPERIMENTS}
    assert drawn == set(main_mod.FOLDERS), (
        f"the runner writes {sorted(main_mod.FOLDERS)} but the plotter "
        f"draws {sorted(drawn)}"
    )
    for spec in plots.EXPERIMENTS:
        assert spec.folder == main_mod.FOLDERS[spec.number]


def test_there_is_exactly_one_figure_family():
    """The second family must not come back.

    Replaces `test_the_two_figure_families_never_share_a_filename`, which
    checked that the two families' filenames were disjoint. There is one family
    now; the thing worth guarding is that a `psa_`-prefixed spec cannot
    reappear and glob the same directories, which is how one dataset ends up
    drawn twice in one paper.
    """
    plots = _plots_module()
    assert not hasattr(plots, "PSA_EXPERIMENTS"), (
        "a second figure family reappeared; both would glob exp<N>_* and draw "
        "the same results twice"
    )
    for spec in plots.EXPERIMENTS:
        assert spec.prefix == "", f"exp{spec.number} spec carries prefix {spec.prefix!r}"
        assert not spec.filename.startswith("fig_psa_")


def test_exp1_figure_draws_only_arms_the_runner_writes(config):
    """Every |P_U| arm Fig. 1 declares must exist and be styled.

    WAS an assertion that all four scopes are drawn. Fig. 1 draws only
    |P_U| = 1 as of 2026-09-13, a presentation choice: four proposed curves
    against each baseline's one made it an eight-series figure that read as
    eight unrelated schemes. Exp. 1 still MEASURES every scope -- global.yaml
    still declares policy_scopes [1,2,4,8] and the runner still writes all four
    `__pu<N>` directories -- so the count is not the invariant and pinning it
    would just block the next presentation change.

    What must hold is the mechanism. `collect` takes the FIRST matching
    directory per scheme and stops, so a declared arm whose directory the
    runner never writes does not fall back to the scheme curve: it drops the
    proposed series from the figure silently. And an arm with no style slot
    draws in the fallback style, which is how two curves end up identical in
    grayscale.
    """
    plots = _plots_module()
    spec = next(s for s in plots.EXPERIMENTS if s.number == 1)
    slugs = dict(spec.proposed_variants)
    assert slugs, "exp1 declares no proposed arm; the proposed curve would vanish"
    unknown = set(slugs) - set(psa.PSA_EXP1_VARIANTS)
    assert not unknown, (
        f"exp1 declares arm(s) {sorted(unknown)} that the runner never writes; "
        f"collect() would drop the proposed series rather than fall back"
    )
    slots = {plots.ABLATION_STYLE_SLOT.get(label) for label in slugs.values()}
    assert None not in slots, (
        f"unstyled exp1 arm label(s) in {sorted(slugs.values())}"
    )
    assert len(slots) == len(slugs), "two exp1 arms share a style slot"


def test_exp6_figure_uses_the_runners_variant_slugs(config):
    """The plotter's arm names must be the ones the runner writes as directories.

    `psa_experiments.py` names the DIAS arms `dias`/`incremental_all`/
    `full_state`; `experiments.py` carries an older `ias`/`broadcast`/
    `full_rebuild` vocabulary. Only the first reaches disk, because `--
    construction` accepts only `psa`. Reusing the other here would find no
    directories and draw an empty figure with three "missing variant" notes.
    """
    plots = _plots_module()
    spec = next(s for s in plots.EXPERIMENTS if s.number == 6)
    assert dict(plots.variants_for(spec)).keys() == set(psa.PSA_EXP6_VARIANTS)


# ===========================================================================
# Exp. 4 under the PSA commitment — r counts RECORDS
# ===========================================================================
def test_psa_exp4_r_counts_records_not_index_entries(config):
    """Defect d1cdf9c, which has already forced two re-runs, must not recur.

    `psa/verify.py::build_response` emits one bundle per index ENTRY. At
    keywords_per_record=6, taking them all would make r=100 into 600 bundles
    and compare 6r entries against baselines that return r records.
    """
    experiment = psa.build(4, config, source=_source())
    for r in (10, 100):
        sample = experiment.measure(experiment.prepare(r))
        assert sample.secondaries["records_verified"] == r


def test_psa_exp4_step_3_is_not_quadratic(config):
    """The anchors are fetched once per response, not once per record.

    Option D's per-record namespace walk made Step 3 O(r^2) and 99.6% of the
    step's cost. Asserted on the shape of the curve rather than a wall-clock
    threshold, so it holds on the campaign host too.
    """
    experiment = psa.build(4, config, source=_source())
    per_record = {}
    for r in (100, 500):
        best = min(experiment.measure(experiment.prepare(r)).primary for _ in range(3))
        per_record[r] = best / r
    # Quadratic would make the per-record cost grow ~5x from r=100 to r=500.
    assert per_record[500] < per_record[100] * 2.0, per_record


def test_psa_exp4_chain_check_actually_runs(config):
    """Step 3 is inside §5's Exp. 4 boundary, so it must be on the timed path."""
    experiment = psa.build(4, config, source=_source())
    prepared = experiment.prepare(10)
    checker = psa_mod._psa_batched_chain_checker(
        prepared["ledger"], prepared["cids"]
    )
    result = psa_verify_mod.verify_bundle(prepared["bundles"][0], chain_check=checker)
    assert [s.step for s in result.steps] == ["merkle", "authorization", "chain"]
    assert result.accepted


def test_psa_exp4_rejects_an_unanchored_commitment(config):
    """A record with no anchor on the ledger must fail at chain, not pass.

    An EMPTY ledger, not an empty dict: Step 3 now reads through
    `verify/ledger.py::lookup_anchors`, so whatever ABCD_LEDGER selects is what
    gets queried and an unanchored record is a real miss.
    """
    from Schemes.ma_lb_pq_vdse.src.chain import ledger as ledger_mod

    experiment = psa.build(4, config, source=_source())
    prepared = experiment.prepare(5)
    checker = psa_mod._psa_batched_chain_checker(
        ledger_mod.InProcessLedger(), prepared["cids"]
    )
    result = psa_verify_mod.verify_bundle(prepared["bundles"][0], chain_check=checker)
    assert not result.accepted and result.failed_step == "chain"


# ===========================================================================
# The corpus seam — PSA must read the records Option D reads
# ===========================================================================
def _source():
    from Schemes.ma_lb_pq_vdse.src.harness import experiments as option_d_mod

    return option_d_mod.SyntheticRecordSource()


def test_psa_deployment_reads_the_same_source_as_option_d(config, source):
    """The whole point of the seam.

    Before this, every PSA number came from `build_world()` — invented
    policies, CIDs and keywords — so no PSA figure could ever be reportable,
    and `|W_i|` was a hardcoded 6 against the corpus's ~32. Both Exp. 4 and
    Exp. 5 divide by that.
    """
    source = _source()
    theirs = option_d.build_deployment(config=config, source=source, records=120)
    ours = psa_mod.psa_build_deployment(config=config, source=source, records=120)
    assert len(ours.records) == len(theirs.records)
    # Same records, so the same policies and domains -- derived from the
    # source, never stipulated.
    assert {r["policy"] for r in ours.records} == {
        r["record"].policy_id for r in theirs.records
    }
    assert {r["domain"] for r in ours.records} == {
        r["record"].domain for r in theirs.records
    }


def test_psa_deployment_carries_the_sources_provenance(config):
    """A corpus-backed run may be reportable; an invented one may not."""
    ours = psa_mod.psa_build_deployment(
        config=config, source=_source(), records=20
    )
    assert ours.corpus_type == _source().corpus_type


def test_psa_governance_is_derived_from_real_policy_ids(config):
    """`extract` emits `<domain>/polN`, which PolicyGovernance parses."""
    ours = psa_mod.psa_build_deployment(
        config=config, source=_source(), records=60
    )
    assert ours.world.policies, "no policies were discovered from the source"
    for policy in ours.world.policies:
        governing = ours.world.governance.governing(policy)
        assert len(governing) == 2, governing
        # The policy's own domain authority must be among them.
        owner = ours.world.authorities[policy.split("/", 1)[0]]
        assert owner in governing


def test_psa_shards_are_real_indexes_not_dicts(config):
    """Exp. 2 measures bitmap + Bloom + traversal; a dict measures none of it."""
    ours = psa_mod.psa_build_deployment(
        config=config, source=_source(), records=80
    )
    total = 0
    # PSA nodes are real `FogSearchNode`s since 2026-09-10, sharing Option D's
    # Phase I-III scaffolding — that is what lets the AIM check and AASS run
    # inside the timed path, as §VI Exp. 2 and Exp. 3 describe.
    for node in ours.nodes:
        assert hasattr(node.index, "authorized_bitmap"), "not a DynamicSearchIndex"
        total += node.index.entry_count
    # Summed ACROSS nodes, so each entry is counted once per holder:
    # `sharding.replication` went to 2 on 2026-09-12 and every shard now lives
    # on two FSNs. `entry_count` is the logical total, so the two differ by
    # exactly that factor -- and must, or a replica is missing its copy.
    assert ours.entry_count > 0
    assert total == ours.entry_count * config.index.replication, (
        f"{total} entries across nodes against a logical {ours.entry_count} at "
        f"replication {config.index.replication}; a mismatch means a holder "
        f"was never written"
    )


# ===========================================================================
# Exp. 2 — what D1's token binding costs the search path
# ===========================================================================
def test_psa_exp2_issues_q_times_pu_tokens(config):
    """Option D issues q; this issues one per (keyword, authorized policy)."""
    experiment = psa.build(2, config, source=_source())
    sample = experiment.measure(experiment.prepare(10000))
    q = config.defaults.keywords_per_query
    issued = sample.secondaries["tokens_issued"]
    assert issued > q, f"{issued} tokens for q={q}; the |P_U| factor is missing"
    assert issued % q == 0


def test_psa_exp2_shares_fewer_posting_lists_than_option_d(config, source):
    """The measured cost of D1 on index structure.

    Option D's `H(w)` shares one posting list across every record carrying the
    keyword. The PSA token binds (policy, domain, PV), so sharing only happens
    within one of those — the ratio must be strictly lower.
    """
    source = _source()
    experiment = psa.build(2, config, source=source)
    n = 50000
    ours = experiment.measure(experiment.prepare(n)).secondaries["entries_per_token"]

    # SAME N, two constructions. This built Option D at
    # `n // keywords_per_record` while PSA was built at `n` -- once both
    # experiments started sizing N in RECORDS (2026-09-07) that compared a
    # 50,000-record PSA index against an 8,333-record Option D one, and the
    # sharing ratio it reports is a function of index size.
    theirs = option_d.build_deployment(
        config=config, source=source, records=max(1, n)
    )
    entries = sum(node.index.entry_count for node in theirs.nodes)
    tokens = sum(node.index.token_count for node in theirs.nodes)
    assert ours < entries / max(tokens, 1), (
        f"PSA shares {ours:.2f} entries per token against Option D's "
        f"{entries / max(tokens, 1):.2f}; D1's binding must reduce sharing"
    )


def test_psa_exp2_survives_the_multiprocess_replay_boundary(config):
    """Exp. 7-8 fork one worker per FSN, so the index must pickle.

    Asserted here rather than in Exp. 7-8 because it is a property of the
    ENTRY type, and finding it out during a concurrency run would cost a
    campaign slot rather than a millisecond.
    """
    import pickle

    ours = psa_mod.psa_build_deployment(
        config=config, source=_source(), records=40
    )
    index = ours.nodes[0].index
    assert pickle.loads(pickle.dumps(index)).entry_count == index.entry_count
    entry = ours.records[0]["entries"][0]
    assert pickle.loads(pickle.dumps(entry)) == entry


# ===========================================================================
# Exp. 7-8 — the scheduler ablation under the policy-bound token
# ===========================================================================
def test_psa_scheduler_ablation_only_overrides_prepare(config):
    """The measured path stays Option D's.

    Scheduler, replay, FSN pool and utilization sampling are
    construction-independent, and a second copy of them would drift from the
    first. If this list ever grows, a measured path has been forked.
    """
    overridden = {
        name for name in vars(psa_mod.PsaSchedulerAblation)
        if not name.startswith("__")
    }
    assert overridden == {"prepare"}, overridden


def test_psa_exp7_shards_hold_psa_entries_and_tokens_scale_with_pu(config):
    """The two things that make it a PSA measurement rather than a rerun."""
    from Schemes.ma_lb_pq_vdse.src.psa import records as psa_records_mod

    experiment = psa_mod.PsaExp7Throughput(
        config=config, source=_source(), variant="aass"
    )
    prepared = experiment.prepare(60)
    deployment, requests = prepared["deployment"], prepared["requests"]
    assert requests, "the trace is empty; every request was rejected"

    for node in deployment.nodes:
        assert node.index.entry_count > 0
    sample_entry = deployment.records[0]["psa_entries"][0]
    assert isinstance(sample_entry, psa_records_mod.PolicyStateIndexEntry)

    # One token per (keyword, authorized policy) -- q*|P_U|, where Option D
    # issues q. Was `== len(authorized_shards)` while the trace still used one
    # keyword; the q=1 fix made that the wrong identity.
    trapdoor, decision = requests[0]
    q = config.defaults.keywords_per_query
    assert len(trapdoor.tokens) == q * len(decision.authorized_shards)
    assert len(trapdoor.tokens) > q


def test_psa_exp7_uses_the_same_keyword_count_as_option_d(config, source):
    """Otherwise the comparison measures two workloads, not two constructions.

    A draft took q=5 here while Option D's trace takes one keyword, and the
    resulting "PSA is 1.38x faster" was entirely that mismatch.
    """
    source = _source()
    ours = psa_mod.PsaExp7Throughput(config=config, source=source, variant="aass")
    theirs = option_d.Exp7Throughput(config=config, source=source, variant="aass")
    mine = ours.prepare(40)["requests"]
    yours = theirs.prepare(40)["requests"]
    assert mine and yours
    # Option D: q tokens. PSA: q * |P_U|. Same q means the ratio is exactly
    # the authorized-policy count.
    ratio = len(mine[0][0].tokens) / len(yours[0][0].tokens)
    assert ratio == len(mine[0][1].authorized_shards)


def test_psa_exp8_shares_the_ablation_and_its_metrics(config):
    """Exp. 8 must keep Option D's metric names, or the figures diverge."""
    ours = psa_mod.PsaExp8LoadBalance(config=config, source=_source())
    theirs = option_d.Exp8LoadBalance(config=config, source=_source())
    assert ours.primary.name == theirs.primary.name
    assert [m.name for m in ours.secondaries] == [
        m.name for m in theirs.secondaries
    ]
    assert ours.variable == theirs.variable


def test_both_exp7_traces_use_the_published_q(config, source):
    """global.yaml fixes q=5 from §VI; the trace used ONE keyword until 2026-09-06.

    Asserted for BOTH constructions, because the moment they differ the Exp. 7
    comparison measures two workloads rather than two schemes.
    """
    source = _source()
    q = config.defaults.keywords_per_query
    theirs = option_d.Exp7Throughput(config=config, source=source, variant="aass")
    ours = psa_mod.PsaExp7Throughput(config=config, source=source, variant="aass")
    yours = theirs.prepare(40)["requests"]
    mine = ours.prepare(40)["requests"]
    assert yours and mine
    assert len(yours[0][0].tokens) == q, (
        f"Option D's trace carries {len(yours[0][0].tokens)} tokens for q={q}"
    )
    assert len(mine[0][0].tokens) == q * len(mine[0][1].authorized_shards)


# ===========================================================================
# The conjunctive query — §VI's q-keyword search must be answerable at all
# ===========================================================================
def test_a_multi_keyword_conjunctive_query_can_match(config):
    """It could not, before 2026-09-06, for ANY data.

    `dsi.lookup` intersected ORDINALS. An ordinal is one index entry and an
    entry carries exactly one token, so two distinct keywords never shared one
    and a q-keyword conjunctive query returned the empty set by construction.
    §VI's central search claim is exactly such a query.
    """
    from Schemes.ma_lb_pq_vdse.src.harness import experiments as od

    experiment = od.Exp7Throughput(
        config=config, source=_source(), variant="aass"
    )
    deployment = experiment.prepare(20)["deployment"]
    record = deployment.records[0]["record"]
    node = [n for n in deployment.nodes if n.serves_domain(record.domain)][0]
    scoped = [(record.domain, record.policy_id)]

    tokens = [deployment.scheme.query_token(k) for k in record.keywords[:5]]
    hits, stats = node.index.lookup(tokens, scoped)
    assert hits, "a 5-keyword conjunctive query matched nothing"
    assert stats.entries_traversed > 0


def test_conjunctive_is_per_record_not_per_entry(config):
    """Every returned entry belongs to a record satisfying EVERY token."""
    from Schemes.ma_lb_pq_vdse.src.harness import experiments as od

    experiment = od.Exp7Throughput(
        config=config, source=_source(), variant="aass"
    )
    deployment = experiment.prepare(20)["deployment"]
    record = deployment.records[0]["record"]
    node = [n for n in deployment.nodes if n.serves_domain(record.domain)][0]
    scoped = [(record.domain, record.policy_id)]

    keywords = list(dict.fromkeys(record.keywords))[:3]
    tokens = [deployment.scheme.query_token(k) for k in keywords]
    hits, _ = node.index.lookup(tokens, scoped)
    assert hits
    wanted = set(tokens)
    for cid in {h.cid for h in hits}:
        held = {
            node.index.entry(o).token
            for o in node.index.ordinals_for_cid(cid)
        }
        assert wanted <= held, f"{cid} does not carry every queried token"


def test_a_single_keyword_query_is_unchanged_by_the_fix(config):
    """Exp. 2 rotates ONE keyword per run, so its banked curve must not move.

    At q=1 per-record and per-entry intersection coincide, and the returned
    set must stay the matching entries -- not every entry of a matching
    record, which would inflate n_eff by |W_i| and silently move Exp. 2.
    """
    from Schemes.ma_lb_pq_vdse.src.harness import experiments as od

    experiment = od.Exp7Throughput(
        config=config, source=_source(), variant="aass"
    )
    deployment = experiment.prepare(20)["deployment"]
    record = deployment.records[0]["record"]
    node = [n for n in deployment.nodes if n.serves_domain(record.domain)][0]
    token = deployment.scheme.query_token(record.keywords[0])
    hits, _ = node.index.lookup([token], [(record.domain, record.policy_id)])
    assert hits
    # One entry per matching record, and each IS the entry that matched.
    assert len(hits) == len({h.cid for h in hits})
    assert all(h.token == token for h in hits)


def test_psa_exp7_requests_actually_match_records(config):
    """Zero hits would mean Exp. 7-8 time an empty search.

    A PSA query is a disjunction ACROSS policies of a conjunction OVER
    keywords. Handing the flat q*|P_U| set to one conjunctive lookup asks a
    record to satisfy tokens bound to several policies, which no record can:
    that returned 0 hits over every request until the trace carried its
    per-policy grouping.
    """
    from Schemes.ma_lb_pq_vdse.src.fsn import search as search_mod

    experiment = psa_mod.PsaExp7Throughput(
        config=config, source=_source(), variant="aass"
    )
    prepared = experiment.prepare(20)
    deployment, requests = prepared["deployment"], prepared["requests"]
    trapdoor, decision = requests[0]
    assert trapdoor.groups, "the trace carries no per-policy grouping"

    node = [
        n for n in deployment.nodes
        if n.serves_domain(decision.authorized_shards[0][0])
    ][0]
    grouped = search_mod.execute_search(
        node, trapdoor.tokens, decision.authorized_shards,
        groups=trapdoor.groups,
    )
    flat = search_mod.execute_search(
        node, trapdoor.tokens, decision.authorized_shards
    )
    assert grouped.hits, "a grouped PSA query matched nothing"
    assert not flat.hits, (
        "the flat form matched something; if that becomes possible the "
        "grouping may no longer be load-bearing and this test is stale"
    )


def test_option_d_dispatch_passes_no_groups(config):
    """Option D's H(w) token carries no policy, so there is nothing to group.

    The grouped branch must stay opt-in: if Option D ever started passing
    groups it would silently change the banked Exp. 7-8 measurement.
    """
    experiment = option_d.Exp7Throughput(
        config=config, source=_source(), variant="aass"
    )
    trapdoor, _ = experiment.prepare(20)["requests"][0]
    assert not getattr(trapdoor, "groups", None)


_SCHEDULER_VARIANTS = (
    aass_mod.VARIANT_NO_LB,
    aass_mod.VARIANT_ROUND_ROBIN,
    aass_mod.VARIANT_LEAST_LOADED,
    aass_mod.VARIANT_AASS,
)


def test_psa_build_propagates_the_scheduler_variant(config):
    """Exp. 7-8's arm IS the scheduler, so `build` must carry it through.

    `psa.build` handled `variant` for Exp. 1 (|P_U|), Exp. 4 (`granularity`)
    and Exp. 6 (DIAS propagation), but Exp. 7-8 are CORPUS_BACKED and fell
    through to the variant-less `cls(config=..., source=...)`. Every arm was
    therefore built at the default `aass`: `--variant all` ran one scheduler
    four times and wrote the results to four directories named after four
    different schedulers.

    Measured on the campaign host 2026-09-12, that gave four Exp. 7 throughput
    curves agreeing inside their confidence intervals and
    `cross_node_forwards = 0` in all four arms -- AASS's signature, since its
    eligibility guard never misplaces a shard, reported as though the three
    oblivious arms shared it. Fig. 8(c) compared one scheduler with itself.
    """
    for number in (7, 8):
        for variant in _SCHEDULER_VARIANTS:
            experiment = psa.build(
                number, config, variant=variant, source=_source()
            )
            assert experiment.variant == variant, (
                f"psa.build({number}, variant={variant!r}) produced "
                f"variant={experiment.variant!r}; the ablation would measure "
                f"the default scheduler under this arm's directory name"
            )
