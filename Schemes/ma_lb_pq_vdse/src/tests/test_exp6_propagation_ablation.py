"""Exp. 6's IAS claim has two halves, and neither had a measurement behind it.

README §5 says of Exp. 6: "Report FSNs touched; **selective propagation is the
claim**." Every campaign before 2026-09-03 reported ``fsns_touched = 1.000`` at
every δ and called that the evidence. It is not evidence of anything:
``assign_domains_to_fsns`` gives each domain to exactly ONE node and an
``IASMessage`` carries exactly one domain, so selective delivery touches one node
for any ``d`` and ``m``. The constant is a property of the design, not a
measurement of it.

The claim is only observable against the alternative the manuscript names and
rejects, so Exp. 6 now carries an ablation with one variant per half:

    ``broadcast``     — deliver IAS_i to every FSN         (tests SELECTIVE, :1111)
    ``full_rebuild``  — every authority recomputes C^auth  (tests INCREMENTAL, :1045)

The risk an ablation like this carries is that the strawman is not the published
alternative but a deliberately bad implementation. Every test below is aimed at
that: the variants must differ from ``ias`` in **who is contacted** and **how many
authorities recompute**, and in nothing else — same final authorization state,
same per-message payload, same code paths for the work itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from Schemes.ma_lb_pq_vdse.src import config as config_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import experiments as exp_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.harness import provenance  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.sync import ias as ias_mod  # noqa: E402

CONFIG = config_mod.load()
SOURCE = exp_mod.SyntheticRecordSource()

UPDATES = 3


def _measure(variant: str):
    experiment = exp_mod.build_experiment(6, CONFIG, SOURCE, variant=variant)
    prepared = experiment.prepare(UPDATES)
    return experiment, prepared, experiment.measure(prepared)


# ===========================================================================
# The variants exist and the default is the published rule
# ===========================================================================
def test_default_variant_is_the_published_selective_rule():
    experiment = exp_mod.build_experiment(6, CONFIG, SOURCE)
    assert experiment.variant == exp_mod.VARIANT_IAS


def test_unknown_variant_is_refused_rather_than_silently_ignored():
    with pytest.raises(ValueError) as excinfo:
        exp_mod.Exp6AuthorizationSync(
            config=CONFIG, source=SOURCE, variant="round_robin"
        )
    # The scheduler vocabulary belongs to Exp. 7-8. Accepting it here is what
    # produced the stale exp6_authorization_sync__no_lb directory: a second run
    # of the identical measurement under a different name.
    assert "round_robin" in str(excinfo.value)


# ===========================================================================
# SELECTIVE — the half `broadcast` tests
# ===========================================================================
def test_selective_delivery_touches_exactly_one_node():
    """d = m = 4, one domain per node, so one authority's update reaches one."""
    _, _, sample = _measure(exp_mod.VARIANT_IAS)
    assert sample.secondaries["fsns_touched"] == 1.0


def test_broadcast_touches_every_node():
    """The alternative :1111 rejects: "broadcasting the complete index state"."""
    _, prepared, sample = _measure(exp_mod.VARIANT_BROADCAST)
    nodes = len(prepared["deployment"].nodes)
    assert nodes > 1, "a one-node deployment cannot distinguish the variants"
    assert sample.secondaries["fsns_touched"] == float(nodes)


def test_broadcast_is_the_measurable_contrast_selective_needs():
    """The point of the ablation: 1 against m, not 1 against nothing."""
    _, prepared, selective = _measure(exp_mod.VARIANT_IAS)
    _, _, broadcast = _measure(exp_mod.VARIANT_BROADCAST)
    nodes = len(prepared["deployment"].nodes)
    assert broadcast.secondaries["fsns_touched"] == (
        selective.secondaries["fsns_touched"] * nodes
    )


def test_broadcast_carries_the_same_message_it_just_sends_it_further():
    """Selectivity must be the ONLY difference — not a bigger payload."""
    _, _, selective = _measure(exp_mod.VARIANT_IAS)
    _, _, broadcast = _measure(exp_mod.VARIANT_BROADCAST)
    assert broadcast.secondaries["ias_message_size"] == pytest.approx(
        selective.secondaries["ias_message_size"]
    )


# ===========================================================================
# INCREMENTAL — the half `full_rebuild` tests
# ===========================================================================
def test_full_rebuild_recomputes_every_authority():
    """:1045 — "only the affected authority updates its commitment"."""
    _, prepared, sample = _measure(exp_mod.VARIANT_FULL_REBUILD)
    d = prepared["deployment"]
    nodes = len(d.nodes)
    authorities = len(d.authorities)
    # One selective delivery for the affected authority, plus a republish of
    # every other authority's recomputed state to every node.
    expected = 1 + (authorities - 1) * nodes
    assert sample.secondaries["fsns_touched"] == float(expected)


def test_full_rebuild_costs_more_than_the_incremental_path():
    """An ablation that shows no effect would mean the claim is untestable."""
    _, _, incremental = _measure(exp_mod.VARIANT_IAS)
    _, _, rebuild = _measure(exp_mod.VARIANT_FULL_REBUILD)
    assert rebuild.primary > incremental.primary


def test_full_rebuild_uses_the_same_commitment_function_not_a_slow_one():
    """Guard against measuring against a strawman.

    The advantage must come from calling ``Authority.commitment()`` for FEWER
    authorities, never from the rebuild path calling something worse. The
    superseded O(delta^2) ``RevocationList`` is exactly the trap: measuring
    against an old bug would overstate the result.
    """
    import inspect

    src = inspect.getsource(exp_mod.Exp6AuthorizationSync.measure)
    assert ".meta()" in src, "full_rebuild must go through Authority.meta()"
    assert "RevocationList" not in src
    assert "_compute_root" not in src


# ===========================================================================
# The ablation changes COST, not correctness
# ===========================================================================
@pytest.mark.parametrize("variant", exp_mod.EXP6_VARIANTS)
def test_every_variant_reaches_the_same_authorization_state(variant):
    """VID_k advances once per update however the message was delivered."""
    _, prepared, _ = _measure(variant)
    d = prepared["deployment"]
    authority = d.authorities[d.records[0]["record"].domain]
    assert authority.vid == UPDATES


@pytest.mark.parametrize("variant", exp_mod.EXP6_VARIANTS)
def test_every_variant_reports_both_secondaries(variant):
    _, _, sample = _measure(variant)
    assert sample.secondaries["ias_message_size"] > 0
    assert sample.secondaries["fsns_touched"] >= 1.0
    assert sample.primary > 0


# ===========================================================================
# The injected selector must not weaken the default path
# ===========================================================================
def test_default_path_still_refuses_a_node_that_does_not_hold_the_shard():
    """``require_shard`` is relaxed ONLY for an injected selector.

    ``apply_ias`` gained ``require_shard=False`` so ``broadcast`` can reach nodes
    without the affected shard. If that leaked into the default, selective
    propagation would silently accept a misrouted message.
    """
    import inspect

    src = inspect.getsource(ias_mod.synchronize)
    assert "require_shard=select_nodes is None" in src, (
        "the shard guard must stay on whenever no selector was injected"
    )


def test_affected_nodes_is_still_the_default_selector():
    import inspect

    src = inspect.getsource(ias_mod.synchronize)
    assert "select_nodes or affected_nodes" in src


# ===========================================================================
# Reportability — Exp. 6's boundary excludes Phase VII Step 7
# ===========================================================================
def _reasons(experiment: str):
    _, reasons = provenance.reportability(
        CONFIG,
        experiment=experiment,
        corpus_type="synthea",
        corpus_sha256=None,
        group_faithful=True,
        token_scheme_keyed=True,
        ledger_faithful=False,
    )
    return [r for r in reasons if "ledger" in r or "Fabric" in r]


def test_exp6_is_not_blocked_on_the_fabric_adapter():
    """Its timed path never anchors, so the ledger cannot understate it.

    ``synchronize`` takes ``ledger`` as optional and anchors only inside
    ``if ledger is not None``; the Exp. 6 runner passes none. README §5 ends the
    Exp. 6 boundary at "until all affected FSNs report the new VID", and
    ``tab:cost``'s authorization-synchronization row carries no chain term.
    """
    assert _reasons("exp6_authorization_sync") == []


def test_exp4_is_still_blocked_on_the_fabric_adapter():
    """§5 puts "chain consistency" INSIDE Exp. 4's boundary in as many words."""
    assert len(_reasons("exp4_verification_overhead")) == 1


def test_exp6_runner_passes_no_ledger():
    """The premise the gate change rests on, pinned.

    If Phase VII Step 7 is ever brought inside Exp. 6's boundary, this fails and
    ``exp6_authorization_sync`` must go back into the ledger gate.
    """
    import inspect

    src = inspect.getsource(exp_mod.Exp6AuthorizationSync.measure)
    assert "ledger=" not in src, (
        "Exp. 6 now anchors on its timed path; restore the ledger gate in "
        "provenance.reportability()"
    )
