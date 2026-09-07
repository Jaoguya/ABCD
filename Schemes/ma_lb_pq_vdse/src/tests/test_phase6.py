#!/usr/bin/env python3
"""Verification tests for MA-LB-PQ-VDSE Phase VI Steps 3-4.

Each test checks a DEFINING PROPERTY. A scheduler that returns a valid node but
picks it by evaluating the query has passed the shallow test and made Exp. 7
measure the scheduler instead of the search.

Runs standalone with no test framework::

    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase6.py           # all
    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase6.py aass      # one area

and is also collectible by pytest if it is installed.

Covers ``scheduler/aass.py`` (Step 3) and ``fsn/search.py`` (Step 4). Steps 1-2
(search-token assembly and AIM authorization verification) are not implemented;
tests supply the ``(domain, policy)`` set the AIM would have resolved.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Common.crypto import hashes  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import config as config_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import types  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.fsn import fsn as fsn_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.fsn import search as search_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import extract as extract_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import tokens as tokens_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.scheduler import aass as aass_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.shard import propagation as prop_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.tests import test_phase4 as base  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


DOMAINS = extract_mod.DEFAULT_DOMAIN_NAMES
SEARCH_KEY = hashes.sha256(b"phase6-search-key", domain=b"test/search-key")


# ===========================================================================
# Fixtures
# ===========================================================================
def scheme() -> tokens_mod.TokenScheme:
    return tokens_mod.TokenScheme.keyed(SEARCH_KEY)


def populated_federation(records_per_domain: int = 3, keywords: int = 6):
    """A 4-node federation with records propagated to their domain shards.

    Returns ``(nodes, authorized, keyword_by_domain)`` — the authorization set the
    AIM would have resolved in Phase VI Step 2, and one keyword per domain.
    """
    token_scheme = scheme()
    nodes = fsn_mod.build_fsn_set(DOMAINS, 4)
    authorized: List[Tuple[str, str]] = []
    keyword_by_domain = {}
    rid = 0
    for dom_index, domain in enumerate(DOMAINS):
        for local in range(records_per_domain):
            record = extract_mod.extract(
                base.make_corpus_record(
                    rid=rid,
                    patient=f"patient-{dom_index}{local:04d}",
                    dom=dom_index,
                    keywords=keywords,
                ),
                assignment=base.make_assignment(1),
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
            payload = prop_mod.build_sync_payload(
                entries=entries, metadata=record.metadata, cid=cid
            )
            prop_mod.propagate_to_authorized(
                payload, domain=record.domain, nodes=nodes
            )
            if (record.domain, record.policy_id) not in authorized:
                authorized.append((record.domain, record.policy_id))
            keyword_by_domain.setdefault(record.domain, record.keywords[0])
            rid += 1
    return nodes, tuple(authorized), keyword_by_domain


def make_request(
    keyword: str, authorized: Tuple[Tuple[str, str], ...], *, vid_u: int = 1
) -> aass_mod.SearchRequest:
    return aass_mod.SearchRequest(
        tokens=(scheme().query_token(keyword),),
        authorized=authorized,
        vid_u=vid_u,
    )


def sync_nodes(nodes, authorized, *, vid: int = 1):
    """Give every node the authorization state its domains need."""
    for node in nodes:
        for domain, _ in authorized:
            if node.serves_domain(domain):
                node.apply_meta(
                    f"AA-{domain}",
                    types.AuthorizationMeta(domain, vid, bytes(32)),
                )


# ===========================================================================
# scheduler/aass.py — the request
# ===========================================================================
def test_request_reports_its_distinct_domains():
    """`domains` drives `_candidates`; `|P_Q|` no longer enters the cost.

    This asserted `request.policy_count == 2` as well, the input to the C^auth
    term of the previous manuscript revision. eq:search-cost states four terms
    and none of them is C^auth, so the property was removed with it on
    2026-09-07 rather than left as dead code.
    """
    request = aass_mod.SearchRequest(
        tokens=(b"t1",),
        authorized=(("dom0", "p0"), ("dom1", "p1"), ("dom2", "p1")),
        vid_u=0,
    )
    assert not hasattr(request, "policy_count")
    assert request.domains == ("dom0", "dom1", "dom2")


def test_request_refuses_an_unauthorized_query():
    """Phase VI Step 2 rejects before the index is traversed."""
    for kwargs in (
        dict(tokens=(), authorized=(("d", "p"),), vid_u=0),
        dict(tokens=(b"t",), authorized=(), vid_u=0),
    ):
        try:
            aass_mod.SearchRequest(**kwargs)
        except aass_mod.SchedulerError:
            continue
        raise AssertionError(f"{kwargs} should be refused")


# ===========================================================================
# scheduler/aass.py — the cost model
# ===========================================================================
def test_costs_are_the_four_published_terms():
    """SC_j = L1*C^index + L2*C^verify + L3*C^sync + L4*C^queue.

    FOUR, per eq:search-cost. This asserted five and named C^auth first,
    carried from the previous manuscript revision; the current one states four
    and the code was aligned to it on 2026-09-07. C^auth is gone entirely --
    authorization now enters scheduling only through `_candidates`, which still
    restricts selection to nodes serving an authorized domain.
    """
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized, vid=1)
    node = nodes[0]
    domain = sorted(node.domains)[0]
    request = make_request(keywords[domain], authorized, vid_u=1)

    costs = aass_mod.estimate_costs(node, request)
    assert not hasattr(costs, "auth"), "C^auth is not a term of eq:search-cost"
    assert costs.index == float(aass_mod.estimate_candidate_count(node, request))
    assert costs.sync == 0.0                    # VID_U == VID_j
    assert costs.queue == 0.0                   # empty queue
    assert costs.verify >= 0.0
    assert len(costs.as_tuple()) == 4


def test_cost_verify_scales_with_log_entry_count():
    """C_j^verify = |R_Q^(j)| * log N_j."""
    nodes, authorized, keywords = populated_federation(records_per_domain=8)
    sync_nodes(nodes, authorized)
    node = nodes[0]
    domain = sorted(node.domains)[0]
    request = make_request(keywords[domain], authorized, vid_u=0)
    predicted = aass_mod.estimate_result_count(node, request)
    costs = aass_mod.estimate_costs(node, request)
    import math

    expected = predicted * math.log2(node.entry_count)
    assert abs(costs.verify - expected) < 1e-9


def test_cost_sync_is_the_version_gap():
    """C_j^sync = |VID_U - VID_j| — the term that makes AASS prefer fresh nodes."""
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized, vid=2)
    node = nodes[0]
    domain = sorted(node.domains)[0]
    for vid_u, expected in ((2, 0.0), (5, 3.0), (0, 2.0)):
        request = make_request(keywords[domain], authorized, vid_u=vid_u)
        assert aass_mod.estimate_costs(node, request).sync == expected


def test_cost_queue_is_a_measured_wait():
    """C_j^queue = T_j^queue, a time — not a queue-length proxy."""
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized)
    node = nodes[0]
    domain = sorted(node.domains)[0]
    request = make_request(keywords[domain], authorized, vid_u=0)
    assert aass_mod.estimate_costs(node, request).queue == 0.0
    node.enqueue("q1")
    assert aass_mod.estimate_costs(node, request).queue > 0.0


def test_cost_estimation_does_not_evaluate_the_query():
    """AASS "predicts… before executing encrypted search" (Step 3).

    Estimation must not traverse the index. Checked by its side effects: a real
    search records service time and increments the served count, so a scheduler
    that searched would leave both changed.
    """
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized)
    node = nodes[0]
    domain = sorted(node.domains)[0]
    request = make_request(keywords[domain], authorized, vid_u=0)

    before = (node.service_ns, node.served_count)
    aass_mod.estimate_costs(node, request)
    assert (node.service_ns, node.served_count) == before


def test_result_estimate_bounds_the_true_count():
    """|R_Q^(j)| is the shortest posting list — an upper bound for a conjunction."""
    nodes, authorized, keywords = populated_federation(records_per_domain=5)
    sync_nodes(nodes, authorized)
    node = nodes[0]
    domain = sorted(node.domains)[0]
    request = make_request(keywords[domain], authorized, vid_u=0)
    predicted = aass_mod.estimate_result_count(node, request)
    response = search_mod.execute_search(node, request.tokens, authorized)
    assert response.result_count <= predicted


# ===========================================================================
# scheduler/aass.py — normalization
# ===========================================================================
def test_normalization_maps_terms_into_the_unit_interval():
    """Raw terms span orders of magnitude; unnormalized weights would be vacuous."""
    vectors = [
        aass_mod.CostVector(index=10000, verify=1000, sync=1, queue=5e6),
        aass_mod.CostVector(index=100, verify=10, sync=3, queue=1e6),
    ]
    normalized = aass_mod.normalize(vectors)
    for vector in normalized:
        for term in vector.as_tuple():
            assert 0.0 <= term <= 1.0


def test_normalization_maps_a_degenerate_term_to_zero():
    """A term equal on every node cannot affect arg min, so it must not consume weight."""
    vectors = [
        aass_mod.CostVector(index=10, verify=7, sync=0, queue=0),
        aass_mod.CostVector(index=20, verify=7, sync=0, queue=0),
    ]
    normalized = aass_mod.normalize(vectors, degenerate_value=0.0)
    # verify is identical across nodes -> 0.0 for both, despite being non-zero.
    assert normalized[0].verify == normalized[1].verify == 0.0
    # index differs -> retained and scaled.
    assert normalized[0].index < normalized[1].index == 1.0


def test_normalization_preserves_the_ordering_of_a_varying_term():
    """arg min must be unchanged by normalization, or it changes the decision."""
    vectors = [
        aass_mod.CostVector(index=i * 10, verify=0, sync=0, queue=0)
        for i in (3, 1, 2)
    ]
    normalized = aass_mod.normalize(vectors)
    assert normalized[1].index < normalized[2].index < normalized[0].index
    # The maximum maps to exactly 1.0 — no epsilon in the divisor.
    assert normalized[0].index == 1.0


def test_normalization_can_flip_arg_min_against_raw_scoring():
    """Why normalization is load-bearing, as a concrete arg-min flip.

    Raw terms span orders of magnitude, so a large ``C_index`` swamps a decisive
    ``C_sync`` and the weights become vacuous. Here raw scoring picks the STALE
    node and normalized scoring picks the fresh one — the whole point of the rule.
    """
    weights = config_mod.load().scheduler.weights
    fresh = aass_mod.CostVector(index=10000, verify=0, sync=0, queue=0)
    stale = aass_mod.CostVector(index=9000, verify=0, sync=100, queue=0)

    # Raw: C_index dominates, so the stale node scores lower and would be chosen.
    assert stale.score(weights) < fresh.score(weights)

    # Normalized: the terms are commensurable and the fresh node wins.
    n_fresh, n_stale = aass_mod.normalize([fresh, stale])
    assert n_fresh.score(weights) < n_stale.score(weights)


def test_scheduler_scores_from_normalized_terms():
    """The scheduler must actually normalize, not merely have a function that can.

    Pins the score to the normalized vector: with raw scoring the two would differ
    by orders of magnitude, and no behavioural test above happened to distinguish
    them.
    """
    nodes, authorized, keywords = populated_federation(records_per_domain=5)
    sync_nodes(nodes, authorized, vid=3)
    nodes[1].apply_meta("AA-extra", types.AuthorizationMeta(
        sorted(nodes[1].domains)[0], 1, bytes(32)
    ))
    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token(keywords[DOMAINS[0]]),),
        authorized=authorized,
        vid_u=3,
    )
    selection = aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(nodes, request)
    weights = selection.costs[0]  # placeholder to keep the name in scope
    for cost in selection.costs:
        assert abs(
            cost.score - cost.normalized.score(
                aass_mod.Scheduler(aass_mod.VARIANT_AASS).weights
            )
        ) < 1e-12
        for term in cost.normalized.as_tuple():
            assert 0.0 <= term <= 1.0
    # At least one term genuinely varied, so normalization was not a no-op.
    assert any(
        cost.normalized.as_tuple() != cost.raw.as_tuple()
        for cost in selection.costs
    )


def test_normalization_handles_all_zero_and_empty_inputs():
    zeros = [aass_mod.CostVector(0, 0, 0, 0)] * 2
    for vector in aass_mod.normalize(zeros):
        assert vector.as_tuple() == (0.0, 0.0, 0.0, 0.0)
    assert aass_mod.normalize([]) == ()


# ===========================================================================
# scheduler/aass.py — selection and the ablation variants
# ===========================================================================
def test_scheduler_rejects_an_unknown_variant():
    try:
        aass_mod.Scheduler("hand_wave")
    except aass_mod.SchedulerError:
        return
    raise AssertionError("an unknown variant should be refused")


def test_scheduler_has_exactly_the_four_variants():
    assert set(aass_mod.VARIANTS) == set(config_mod.load().scheduler.variants)


def test_scheduler_refuses_a_reportable_aass_run_while_weights_are_pending():
    """Exp. 7-8 must not report an unswept scheduler as AASS.

    The weights were fixed by the documented sweep on 2026-08-28, so a
    reportable AASS scheduler now builds. The gate is therefore exercised
    against a deliberately pending config rather than the live one -- the
    mechanism has to keep working after the weights are fixed, which is
    precisely when a regression here would go unnoticed.
    """
    import dataclasses

    # Fixed weights: a reportable scheduler builds.
    live = aass_mod.Scheduler(aass_mod.VARIANT_AASS, reportable=True)
    assert live.weights.is_fixed

    # Pending weights: still refused, with an actionable message.
    cfg = config_mod.load()
    pending_cfg = dataclasses.replace(
        cfg,
        scheduler=dataclasses.replace(
            cfg.scheduler,
            weights=dataclasses.replace(
                cfg.scheduler.weights, status="pending_sweep", provisional=True
            ),
        ),
    )
    try:
        aass_mod.Scheduler(
            aass_mod.VARIANT_AASS, config=pending_cfg, reportable=True
        )
    except config_mod.SchedulerWeightsPendingError as exc:
        assert "issue #5" in str(exc)
        return
    raise AssertionError("a reportable AASS run must be refused while pending")


def test_scheduler_allows_a_non_reportable_aass_run():
    """The sweep itself and smoke tests must still be able to run.

    No longer asserts the weights are unfixed -- that was true only before the
    2026-08-28 sweep. What matters is that reportable=False never refuses,
    since that is the path the sweep itself runs on.
    """
    scheduler = aass_mod.Scheduler(aass_mod.VARIANT_AASS, reportable=False)
    assert scheduler.is_authorization_aware


def test_scheduler_oblivious_variants_are_not_authorization_aware():
    """Only aass reads C_j^sync, which is why the VID_j rule affects it alone."""
    for variant in (
        aass_mod.VARIANT_NO_LB,
        aass_mod.VARIANT_ROUND_ROBIN,
        aass_mod.VARIANT_LEAST_LOADED,
    ):
        assert not aass_mod.Scheduler(variant).is_authorization_aware


def test_scheduler_no_lb_pins_one_node():
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized)
    scheduler = aass_mod.Scheduler(aass_mod.VARIANT_NO_LB)
    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token(keywords[DOMAINS[0]]),),
        authorized=authorized,
        vid_u=1,
    )
    chosen = {scheduler.select(nodes, request).node_id for _ in range(5)}
    assert len(chosen) == 1


def test_scheduler_round_robin_cycles():
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized)
    scheduler = aass_mod.Scheduler(aass_mod.VARIANT_ROUND_ROBIN)
    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token(keywords[DOMAINS[0]]),),
        authorized=authorized,
        vid_u=1,
    )
    picked = [scheduler.select(nodes, request).node_id for _ in range(8)]
    assert len(set(picked)) == 4                 # every candidate used
    assert picked[:4] == picked[4:]              # and cyclically


def test_scheduler_least_loaded_picks_the_shortest_queue():
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized)
    for index, node in enumerate(nodes):
        for q in range(3 - min(index, 3) + 1):
            node.enqueue(f"q{index}-{q}")
    scheduler = aass_mod.Scheduler(aass_mod.VARIANT_LEAST_LOADED)
    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token(keywords[DOMAINS[0]]),),
        authorized=authorized,
        vid_u=1,
    )
    selection = scheduler.select(nodes, request)
    shortest = min(node.queue_length for node in nodes)
    assert selection.node.queue_length == shortest


def test_scheduler_aass_prefers_the_fresher_node():
    """Phase VII Step 4: "the AASS scheduler naturally prefers fresh FSNs".

    Two nodes, identical in every term but their synchronized version. AASS must
    pick the one whose VID matches the user's; an authorization-oblivious variant
    cannot tell them apart.
    """
    nodes = fsn_mod.build_fsn_set(("dom0",), 1) + fsn_mod.build_fsn_set(
        ("dom0",), 1, prefix="FSNB"
    )
    authorized = (("dom0", "p0"),)
    # Same shard contents on both.
    for node in nodes:
        node.insert_entries(
            [
                types.IndexEntry(
                    token=scheme().index_token("kw"),
                    cid="cid-0",
                    policy_id="p0",
                    vid=0,
                )
            ],
            domain="dom0",
        )
    nodes[0].apply_meta("AA1", types.AuthorizationMeta("dom0", 5, bytes(32)))
    nodes[1].apply_meta("AA1", types.AuthorizationMeta("dom0", 1, bytes(32)))

    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token("kw"),), authorized=authorized, vid_u=5
    )
    selection = aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(nodes, request)
    assert selection.node_id == nodes[0].node_id       # the fresh node

    # The stale node's sync cost is strictly higher, which is why.
    fresh = selection.cost_for(nodes[0].node_id)
    stale = selection.cost_for(nodes[1].node_id)
    assert stale.raw.sync > fresh.raw.sync
    assert stale.score > fresh.score


def test_scheduler_aass_avoids_a_congested_node():
    """C_j^queue must be able to move the decision on its own."""
    nodes = fsn_mod.build_fsn_set(("dom0",), 1) + fsn_mod.build_fsn_set(
        ("dom0",), 1, prefix="FSNB"
    )
    for node in nodes:
        node.insert_entries(
            [
                types.IndexEntry(
                    token=scheme().index_token("kw"), cid="c", policy_id="p0", vid=0
                )
            ],
            domain="dom0",
        )
        node.apply_meta("AA1", types.AuthorizationMeta("dom0", 1, bytes(32)))
    nodes[0].enqueue("waiting", now_ns=0)          # a long-waiting request

    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token("kw"),), authorized=(("dom0", "p0"),), vid_u=1
    )
    selection = aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(nodes, request)
    assert selection.node_id == nodes[1].node_id   # the idle node


def test_scheduler_only_costs_nodes_holding_an_authorized_shard():
    """Costing a node with no authorized shard could select one that returns nothing."""
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized)
    one_domain = (authorized[0],)
    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token(keywords[one_domain[0][0]]),),
        authorized=one_domain,
        vid_u=1,
    )
    selection = aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(nodes, request)
    assert len(selection.costs) == 1
    assert selection.node.serves_domain(one_domain[0][0])


def test_scheduler_refuses_when_no_node_serves_the_domain():
    nodes, authorized, _ = populated_federation()
    request = aass_mod.SearchRequest(
        tokens=(b"t",), authorized=(("atlantis", "p0"),), vid_u=0
    )
    try:
        aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(nodes, request)
    except aass_mod.SchedulerError as exc:
        assert "no Fog Search Node serves" in str(exc)
        return
    raise AssertionError("an unserved domain should be refused")


def test_scheduler_selection_is_deterministic():
    """One trace must reproduce one decision, or Exp. 7-8 is not replayable."""
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized)
    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token(keywords[DOMAINS[0]]),),
        authorized=authorized,
        vid_u=1,
    )
    picked = {
        aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(nodes, request).node_id
        for _ in range(5)
    }
    assert len(picked) == 1


def test_scheduler_retains_the_evidence_for_its_decision():
    """A scheduler that cannot show its reasoning cannot be audited."""
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized)
    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token(keywords[DOMAINS[0]]),),
        authorized=authorized,
        vid_u=1,
    )
    selection = aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(nodes, request)
    assert len(selection.costs) == len(nodes)
    chosen = selection.cost_for(selection.node_id)
    assert chosen.score == min(cost.score for cost in selection.costs)


def test_scheduler_score_is_the_weighted_sum():
    weights = config_mod.load().scheduler.weights
    vector = aass_mod.CostVector(index=0.2, verify=0.3, sync=0.4, queue=0.5)
    expected = sum(
        term * weight for term, weight in zip(vector.as_tuple(), weights.as_tuple())
    )
    assert abs(vector.score(weights) - expected) < 1e-12


# ===========================================================================
# fsn/search.py — Phase VI Step 4
# ===========================================================================
def test_search_returns_the_published_triple():
    """R = {(CID_i, PID_i, VID_i) | T_Q -> I_i}."""
    nodes, authorized, keywords = populated_federation()
    domain, policy = authorized[0]
    node = [n for n in nodes if n.serves_domain(domain)][0]
    response = search_mod.execute_search(
        node, (scheme().query_token(keywords[domain]),), [(domain, policy)]
    )
    assert response.result_count >= 1
    for hit in response.hits:
        assert isinstance(hit, search_mod.SearchHit)
        assert hit.cid and hit.policy_id == policy
        assert hit.vid >= 0


def test_search_never_returns_the_token():
    """A hit carries the record's identity, not the lookup key that found it."""
    nodes, authorized, keywords = populated_federation()
    domain, policy = authorized[0]
    node = [n for n in nodes if n.serves_domain(domain)][0]
    response = search_mod.execute_search(
        node, (scheme().query_token(keywords[domain]),), [(domain, policy)]
    )
    fields = set(search_mod.SearchHit.__dataclass_fields__)
    assert fields == {"cid", "policy_id", "policy_state"}
    assert "token" not in fields


def test_search_rejects_an_unauthorized_request_without_traversing():
    """Phase VI Step 2: "rejected without traversing the encrypted index"."""
    nodes, authorized, keywords = populated_federation()
    domain, _ = authorized[0]
    node = [n for n in nodes if n.serves_domain(domain)][0]
    before = (node.service_ns, node.served_count)
    try:
        search_mod.execute_search(node, (b"token",), [])
    except search_mod.SearchRejected:
        assert (node.service_ns, node.served_count) == before
        return
    raise AssertionError("an unauthorized request should be rejected")


def test_search_rejects_a_node_holding_no_authorized_shard():
    nodes, authorized, keywords = populated_federation()
    domain, policy = authorized[0]
    wrong = [n for n in nodes if not n.serves_domain(domain)][0]
    try:
        search_mod.execute_search(
            wrong, (scheme().query_token(keywords[domain]),), [(domain, policy)]
        )
    except search_mod.SearchRejected as exc:
        assert "holds no shard" in str(exc)
        return
    raise AssertionError("a node without the authorized shard should refuse")


def test_search_scopes_authorization_to_the_nodes_own_domains():
    """Passing foreign-domain pairs must not inflate the candidate count.

    Not a correctness bug — the bitmaps hold nothing for them — but n_eff and the
    scheduler's C_index are computed from that count, so it would be a
    measurement bug.
    """
    nodes, authorized, keywords = populated_federation()
    domain, policy = authorized[0]
    node = [n for n in nodes if n.serves_domain(domain)][0]
    scoped = search_mod.execute_search(
        node, (scheme().query_token(keywords[domain]),), [(domain, policy)]
    )
    with_extras = search_mod.execute_search(
        node, (scheme().query_token(keywords[domain]),), list(authorized)
    )
    assert (
        scoped.statistics.authorized_candidates
        == with_extras.statistics.authorized_candidates
    )


def test_search_filters_before_matching():
    """§V :1892 — cost tracks n_eff, not total index size."""
    nodes, authorized, keywords = populated_federation(records_per_domain=6)
    domain, policy = authorized[0]
    node = [n for n in nodes if n.serves_domain(domain)][0]
    response = search_mod.execute_search(
        node, (scheme().query_token(keywords[domain]),), [(domain, policy)]
    )
    stats = response.statistics
    assert stats.n_eff == response.result_count
    assert stats.authorized_candidates <= stats.shard_entries
    assert 0.0 <= stats.prune_ratio <= 1.0


def test_search_records_service_time_for_utilization():
    """Exp. 8 samples utilization from accumulated service time."""
    nodes, authorized, keywords = populated_federation()
    domain, policy = authorized[0]
    node = [n for n in nodes if n.serves_domain(domain)][0]
    before = node.service_ns
    response = search_mod.execute_search(
        node, (scheme().query_token(keywords[domain]),), [(domain, policy)]
    )
    assert node.service_ns > before
    assert node.served_count == 1
    assert response.elapsed_ns > 0
    assert response.elapsed_ms == response.elapsed_ns / 1e6


def test_search_probing_can_leave_a_node_untouched():
    """A scheduler considering a node must not make it look busier."""
    nodes, authorized, keywords = populated_federation()
    domain, policy = authorized[0]
    node = [n for n in nodes if n.serves_domain(domain)][0]
    before = (node.service_ns, node.served_count)
    search_mod.execute_search(
        node,
        (scheme().query_token(keywords[domain]),),
        [(domain, policy)],
        record_service=False,
    )
    assert (node.service_ns, node.served_count) == before


def test_search_across_domains_uses_one_trapdoor():
    """The Exp. 3 path: d domains, ONE trapdoor, no per-domain token."""
    token_scheme = scheme()
    nodes = fsn_mod.build_fsn_set(DOMAINS, 4)
    shared = "cond:shared-across-domains"
    authorized = []
    for index, domain in enumerate(DOMAINS):
        node = [n for n in nodes if n.serves_domain(domain)][0]
        policy = f"{domain}/pol0"
        node.insert_entries(
            [
                types.IndexEntry(
                    token=token_scheme.index_token(shared),
                    cid=f"cid-{index}",
                    policy_id=policy,
                    vid=0,
                )
            ],
            domain=domain,
        )
        authorized.append((domain, policy))

    trapdoor = tokens_mod.generate_trapdoor(token_scheme, [shared])
    assert trapdoor.keyword_count == 1

    responses = search_mod.execute_search_across(
        nodes, trapdoor.tokens, authorized
    )
    assert len(responses) == 4
    merged = search_mod.merge_responses(responses)
    assert len(merged) == 4
    assert {hit.cid for hit in merged} == {f"cid-{i}" for i in range(4)}


def test_search_across_skips_nodes_without_an_authorized_shard():
    """"unnecessary encrypted-search operations over unrelated domains are avoided"."""
    nodes, authorized, keywords = populated_federation()
    domain, policy = authorized[0]
    responses = search_mod.execute_search_across(
        nodes, (scheme().query_token(keywords[domain]),), [(domain, policy)]
    )
    assert len(responses) == 1
    assert responses[0].node_id == [
        n.node_id for n in nodes if n.serves_domain(domain)
    ][0]
    # The skipped nodes were never searched.
    for node in nodes:
        if not node.serves_domain(domain):
            assert node.served_count == 0


def test_search_across_refuses_when_nothing_is_reachable():
    nodes, _, _ = populated_federation()
    try:
        search_mod.execute_search_across(nodes, (b"t",), [("atlantis", "p")])
    except search_mod.SearchRejected:
        return
    raise AssertionError("an unreachable authorization set should be refused")


def test_merge_deduplicates_by_cid():
    """A duplicated hit would inflate the r that Exp. 4 sweeps."""
    hit = search_mod.SearchHit(cid="c1", policy_id="p", policy_state=0)
    stats = search_mod.SearchStatistics(1, 1, 1, 1, 0)
    responses = [
        search_mod.SearchResponse("FSN1", (hit,), stats, 10),
        search_mod.SearchResponse("FSN2", (hit,), stats, 10),
    ]
    assert search_mod.merge_responses(responses) == (hit,)


def test_aggregate_statistics_sums_the_per_node_measurements():
    stats = search_mod.SearchStatistics(2, 5, 7, 11, 1)
    responses = [
        search_mod.SearchResponse("FSN1", (), stats, 10),
        search_mod.SearchResponse("FSN2", (), stats, 20),
    ]
    total = search_mod.aggregate_statistics(responses)
    assert (total.n_eff, total.entries_traversed) == (4, 10)
    assert (total.authorized_candidates, total.shard_entries) == (14, 22)
    try:
        search_mod.aggregate_statistics([])
    except ValueError:
        return
    raise AssertionError("aggregating nothing should raise")


# ===========================================================================
# Phase VI Steps 3-4 together
# ===========================================================================
def test_phase_vi_schedule_then_search():
    """Select a node, search only that node, get the record back."""
    nodes, authorized, keywords = populated_federation(records_per_domain=4)
    sync_nodes(nodes, authorized, vid=1)
    domain, policy = authorized[0]
    request = make_request(keywords[domain], ((domain, policy),), vid_u=1)

    selection = aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(nodes, request)
    assert selection.node.serves_domain(domain)

    response = search_mod.execute_search(
        selection.node, request.tokens, request.authorized
    )
    assert response.result_count >= 1
    assert response.node_id == selection.node_id
    # Only the selected node did any work.
    for node in nodes:
        if node.node_id != selection.node_id:
            assert node.served_count == 0


def test_phase_vi_all_four_variants_run_the_same_workload():
    """Exp. 7-8 is an ablation: one workload, four selection rules.

    All four must complete and return a node holding an authorized shard —
    otherwise a variant would be compared on a different query set.
    """
    nodes, authorized, keywords = populated_federation()
    sync_nodes(nodes, authorized, vid=1)
    request = aass_mod.SearchRequest(
        tokens=(scheme().query_token(keywords[DOMAINS[0]]),),
        authorized=authorized,
        vid_u=1,
    )
    chosen = {}
    for variant in aass_mod.VARIANTS:
        selection = aass_mod.Scheduler(variant).select(nodes, request)
        chosen[variant] = selection.node_id
        assert set(selection.node.domains) & set(request.domains)
    assert len(chosen) == 4


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
