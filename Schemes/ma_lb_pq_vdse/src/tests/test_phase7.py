#!/usr/bin/env python3
"""Verification tests for MA-LB-PQ-VDSE Phase VII (IAS).

Each test checks a DEFINING PROPERTY. An update that produces the right root by
rebuilding the whole index has passed the shallow test and is the exact bug
README §5's Exp. 5 rule calls out.

Runs standalone with no test framework::

    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase7.py            # all
    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase7.py revoke     # one area

and is also collectible by pytest if it is installed.

Covers ``sync/ias.py``. Phase VII Step 1 is the request record; Steps 2-7 are the
mechanism. Step 7 anchors to the in-process ledger, since Fabric is still deferred.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Common.crypto import hashes  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import types  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.aim import aim as aim_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.chain import ledger as ledger_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.fsn import fsn as fsn_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.fsn import search as search_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import commit as commit_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import extract as extract_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import tokens as tokens_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.shard import propagation as prop_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.sync import ias as ias_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.tests import test_phase1_2 as p12  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.tests import test_phase4 as p4  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


DOMAINS = extract_mod.DEFAULT_DOMAIN_NAMES
SEARCH_KEY = hashes.sha256(b"phase7-search-key", domain=b"test/search-key")
AUTH_ROOT_DO = hashes.sha256(b"AuthRoot_DO", domain=b"test/auth-root")


# ===========================================================================
# Fixtures
# ===========================================================================
def scheme() -> tokens_mod.TokenScheme:
    return tokens_mod.TokenScheme.keyed(SEARCH_KEY)


def token_for(keyword: str) -> bytes:
    return scheme().index_token(keyword)


def outsourced_record(keywords: int = 6, dom: int = 0):
    """One record indexed, committed and propagated to its domain's node.

    Returns everything Phase VII needs: the nodes, the authority governing that
    domain, the record's entries and commitment, and the CID.
    """
    token_scheme = scheme()
    nodes = fsn_mod.build_fsn_set(DOMAINS, 4)
    record = extract_mod.extract(
        p4.make_corpus_record(rid=0, patient="patient-0001", dom=dom, keywords=keywords),
        assignment=p4.make_assignment(2),
    )
    cid = prop_mod.placeholder_cid(0)
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
    prop_mod.propagate_to_authorized(payload, domain=record.domain, nodes=nodes)
    commitment = commit_mod.commit_record(
        record_id=0,
        entries=entries,
        policy_id=record.policy_id,
        vid=record.metadata.vid,
        auth_root_do=AUTH_ROOT_DO,
    )
    authority = p12.make_authority(f"AA-{record.domain}", record.domain)

    # Give every node serving that domain the authority's initial state.
    for node in nodes:
        if node.serves_domain(record.domain):
            node.apply_meta(authority.authority_id, authority.meta())
    return nodes, authority, record, entries, commitment, cid


def revoke_request(cid: str, *identifiers: str) -> ias_mod.UpdateRequest:
    return ias_mod.UpdateRequest(
        operation=ias_mod.Operation.REVOKE,
        cid=cid,
        delta=ias_mod.UpdateDelta(revoked=tuple(identifiers or ("patient-9",))),
    )


def modify_request(cid: str, policy_id: str) -> ias_mod.UpdateRequest:
    return ias_mod.UpdateRequest(
        operation=ias_mod.Operation.MODIFY,
        cid=cid,
        delta=ias_mod.UpdateDelta(policy_id=policy_id),
    )


# ===========================================================================
# Step 1 — the update request
# ===========================================================================
def test_request_covers_the_four_published_operations():
    """Op in {Insert, Modify, Delete, Revoke} (:1007)."""
    assert {op.value for op in ias_mod.Operation} == {
        "Insert",
        "Modify",
        "Delete",
        "Revoke",
    }


def test_request_validates_the_delta_each_operation_needs():
    cid = "cid-0"
    for operation, delta in (
        (ias_mod.Operation.INSERT, ias_mod.UpdateDelta()),
        (ias_mod.Operation.DELETE, ias_mod.UpdateDelta()),
        (ias_mod.Operation.MODIFY, ias_mod.UpdateDelta()),
        (ias_mod.Operation.REVOKE, ias_mod.UpdateDelta()),
    ):
        try:
            ias_mod.UpdateRequest(operation=operation, cid=cid, delta=delta)
        except ias_mod.IASError:
            continue
        raise AssertionError(f"{operation} with an empty delta should be refused")


def test_request_refuses_revocation_smuggled_into_another_operation():
    """One mechanism per operation, so Exp. 6 measures one thing."""
    try:
        ias_mod.UpdateRequest(
            operation=ias_mod.Operation.MODIFY,
            cid="cid-0",
            delta=ias_mod.UpdateDelta(policy_id="p1", revoked=("u1",)),
        )
    except ias_mod.IASError as exc:
        assert "revocation information" in str(exc)
        return
    raise AssertionError("revocation inside a Modify should be refused")


def test_operation_classifies_what_it_touches():
    """Revoke changes authorization state only; Insert/Delete change no VID_k."""
    assert not ias_mod.Operation.REVOKE.touches_index
    assert ias_mod.Operation.REVOKE.touches_authorization
    assert ias_mod.Operation.MODIFY.touches_index
    assert ias_mod.Operation.MODIFY.touches_authorization
    for op in (ias_mod.Operation.INSERT, ias_mod.Operation.DELETE):
        assert op.touches_index
        assert not op.touches_authorization


def test_delta_reports_the_exp5_sweep_variable():
    """Exp. 5 sweeps k = (keyword, document) pairs."""
    delta = ias_mod.UpdateDelta(
        keywords_added=("a", "b"), keywords_removed=("c",)
    )
    assert delta.keyword_pair_count == 3


# ===========================================================================
# Step 3 — authorization-state evolution
# ===========================================================================
def test_evolution_increments_the_version_by_exactly_one():
    """VID_k' = VID_k + 1 (:1045).

    A version that could jump would break C_j^sync as a distance: a node one
    update behind and a node five behind must not look alike.
    """
    authority = p12.make_authority("AA1", "dom0")
    assert authority.vid == 0
    for expected in (1, 2, 3):
        evolution = ias_mod.evolve_authorization_state(authority, revoke=(f"u{expected}",))
        assert evolution.new_vid == expected
        assert evolution.delta_vid == 1
        assert authority.vid == expected


def test_evolution_updates_the_revocation_root_and_commitment():
    authority = p12.make_authority("AA1", "dom0")
    evolution = ias_mod.evolve_authorization_state(authority, revoke=("patient-7",))
    assert evolution.new_revocation_root != evolution.previous_revocation_root
    assert evolution.new_commitment != evolution.previous_commitment
    assert authority.commitment() == evolution.new_commitment


def test_evolution_recomputes_the_commitment_from_its_five_inputs():
    """C_k^auth' must be the published function of the evolved state."""
    from Schemes.ma_lb_pq_vdse.src.authority import authority as authority_mod

    authority = p12.make_authority("AA1", "dom0")
    evolution = ias_mod.evolve_authorization_state(authority, revoke=("u1",))
    assert evolution.new_commitment == authority_mod.authorization_state_commitment(
        authority_id=authority.authority_id,
        domain=authority.domain,
        namespace_digest_value=authority.namespace_digest(),
        vid=evolution.new_vid,
        revocation_root=evolution.new_revocation_root,
    )


def test_evolution_leaves_other_authorities_untouched():
    """"Only the affected authority updates its commitment" (:1045).

    The property Exp. 6's selective propagation rests on.
    """
    context = p12.initializer.initialize(group_provider=p12.stub_provider)
    authorities = [
        p12.make_authority(f"AA{i}", DOMAINS[i - 1], context=context)
        for i in range(1, 5)
    ]
    before = {a.authority_id: (a.vid, a.commitment()) for a in authorities}
    ias_mod.evolve_authorization_state(authorities[1], revoke=("patient-7",))
    for authority in authorities:
        vid, commitment = before[authority.authority_id]
        if authority is authorities[1]:
            assert authority.vid == vid + 1
            assert authority.commitment() != commitment
        else:
            assert (authority.vid, authority.commitment()) == (vid, commitment)


def test_evolution_supports_restoring_a_revoked_identifier():
    authority = p12.make_authority("AA1", "dom0")
    ias_mod.evolve_authorization_state(authority, revoke=("u1",))
    root_with = authority.revocation_root()
    evolution = ias_mod.evolve_authorization_state(authority, restore=("u1",))
    assert evolution.new_revocation_root != root_with
    assert authority.vid == 2          # a restore is still a version advance


# ===========================================================================
# Step 2 — localized index evolution
# ===========================================================================
def test_modify_rewrites_payload_but_no_token():
    """Option D's consequence, and the basis of Exp. 5's incrementality.

    As published, Step 2 recomputes T_j' from the policy and version. Under
    Option D the token is H(w), so a policy change rewrites payload only and
    tokens_rewritten stays 0.
    """
    _, _, record, entries, _, cid = outsourced_record(keywords=6)
    evolution = ias_mod.evolve_index_entries(
        entries, modify_request(cid, "dom0/new-policy"), token_for=token_for
    )
    assert evolution.entries_rewritten == 6
    assert evolution.tokens_rewritten == 0
    assert [e.token for e in evolution.entries] == [e.token for e in entries]
    assert all(e.policy_id == "dom0/new-policy" for e in evolution.entries)


def test_revoke_touches_no_index_entry():
    """A revocation changes authorization state only, not the index.

    This is what lets Exp. 6 measure the IAS mechanism rather than re-indexing a
    domain of 285,268 records.
    """
    _, _, _, entries, _, cid = outsourced_record()
    evolution = ias_mod.evolve_index_entries(
        entries, revoke_request(cid, "patient-7"), token_for=token_for
    )
    assert evolution.entries_touched == 0
    assert evolution.entries == entries


def test_insert_adds_only_the_new_keywords():
    _, _, _, entries, _, cid = outsourced_record(keywords=6)
    request = ias_mod.UpdateRequest(
        operation=ias_mod.Operation.INSERT,
        cid=cid,
        delta=ias_mod.UpdateDelta(keywords_added=("cond:new-1", "cond:new-2")),
    )
    evolution = ias_mod.evolve_index_entries(entries, request, token_for=token_for)
    assert evolution.entries_inserted == 2
    assert len(evolution.entries) == 8
    # The record's other entries are rewritten too: Step 2's I_j' primes VID_i',
    # and all of a record's entries share one (PID_i, VID_i) pair, which Commit_i
    # and Sync_i both bind. Bounded by |W_i|, so still per-record.
    assert evolution.entries_rewritten == 6
    assert all(e.vid == entries[0].vid + 1 for e in evolution.entries)
    assert evolution.tokens_rewritten == 0


def test_insert_refuses_a_keyword_already_indexed():
    _, _, record, entries, _, cid = outsourced_record()
    request = ias_mod.UpdateRequest(
        operation=ias_mod.Operation.INSERT,
        cid=cid,
        delta=ias_mod.UpdateDelta(keywords_added=(record.keywords[0],)),
    )
    try:
        ias_mod.evolve_index_entries(entries, request, token_for=token_for)
    except ias_mod.IASError as exc:
        assert "already indexed" in str(exc)
        return
    raise AssertionError("re-inserting an indexed keyword should be refused")


def test_delete_removes_only_the_named_keywords():
    _, _, record, entries, _, cid = outsourced_record(keywords=6)
    request = ias_mod.UpdateRequest(
        operation=ias_mod.Operation.DELETE,
        cid=cid,
        delta=ias_mod.UpdateDelta(keywords_removed=record.keywords[:2]),
    )
    evolution = ias_mod.evolve_index_entries(entries, request, token_for=token_for)
    assert evolution.entries_removed == 2
    assert len(evolution.entries) == 4


def test_delete_refuses_when_a_named_keyword_is_absent():
    _, _, _, entries, _, cid = outsourced_record()
    request = ias_mod.UpdateRequest(
        operation=ias_mod.Operation.DELETE,
        cid=cid,
        delta=ias_mod.UpdateDelta(keywords_removed=("cond:never-indexed",)),
    )
    try:
        ias_mod.evolve_index_entries(entries, request, token_for=token_for)
    except ias_mod.IASError as exc:
        assert "matched" in str(exc)
        return
    raise AssertionError("deleting an absent keyword should be refused")


def test_delete_refuses_to_empty_a_record():
    """A record with no entries has no Merkle root (Phase IV Step 4)."""
    _, _, record, entries, _, cid = outsourced_record(keywords=6)
    request = ias_mod.UpdateRequest(
        operation=ias_mod.Operation.DELETE,
        cid=cid,
        delta=ias_mod.UpdateDelta(keywords_removed=record.keywords),
    )
    try:
        ias_mod.evolve_index_entries(entries, request, token_for=token_for)
    except ias_mod.IASError as exc:
        assert "no index entries" in str(exc)
        return
    raise AssertionError("emptying a record should be refused")


# ===========================================================================
# Step 4 — incremental Merkle commitment update
# ===========================================================================
def test_modify_updates_the_path_without_rebuilding():
    """Root_i' = MerkleUpdate(Root_i, L_delta) — the Exp. 5 rule."""
    _, _, _, entries, commitment, cid = outsourced_record(keywords=6)
    evolution = ias_mod.evolve_index_entries(
        entries, modify_request(cid, "dom0/new"), token_for=token_for
    )
    result = ias_mod.evolve_commitment(
        commitment,
        evolution,
        policy_id="dom0/new",
        vid=entries[0].vid,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert not result.rebuilt
    assert result.commitment.root != result.previous_root
    assert result.nodes_recomputed > 0
    # Matches a full rebuild's root — correctness of the incremental path.
    rebuilt_root, _ = commit_mod.record_root(evolution.entries)
    assert result.commitment.root == rebuilt_root


def test_insert_rebuilds_only_that_records_tree():
    """A leaf-count change cannot be a path update.

    Bounded by |W_i| (mean 31.7, capped 64), NOT by the index — README §5 forbids
    a global rebuild, and ~32 leaves is not one. `rebuilt` says which happened so
    a reported figure cannot conflate them.
    """
    _, _, _, entries, commitment, cid = outsourced_record(keywords=6)
    request = ias_mod.UpdateRequest(
        operation=ias_mod.Operation.INSERT,
        cid=cid,
        delta=ias_mod.UpdateDelta(keywords_added=("cond:new",)),
    )
    evolution = ias_mod.evolve_index_entries(entries, request, token_for=token_for)
    result = ias_mod.evolve_commitment(
        commitment,
        evolution,
        policy_id=entries[0].policy_id,
        vid=evolution.entries[0].vid,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert result.rebuilt
    assert result.commitment.entry_count == 7
    assert result.nodes_recomputed <= 2 * 7      # bounded by the record, not N


def test_commitment_evolution_refreshes_commit_i():
    _, _, _, entries, commitment, cid = outsourced_record()
    evolution = ias_mod.evolve_index_entries(
        entries, modify_request(cid, "dom0/new"), token_for=token_for
    )
    result = ias_mod.evolve_commitment(
        commitment,
        evolution,
        policy_id="dom0/new",
        vid=entries[0].vid,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert commit_mod.verify_commitment(
        result.commitment,
        policy_id="dom0/new",
        vid=entries[0].vid,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert result.commitment.commit != commitment.commit


# ===========================================================================
# Step 5 — the IAS message
# ===========================================================================
def test_ias_message_carries_the_published_tuple():
    """IAS_i = (CID_i, dVID_i, dC_i^auth, dI_i, dRoot_i, Commit_i')."""
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    authorization = ias_mod.evolve_authorization_state(authority, revoke=("u1",))
    index_evolution = ias_mod.evolve_index_entries(
        entries, revoke_request(cid, "u1"), token_for=token_for
    )
    commitment_evolution = ias_mod.evolve_commitment(
        commitment,
        index_evolution,
        policy_id=record.policy_id,
        vid=record.metadata.vid,
        auth_root_do=AUTH_ROOT_DO,
    )
    message = ias_mod.build_ias_message(
        cid=cid,
        authorization=authorization,
        index_evolution=index_evolution,
        commitment_evolution=commitment_evolution,
    )
    assert message.cid == cid
    assert message.delta_vid == 1
    assert message.authority_commitment == authorization.new_commitment
    assert message.root == commitment_evolution.commitment.root
    assert message.commit == commitment_evolution.commitment.commit


def test_ias_message_for_a_revocation_carries_no_index_delta():
    """dI_i is empty, so the message stays small however many records exist.

    The property Exp. 6's message-size metric reports.
    """
    nodes, authority, record, entries, commitment, cid = outsourced_record(keywords=6)
    receipt = ias_mod.synchronize(
        revoke_request(cid, "patient-7"),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert not receipt.message.carries_index_delta
    assert receipt.message.entries == ()

    # And a Modify, which does carry entries, is strictly larger.
    nodes2, authority2, record2, entries2, commitment2, cid2 = outsourced_record()
    modify = ias_mod.synchronize(
        modify_request(cid2, "dom0/new"),
        authority=authority2,
        nodes=nodes2,
        commitment=commitment2,
        entries=entries2,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert modify.message.size_bytes > receipt.message.size_bytes


def test_ias_message_reports_its_size_in_kb():
    """Exp. 6 secondary metric; README §9 reports sizes in KB."""
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    receipt = ias_mod.synchronize(
        modify_request(cid, "dom0/new"),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert receipt.message.size_kb == receipt.message.size_bytes / 1024.0
    assert receipt.message_size_kb > 0


def test_ias_message_binds_every_field():
    fields = dict(
        cid="c",
        delta_vid=1,
        authority_commitment=bytes(32),
        entries=(),
        root=bytes(range(32)),
        commit=hashes.sha256(b"commit", domain=b"t"),
        authority_id="AA1",
        domain="dom0",
    )
    base = ias_mod.IASMessage(**fields).digest()
    for name, replacement in (
        ("cid", "c2"),
        ("delta_vid", 2),
        ("authority_commitment", bytes(range(32))),
        ("root", bytes(32)),
        ("commit", hashes.sha256(b"other", domain=b"t")),
        ("authority_id", "AA2"),
        ("domain", "dom1"),
    ):
        assert ias_mod.IASMessage(**{**fields, name: replacement}).digest() != base, (
            f"{name} not bound"
        )


def test_ias_message_refuses_a_negative_version_delta():
    """Authorization versions only advance."""
    try:
        ias_mod.IASMessage(
            cid="c",
            delta_vid=-1,
            authority_commitment=bytes(32),
            entries=(),
            root=bytes(32),
            commit=bytes(32),
            authority_id="AA1",
            domain="dom0",
        )
    except ValueError as exc:
        assert "only" in str(exc)
        return
    raise AssertionError("a negative dVID should be refused")


# ===========================================================================
# Step 6 — selective synchronization
# ===========================================================================
def test_selective_propagation_touches_one_node_in_four():
    """"the AIM forwards IAS_i ONLY to FSNs that maintain the affected shards"."""
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    receipt = ias_mod.synchronize(
        revoke_request(cid, "patient-7"),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert receipt.touched_count == 1
    assert len(nodes) == 4
    touched = receipt.fsns_touched[0]
    for node in nodes:
        if node.node_id == touched:
            assert node.serves_domain(record.domain)


def test_selective_propagation_advances_only_the_affected_nodes_version():
    """Phase VI's C_j^sync is what makes staleness visible; only one node moves."""
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    affected = [n for n in nodes if n.serves_domain(record.domain)]
    others = [n for n in nodes if not n.serves_domain(record.domain)]
    assert affected[0].vid_for_authority(authority.authority_id) == 0

    ias_mod.synchronize(
        revoke_request(cid, "patient-7"),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert affected[0].vid_for_authority(authority.authority_id) == 1
    for node in others:
        assert authority.authority_id not in node.synced_authorities()


def test_apply_ias_refuses_a_node_outside_the_affected_domain():
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    authorization = ias_mod.evolve_authorization_state(authority, revoke=("u1",))
    index_evolution = ias_mod.evolve_index_entries(
        entries, revoke_request(cid, "u1"), token_for=token_for
    )
    commitment_evolution = ias_mod.evolve_commitment(
        commitment, index_evolution, policy_id=record.policy_id,
        vid=record.metadata.vid, auth_root_do=AUTH_ROOT_DO,
    )
    message = ias_mod.build_ias_message(
        cid=cid,
        authorization=authorization,
        index_evolution=index_evolution,
        commitment_evolution=commitment_evolution,
    )
    wrong = [n for n in nodes if not n.serves_domain(record.domain)][0]
    try:
        ias_mod.apply_ias(wrong, message)
    except ias_mod.IASError as exc:
        assert "not an affected node" in str(exc)
        return
    raise AssertionError("an unaffected node should refuse the message")


def test_apply_ias_repolicies_the_shard_entries():
    """Shard_j' = ApplyIAS(Shard_j, IAS_i): the bitmap moves with the policy."""
    nodes, authority, record, entries, commitment, cid = outsourced_record(keywords=6)
    node = [n for n in nodes if n.serves_domain(record.domain)][0]
    old_pair = (record.domain, record.policy_id)
    new_policy = f"{record.domain}/repolicied"

    assert len(node.index.candidates([old_pair])) == 6
    receipt = ias_mod.synchronize(
        modify_request(cid, new_policy),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert receipt.entries_rewritten == 6
    assert node.index.candidates([old_pair]) == set()
    assert len(node.index.candidates([(record.domain, new_policy)])) == 6
    # N_j unchanged: a repolicy moves bits, it does not add or remove entries.
    assert node.entry_count == 6


def test_apply_ias_does_not_rewrite_tokens_or_postings():
    """The Exp. 5 property, checked at the shard level."""
    nodes, authority, record, entries, commitment, cid = outsourced_record(keywords=6)
    node = [n for n in nodes if n.serves_domain(record.domain)][0]
    postings_before = {k: list(v) for k, v in node.index._postings.items()}

    ias_mod.synchronize(
        modify_request(cid, f"{record.domain}/new"),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert {k: list(v) for k, v in node.index._postings.items()} == postings_before


def test_apply_ias_detects_a_delivery_gap():
    """IAS_i carries dVID, so a node that missed a message cannot catch up.

    An observation about the published design, surfaced rather than hidden: a
    gapped node would otherwise settle on a version nobody published.
    """
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    # Advance the authority twice but deliver only the second message.
    ias_mod.evolve_authorization_state(authority, revoke=("u1",))
    authorization = ias_mod.evolve_authorization_state(authority, revoke=("u2",))
    assert authorization.new_vid == 2

    index_evolution = ias_mod.evolve_index_entries(
        entries, revoke_request(cid, "u2"), token_for=token_for
    )
    commitment_evolution = ias_mod.evolve_commitment(
        commitment, index_evolution, policy_id=record.policy_id,
        vid=record.metadata.vid, auth_root_do=AUTH_ROOT_DO,
    )
    message = ias_mod.build_ias_message(
        cid=cid,
        authorization=authorization,
        index_evolution=index_evolution,
        commitment_evolution=commitment_evolution,
    )
    node = [n for n in nodes if n.serves_domain(record.domain)][0]
    result = ias_mod.apply_ias(node, message)
    # The node applied dVID=1 to its stale 0 and reached 1, not 2.
    assert result.new_vid == 1 != authorization.new_vid


# ===========================================================================
# Step 7 — blockchain anchoring
# ===========================================================================
def test_anchor_records_the_published_tuple():
    """BC_i' = (CID_i, Commit_i', Root_i', VID_i', TS_i')."""
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    chain = ledger_mod.InProcessLedger()
    receipt = ias_mod.synchronize(
        revoke_request(cid, "u1"),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
        ledger=chain,
    )
    keys = chain.keys(ledger_mod.NS_VERSION_IDENTIFIERS)
    assert len(keys) == 1
    anchor = chain.get(ledger_mod.NS_VERSION_IDENTIFIERS, keys[0]).record
    assert anchor.cid == cid
    assert anchor.commit == receipt.message.commit
    assert anchor.root == receipt.message.root
    assert anchor.vid == 1
    assert anchor.timestamp_ns > 0
    assert chain.verify_chain()


def test_anchor_history_is_append_only():
    """"a tamper-evident history of dynamic index evolution".

    Uses Modify, not Revoke: BC_i' carries the RECORD's version, and a revocation
    changes no index entry — so Root_i' and Commit_i' equal the anchored ones and
    there is nothing new to record. Only updates that change the record produce a
    new anchor.
    """
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    chain = ledger_mod.InProcessLedger()
    current_entries, current_commitment = entries, commitment
    for round_index in range(3):
        receipt = ias_mod.synchronize(
            modify_request(cid, f"{record.domain}/pol-{round_index}"),
            authority=authority,
            nodes=nodes,
            commitment=current_commitment,
            entries=current_entries,
            auth_root_do=AUTH_ROOT_DO,
            ledger=chain,
        )
        current_commitment = receipt.commitment_evolution.commitment
        current_entries = receipt.index_evolution.entries
    keys = chain.keys(ledger_mod.NS_VERSION_IDENTIFIERS)
    assert len(keys) == 3                     # every version retained
    assert keys == sorted(keys)               # and ordered by version
    assert chain.verify_chain()


def test_revocation_anchors_nothing_new():
    """A revoke leaves Root_i and Commit_i unchanged, so BC_i' would duplicate BC_i.

    The record's version and the authority's version are separate counters; keying
    the anchor by the authority's would collide with the Phase V Step 3 anchor
    whenever the two happen to coincide.
    """
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    chain = ledger_mod.InProcessLedger()
    ias_mod.anchor_update(
        chain,
        message=ias_mod.IASMessage(
            cid=cid, delta_vid=0,
            authority_commitment=hashes.sha256(b"c", domain=b"t"),
            entries=(), root=commitment.root, commit=commitment.commit,
            authority_id=authority.authority_id, domain=record.domain,
        ),
        vid=record.metadata.vid,
    )
    before = len(chain.keys(ledger_mod.NS_VERSION_IDENTIFIERS))
    ias_mod.synchronize(
        revoke_request(cid, "patient-7"),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
        ledger=chain,
    )
    assert len(chain.keys(ledger_mod.NS_VERSION_IDENTIFIERS)) == before
    assert chain.verify_chain()


# ===========================================================================
# End to end, and the metrics Exp. 5 / Exp. 6 report
# ===========================================================================
def test_synchronize_reports_the_exp6_metrics():
    """IAS end-to-end: FSNs touched, message size, elapsed time."""
    nodes, authority, record, entries, commitment, cid = outsourced_record()
    aim = aim_mod.AuthorizationIndexManager()
    aim.register_meta(authority.authority_id, authority.meta())
    chain = ledger_mod.InProcessLedger()

    receipt = ias_mod.synchronize(
        revoke_request(cid, "patient-7"),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
        aim=aim,
        ledger=chain,
    )
    assert receipt.touched_count == 1
    assert receipt.message_size_kb > 0
    assert receipt.elapsed_ns > 0
    assert receipt.elapsed_ms == receipt.elapsed_ns / 1e6
    # The AIM's view advanced with the authority.
    assert aim.meta_for_authority(authority.authority_id).vid == 1


def test_synchronize_reports_the_exp5_metrics():
    """Merkle nodes recomputed and entries rewritten, both measured."""
    nodes, authority, record, entries, commitment, cid = outsourced_record(keywords=6)
    receipt = ias_mod.synchronize(
        modify_request(cid, f"{record.domain}/new"),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
    )
    assert receipt.merkle_nodes_recomputed > 0
    assert receipt.entries_rewritten == 6
    assert receipt.tokens_rewritten == 0        # Option D
    assert not receipt.commitment_evolution.rebuilt


def test_synchronize_leaves_the_record_searchable_under_the_new_policy():
    """The point of the whole phase: search still works after evolution."""
    nodes, authority, record, entries, commitment, cid = outsourced_record(keywords=6)
    node = [n for n in nodes if n.serves_domain(record.domain)][0]
    new_policy = f"{record.domain}/evolved"
    trapdoor = tokens_mod.generate_trapdoor(scheme(), [record.keywords[0]])

    # Findable under the old policy first.
    before = search_mod.execute_search(
        node, trapdoor.tokens, [(record.domain, record.policy_id)]
    )
    assert before.result_count == 1

    ias_mod.synchronize(
        modify_request(cid, new_policy),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
    )

    # The old authorization no longer reaches it; the new one does. Same token.
    after_old = search_mod.execute_search(
        node, trapdoor.tokens, [(record.domain, record.policy_id)]
    )
    assert after_old.result_count == 0
    after_new = search_mod.execute_search(
        node, trapdoor.tokens, [(record.domain, new_policy)]
    )
    assert after_new.result_count == 1
    assert after_new.hits[0].cid == cid


def test_insert_and_delete_do_not_advance_the_authority_version():
    """Step 3 conditions on policy/attribute/revocation changes only.

    Bumping VID_k on plain index churn would make Exp. 6's version-skew metric
    respond to keyword updates.
    """
    nodes, authority, record, entries, commitment, cid = outsourced_record(keywords=6)
    before = authority.vid
    receipt = ias_mod.synchronize(
        ias_mod.UpdateRequest(
            operation=ias_mod.Operation.INSERT,
            cid=cid,
            delta=ias_mod.UpdateDelta(keywords_added=("cond:brand-new",)),
        ),
        authority=authority,
        nodes=nodes,
        commitment=commitment,
        entries=entries,
        auth_root_do=AUTH_ROOT_DO,
        token_for=token_for,
    )
    assert authority.vid == before
    assert receipt.message.delta_vid == 0


def test_synchronize_has_no_broadcast_path():
    """Selectivity is the Exp. 6 claim; a fan-out would void it."""
    names = {n for n in dir(ias_mod) if not n.startswith("_")}
    assert not {"broadcast", "propagate_all", "sync_all", "apply_everywhere"} & names


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
