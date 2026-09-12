#!/usr/bin/env python3
"""Verification tests for MA-LB-PQ-VDSE Phase IV modules.

Each test checks a DEFINING PROPERTY. An index that returns entries but compacts
its ordinals on deletion has passed the shallow test and silently corrupted every
authorization bitmap in the shard.

Runs standalone with no test framework::

    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase4.py         # all
    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase4.py dsi     # one module

and is also collectible by pytest if it is installed.

Covers ``index/extract.py`` (Step 1), ``index/dsi.py`` (Step 3) and
``index/commit.py`` (Steps 4-5). Step 2 has no tests because it has no
implementation: the matching relation is an open author decision
(Phase IV §1). Every token below is an opaque byte string produced by
the test, which is exactly how ``dsi.py`` treats them.

The corpus is NOT read: the committed manifest is the superseded v1 and
``load_verified_corpus()`` refuses to load. Records are constructed here with the
corpus's field names and shape, so extraction is exercised without pretending to
provenance this machine does not have.
"""

from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT))

from Common.crypto import hashes, merkle  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import config as config_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src import types  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.fsn import fsn as fsn_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import commit as commit_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import dsi as dsi_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import extract as extract_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import tokens as tokens_mod  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


DOMAINS = extract_mod.DEFAULT_DOMAIN_NAMES


# ===========================================================================
# Fixtures
# ===========================================================================
@dataclass
class CorpusRecord:
    """Mirrors ``Dataset.corpus.Record`` — same field names, same shape.

    ``pid`` is a PATIENT pseudonym, as ``prepare_dataset.py:346`` fills it. The
    tests below rely on that being distinct from the access-policy identifier.
    """

    rid: int
    pid: str
    vid: int
    dom: int
    ts: str
    kw: List[str] = field(default_factory=list)


def make_corpus_record(
    rid: int = 0,
    patient: str = "patient-0001",
    vid: int = 1,
    dom: int = 0,
    keywords: int = 6,
) -> CorpusRecord:
    return CorpusRecord(
        rid=rid,
        pid=patient,
        vid=vid,
        dom=dom,
        ts="2026-08-10T12:00:00Z",
        kw=[f"cond:{rid}:{i}" for i in range(keywords)],
    )


def make_assignment(policies_per_domain: int = 5):
    return extract_mod.BucketedPolicyAssignment(
        policies_per_domain=policies_per_domain, domains=len(DOMAINS)
    )


def token_for(keyword: str) -> bytes:
    """An OPAQUE token stand-in.

    Not Phase IV Step 2: the matching relation is undecided, so this is only a
    distinct byte string per keyword, which is all ``dsi.py`` requires of a token.
    """
    return hashes.sha256(keyword.encode("utf-8"), domain=b"test/opaque-token")


def make_entries(
    record: extract_mod.ExtractedRecord, cid: str = "Qm-test-cid"
) -> Tuple[types.IndexEntry, ...]:
    return tuple(
        types.IndexEntry(
            token=token_for(keyword),
            cid=cid,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
        )
        for keyword in record.keywords
    )


def make_shard(domains=(DOMAINS[0],)) -> dsi_mod.DynamicSearchIndex:
    return dsi_mod.DynamicSearchIndex(domains=frozenset(domains))


def indexed_shard(
    records: int = 4, keywords: int = 6, policies_per_domain: int = 2
):
    """A shard holding several records of one domain, with their extractions."""
    assignment = make_assignment(policies_per_domain)
    shard = make_shard()
    extracted = []
    for rid in range(records):
        record = extract_mod.extract(
            make_corpus_record(
                rid=rid, patient=f"patient-{rid:04d}", dom=0, keywords=keywords
            ),
            assignment=assignment,
        )
        shard.insert_record(make_entries(record), domain=record.domain)
        extracted.append(record)
    return shard, extracted


# ===========================================================================
# index/extract.py — Phase IV Step 1
# ===========================================================================
def test_extract_is_a_projection_of_the_corpus_record():
    """No keyword invented, none dropped — the corpus did the clinical work."""
    record = make_corpus_record(keywords=7)
    extracted = extract_mod.extract(record, assignment=make_assignment())
    assert set(extracted.keywords) == set(record.kw)
    assert extracted.keyword_count == 7
    assert extracted.record_id == record.rid
    assert extracted.metadata.timestamp == record.ts
    assert extracted.metadata.vid == record.vid


def test_extract_sorts_keywords_for_a_reproducible_root():
    """Phase IV Step 4 batches per record; an order-dependent Root_i is unverifiable."""
    forward = make_corpus_record(keywords=6)
    shuffled = make_corpus_record(keywords=6)
    shuffled.kw = list(reversed(shuffled.kw))
    assert (
        extract_mod.extract(forward, assignment=make_assignment()).keywords
        == extract_mod.extract(shuffled, assignment=make_assignment()).keywords
    )


def test_extract_policy_id_is_not_the_patient_pseudonym():
    """PID_i is the ACCESS-POLICY identifier (:331, :630), not corpus Record.pid.

    Conflating them would give one policy per patient — ~38,000 over the frozen
    corpus — and index.yaml sizes its bitmap set as |Dom| x |PID|, so the choice
    lands on Exp. 2's n_eff.
    """
    record = make_corpus_record(patient="patient-9999")
    extracted = extract_mod.extract(record, assignment=make_assignment(5))
    assert extracted.policy_id != record.pid
    assert extracted.patient_pseudonym == record.pid


def test_extract_requires_an_explicit_policy_assignment():
    """No default: |PID| is an open decision and must not be made here silently."""
    try:
        extract_mod.extract(make_corpus_record())  # type: ignore[call-arg]
    except TypeError:
        return
    raise AssertionError("a policy assignment must be required")


def test_extract_policy_assignment_is_deterministic_and_bounded():
    assignment = make_assignment(policies_per_domain=5)
    record = make_corpus_record(patient="patient-4242")
    first = extract_mod.extract(record, assignment=assignment).policy_id
    second = extract_mod.extract(record, assignment=assignment).policy_id
    assert first == second
    ids = {
        extract_mod.extract(
            make_corpus_record(rid=i, patient=f"patient-{i:04d}"),
            assignment=assignment,
        ).policy_id
        for i in range(200)
    }
    assert 1 < len(ids) <= 5             # bounded by policies_per_domain
    assert assignment.policy_count == 5 * len(DOMAINS)


def test_extract_keeps_one_patient_under_one_policy():
    """A patient's records are governed together, which is what a policy means."""
    assignment = make_assignment(5)
    ids = {
        extract_mod.extract(
            make_corpus_record(rid=rid, patient="patient-0007"), assignment=assignment
        ).policy_id
        for rid in range(10)
    }
    assert len(ids) == 1


def test_extract_per_patient_assignment_is_available_and_labelled():
    """The dataset.yaml reading, offered explicitly rather than as a default."""
    assignment = extract_mod.PerPatientPolicyAssignment(patients=38000)
    extracted = extract_mod.extract(
        make_corpus_record(patient="patient-0001"), assignment=assignment
    )
    assert "patient-0001" in extracted.policy_id
    assert assignment.policy_count == 38000


def test_extract_rejects_a_record_below_the_query_size():
    """|W_i| < q can never match a conjunctive query, so indexing it adds dead weight."""
    try:
        extract_mod.extract(
            make_corpus_record(keywords=4), assignment=make_assignment(), min_keywords=5
        )
    except extract_mod.ExtractionError as exc:
        assert "can never match" in str(exc)
        return
    raise AssertionError("a short record should be refused")


def test_extract_rejects_duplicate_keywords():
    record = make_corpus_record(keywords=5)
    record.kw = record.kw + [record.kw[0]]
    try:
        extract_mod.extract(record, assignment=make_assignment())
    except extract_mod.ExtractionError:
        return
    raise AssertionError("duplicate keywords should be refused")


def test_extract_rejects_an_out_of_range_domain():
    try:
        extract_mod.extract(make_corpus_record(dom=9), assignment=make_assignment())
    except extract_mod.ExtractionError as exc:
        assert "out of range" in str(exc)
        return
    raise AssertionError("an unknown domain index should be refused")


def test_extract_metadata_binds_all_four_fields():
    """Meta_i = (PID_i, VID_i, Dom_i, TS_i)."""
    fields = dict(
        policy_id="dom0/pol0", vid=1, domain="dom0", timestamp="2026-08-10T12:00:00Z"
    )
    base = types.RecordMetadata(**fields)
    for name, replacement in (
        ("policy_id", "dom0/pol1"),
        ("vid", 2),
        ("domain", "dom1"),
        ("timestamp", "2026-08-11T12:00:00Z"),
    ):
        assert types.RecordMetadata(**{**fields, name: replacement}).digest() != (
            base.digest()
        ), f"{name} not bound"


def test_extract_all_streams_and_honours_a_limit():
    """A generator: materialising 1.14M records costs 1-2 GB."""
    records = (make_corpus_record(rid=i, patient=f"p{i}") for i in range(50))
    taken = list(
        extract_mod.extract_all(records, assignment=make_assignment(), limit=10)
    )
    assert len(taken) == 10
    assert [r.record_id for r in taken] == list(range(10))


# ===========================================================================
# index/dsi.py — Phase IV Step 3
# ===========================================================================
def test_dsi_insert_builds_postings_and_bitmaps():
    shard, extracted = indexed_shard(records=2, keywords=5)
    assert shard.entry_count == 10
    assert shard.token_count == 10          # distinct keywords per record
    assert len(shard.policy_pairs) >= 1
    assert all(domain == DOMAINS[0] for domain, _ in shard.policy_pairs)


def test_dsi_refuses_an_entry_from_another_domain():
    """Shards are domain-keyed, so authorization locality is real, not simulated."""
    shard = make_shard((DOMAINS[0],))
    record = extract_mod.extract(
        make_corpus_record(dom=1), assignment=make_assignment()
    )
    try:
        shard.insert(make_entries(record)[0], domain=record.domain)
    except dsi_mod.DSIError as exc:
        assert "cannot hold" in str(exc)
        return
    raise AssertionError("a foreign-domain entry should be refused")


def test_dsi_deletion_does_not_shift_other_ordinals():
    """The failure mode this test exists for: compaction silently re-points bitmaps.

    Every bitmap is indexed by ordinal. If deleting entry 0 shifted entry 1 down,
    every authorization bit in the shard would then refer to a different entry —
    an index that still returns results, all of them wrong.
    """
    shard, extracted = indexed_shard(records=1, keywords=6)
    entries_before = {o: shard.entry(o) for o in range(6)}
    shard.delete(0)
    assert shard.entry_count == 5
    assert shard.deleted_count == 1
    for ordinal in range(1, 6):
        assert shard.entry(ordinal) == entries_before[ordinal]


def test_dsi_deleted_ordinal_is_not_reused():
    shard, _ = indexed_shard(records=1, keywords=5)
    shard.delete(2)
    record = extract_mod.extract(
        make_corpus_record(rid=99, patient="patient-0099"),
        assignment=make_assignment(),
    )
    new_ordinal = shard.insert(make_entries(record)[0], domain=record.domain)
    assert new_ordinal == 5                 # appended, not slotted into 2
    try:
        shard.entry(2)
    except dsi_mod.DSIError:
        return
    raise AssertionError("a tombstoned ordinal must stay deleted")


def test_dsi_deletion_removes_the_entry_from_results():
    shard, extracted = indexed_shard(records=1, keywords=5)
    record = extracted[0]
    authorized = [(record.domain, record.policy_id)]
    token = token_for(record.keywords[0])
    found, _ = shard.lookup([token], authorized)
    assert len(found) == 1
    shard.delete(0)
    found, stats = shard.lookup([token], authorized)
    assert found == ()
    assert stats.n_eff == 0


def test_dsi_repolicy_leaves_the_token_untouched():
    """Phase IV Step 3 / Exp. 5: a policy change must not re-tokenize.

    The posting list is the thing whose rewrite would make Exp. 5 measure a
    rebuild instead of an incremental update.
    """
    shard, extracted = indexed_shard(records=1, keywords=5)
    record = extracted[0]
    postings_before = dict(shard._postings)
    updated = shard.repolicy(0, policy_id=f"{record.domain}/pol-new", vid=2)
    assert updated.token == shard.entry(0).token
    assert updated.policy_id == f"{record.domain}/pol-new"
    assert updated.vid == 2
    assert shard._postings == postings_before
    assert shard.entry_count == 5           # nothing inserted or removed


def test_dsi_repolicy_moves_the_authorization_bit():
    shard, extracted = indexed_shard(records=1, keywords=5)
    record = extracted[0]
    old_pair = (record.domain, record.policy_id)
    new_pair = (record.domain, f"{record.domain}/pol-new")
    assert 0 in shard.candidates([old_pair])
    shard.repolicy(0, policy_id=new_pair[1], vid=1)
    assert 0 not in shard.candidates([old_pair])
    assert 0 in shard.candidates([new_pair])


def test_dsi_authorization_filter_is_a_union_over_policies():
    """A user authorized for several policies may read entries under any of them."""
    shard, extracted = indexed_shard(records=6, keywords=5, policies_per_domain=3)
    pairs = list(shard.policy_pairs)
    assert len(pairs) >= 2
    single = shard.candidates([pairs[0]])
    both = shard.candidates(pairs[:2])
    assert single < both


def test_dsi_unauthorized_query_returns_nothing():
    """Phase VI Step 2: rejected without traversing the encrypted index."""
    shard, extracted = indexed_shard(records=2, keywords=5)
    record = extracted[0]
    found, stats = shard.lookup(
        [token_for(record.keywords[0])], [(record.domain, "dom0/not-my-policy")]
    )
    assert found == ()
    assert stats.authorized_candidates == 0


def test_dsi_reports_n_eff_and_prune_ratio_as_measurements():
    """§VI :1892 — cost tracks n_eff, so n_eff must be measured, not derived."""
    shard, extracted = indexed_shard(records=8, keywords=5, policies_per_domain=4)
    record = extracted[0]
    authorized = [(record.domain, record.policy_id)]
    found, stats = shard.lookup([token_for(record.keywords[0])], authorized)
    assert stats.n_eff == len(found)
    assert stats.shard_entries == shard.entry_count
    assert 0 <= stats.authorized_candidates <= stats.shard_entries
    assert 0.0 <= stats.prune_ratio <= 1.0
    # Authorization pruned something: fewer candidates than the whole shard.
    assert stats.authorized_candidates < stats.shard_entries


def test_dsi_filters_before_matching():
    """Filter-then-match, or the implementation refutes its own claim.

    With the query keyword present on many records but only one policy
    authorized, entries_traversed counts the posting list while n_eff counts only
    the authorized subset — so n_eff must be strictly smaller.
    """
    assignment = make_assignment(4)
    shard = make_shard()
    shared_keyword = "cond:shared"
    authorized_policy = None
    for rid in range(8):
        record = extract_mod.extract(
            make_corpus_record(rid=rid, patient=f"patient-{rid:04d}", keywords=5),
            assignment=assignment,
        )
        shard.insert(
            types.IndexEntry(
                token=token_for(shared_keyword),
                cid=f"cid-{rid}",
                policy_id=record.policy_id,
                vid=record.metadata.vid,
            ),
            domain=record.domain,
        )
        if authorized_policy is None:
            authorized_policy = record.policy_id
    found, stats = shard.lookup(
        [token_for(shared_keyword)], [(DOMAINS[0], authorized_policy)]
    )
    assert stats.entries_traversed == 8          # the whole posting list
    assert stats.n_eff == len(found) < 8         # only the authorized subset
    assert all(entry.policy_id == authorized_policy for entry in found)


def test_dsi_conjunctive_query_requires_every_keyword():
    """§VI's q-keyword conjunctive query — matched PER RECORD.

    This test used to assert ``found == ()`` with the comment "no single entry
    carries three different tokens", which codified the defect as intended
    behaviour: an ordinal is one entry and an entry holds one token, so
    intersecting ordinals made a q-keyword query unanswerable for ANY data,
    while the docstring claimed it implemented §VI's central search. The
    assertion and the docstring contradicted each other and the assertion won
    for months.

    A record satisfies the query when it carries every queried token; the
    entries returned are the ones that matched.
    """
    shard, extracted = indexed_shard(records=2, keywords=6)
    record = extracted[0]
    authorized = [(record.domain, record.policy_id)]
    present = [token_for(k) for k in record.keywords[:3]]
    found, _ = shard.lookup(present, authorized, conjunctive=True)
    assert found, "a 3-keyword conjunctive query over one record's own keywords"
    # One record satisfies it, so every returned entry shares that record's
    # CID. (`ExtractedRecord` has no cid -- it is assigned at outsourcing --
    # so the entries are what carry it.)
    assert len({e.cid for e in found}) == 1

    # A token the record does NOT carry makes the conjunction fail.
    missing = present + [token_for("keyword-this-record-does-not-have")]
    assert shard.lookup(missing, authorized, conjunctive=True)[0] == ()

    # Disjunctive over the same tokens still matches entrywise.
    found, _ = shard.lookup(present, authorized, conjunctive=False)
    assert len(found) == 3


def test_dsi_bloom_negative_is_definitive_and_never_drops_a_result():
    """A false positive costs one comparison; a false NEGATIVE would lose data."""
    shard, extracted = indexed_shard(records=2, keywords=5)
    record = extracted[0]
    authorized = [(record.domain, record.policy_id)]
    absent = token_for("keyword-that-was-never-indexed")
    found, stats = shard.lookup([absent], authorized)
    assert found == ()
    # Every indexed token must survive the filter — no false negatives.
    for keyword in record.keywords:
        found, _ = shard.lookup([token_for(keyword)], authorized, use_bloom=True)
        assert len(found) == 1
        found_nofilter, _ = shard.lookup(
            [token_for(keyword)], authorized, use_bloom=False
        )
        assert found == found_nofilter


def test_dsi_bloom_is_rebuilt_after_mutation():
    """Deletion cannot clear a Bloom bit, so the filter is rebuilt rather than decremented."""
    shard, extracted = indexed_shard(records=1, keywords=5)
    record = extracted[0]
    authorized = [(record.domain, record.policy_id)]
    shard.lookup([token_for(record.keywords[0])], authorized)   # builds the filter
    new_record = extract_mod.extract(
        make_corpus_record(rid=50, patient="patient-0050"), assignment=make_assignment()
    )
    entry = make_entries(new_record)[0]
    shard.insert(entry, domain=new_record.domain)
    found, _ = shard.lookup(
        [entry.token], [(new_record.domain, new_record.policy_id)]
    )
    assert len(found) == 1     # the newly inserted token is findable


def test_dsi_shards_partition_by_the_same_rule_as_the_nodes():
    """The shard set and the node set must not agree only by luck."""
    config = config_mod.load()
    assignment = fsn_mod.assign_domains_to_fsns(
        DOMAINS, config.topology.fog_search_nodes
    )
    shards = dsi_mod.build_shards(assignment)
    nodes = fsn_mod.build_fsn_set(DOMAINS, config.topology.fog_search_nodes)
    assert len(shards) == len(nodes) == 4
    for shard, node in zip(shards, nodes):
        assert shard.domains == node.domains


def test_dsi_shard_totals_account_for_every_entry():
    """Across shards, nothing dropped and nothing double-counted."""
    config = config_mod.load()
    assignment = make_assignment(3)
    shards = dsi_mod.build_shards(
        fsn_mod.assign_domains_to_fsns(DOMAINS, config.topology.fog_search_nodes)
    )
    by_domain = {
        domain: shard for shard in shards for domain in shard.domains
    }
    total = 0
    for rid in range(8):
        record = extract_mod.extract(
            make_corpus_record(rid=rid, patient=f"patient-{rid:04d}", dom=rid % 4),
            assignment=assignment,
        )
        entries = make_entries(record)
        by_domain[record.domain].insert_record(entries, domain=record.domain)
        total += len(entries)
    assert sum(shard.entry_count for shard in shards) == total


def test_dsi_shard_requires_a_domain():
    try:
        dsi_mod.DynamicSearchIndex(domains=frozenset())
    except dsi_mod.DSIError:
        return
    raise AssertionError("a shard serving no domain should be refused")


def test_dsi_from_config_sizes_the_bloom_filter():
    config = config_mod.load()
    shard = dsi_mod.DynamicSearchIndex.from_config([DOMAINS[0]], config)
    assert shard.bloom_bits_per_entry == config.index.bloom_bits_per_entry
    assert shard.bloom_num_hashes == config.index.bloom_num_hashes


# ===========================================================================
# index/commit.py — Phase IV Steps 4-5
# ===========================================================================
def committed_record(keywords: int = 6):
    record = extract_mod.extract(
        make_corpus_record(keywords=keywords), assignment=make_assignment()
    )
    entries = make_entries(record)
    auth_root_do = hashes.sha256(b"AuthRoot_DO", domain=b"test/auth-root")
    return (
        record,
        entries,
        auth_root_do,
        commit_mod.commit_record(
            record_id=record.record_id,
            entries=entries,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
            auth_root_do=auth_root_do,
        ),
    )


def test_commit_batches_per_record():
    """:690 — one Merkle tree per IoMT record (index.yaml: batch_scope per_record)."""
    _, entries, _, commitment = committed_record(keywords=6)
    assert commitment.entry_count == len(entries) == 6
    assert commitment.tree.leaf_count == 6
    assert len(commitment.root) == merkle.DIGEST_BYTES


def test_commit_leaf_is_the_entry_encoding_not_a_double_hash():
    """L_j = H(I_j): merkle applies hash_leaf, so the leaf DATA is the encoding.

    Hashing here as well would build a tree over digests of digests — sound, but
    not the L_j the manuscript writes.
    """
    _, entries, _, commitment = committed_record()
    leaf = commit_mod.entry_leaf(entries[0])
    assert leaf == types.canonical(entries[0])
    assert commitment.tree.prove(0).leaf_hash == merkle.hash_leaf(leaf)


def test_commit_leaf_is_domain_tagged():
    """The leaf carries IndexEntry's DOMAIN, so it cannot collide with another
    record type that encodes to the same field bytes."""
    _, entries, _, _ = committed_record()
    leaf = commit_mod.entry_leaf(entries[0])
    assert leaf != entries[0].encode()          # bare field encoding
    assert types.IndexEntry.DOMAIN in leaf


def test_commit_every_proof_verifies():
    _, entries, _, commitment = committed_record()
    for index in range(len(entries)):
        assert commitment.verify(commitment.prove(index))


def test_commit_rejects_a_tampered_entry():
    _, entries, _, commitment = committed_record()
    forged = types.IndexEntry(
        token=entries[0].token,
        cid="Qm-different-cid",
        policy_id=entries[0].policy_id,
        vid=entries[0].vid,
    )
    proof = commitment.prove(0)
    tampered = merkle.MerkleProof(
        leaf_index=proof.leaf_index,
        leaf_hash=merkle.hash_leaf(commit_mod.entry_leaf(forged)),
        path=proof.path,
    )
    assert not commitment.verify(tampered)


def test_commit_root_is_order_sensitive():
    """A record's entries are sorted upstream, so the root is a function of the set."""
    _, entries, _, _ = committed_record()
    forward, _ = commit_mod.record_root(entries)
    reverse, _ = commit_mod.record_root(tuple(reversed(entries)))
    assert forward != reverse


def test_commit_reports_proof_metrics_for_exp4():
    """Exp. 4 secondary metrics, measured — odd-node promotion makes log2(N) wrong."""
    _, entries, _, commitment = committed_record(keywords=6)
    path_length, size_bytes = commitment.proof_metrics(0)
    assert path_length > 0
    assert size_bytes == path_length * (merkle.DIGEST_BYTES + 1)
    assert path_length <= commitment.height


def test_commit_rejects_an_empty_record():
    try:
        commit_mod.record_root(())
    except commit_mod.CommitmentError:
        return
    raise AssertionError("a record with no entries should be refused")


def test_commit_binds_all_four_inputs():
    """Commit_i = H(Root_i || PID_i || VID_i || AuthRoot_DO): four assertions."""
    kwargs = dict(
        root=bytes(range(32)),
        policy_id="dom0/pol0",
        vid=1,
        auth_root_do=hashes.sha256(b"do", domain=b"test/auth-root"),
    )
    base = commit_mod.policy_commitment(**kwargs)
    variants = {
        "root": dict(kwargs, root=bytes(range(1, 33))),
        "policy_id": dict(kwargs, policy_id="dom0/pol1"),
        "vid": dict(kwargs, vid=2),
        "auth_root_do": dict(
            kwargs, auth_root_do=hashes.sha256(b"other", domain=b"test/auth-root")
        ),
    }
    for name, variant in variants.items():
        assert commit_mod.policy_commitment(**variant) != base, f"{name} not bound"


def test_commit_tracks_the_data_owners_authorization_state():
    """The binding that ties outsourced data to its owner's authorization."""
    record, entries, auth_root_do, commitment = committed_record()
    rebound = commit_mod.commit_record(
        record_id=record.record_id,
        entries=entries,
        policy_id=record.policy_id,
        vid=record.metadata.vid,
        auth_root_do=hashes.sha256(b"AuthRoot_DO-v2", domain=b"test/auth-root"),
    )
    assert rebound.root == commitment.root       # same index
    assert rebound.commit != commitment.commit   # different owner authorization


def test_commit_cannot_be_reframed_across_fields():
    shared = dict(root=bytes(32), vid=0, auth_root_do=bytes(32))
    assert commit_mod.policy_commitment(policy_id="ab", **shared) != (
        commit_mod.policy_commitment(policy_id="a", **{**shared, "vid": 0})
    )


def test_commit_rejects_wrong_width_digests():
    for kwargs in (
        dict(root=bytes(31), policy_id="p", vid=0, auth_root_do=bytes(32)),
        dict(root=bytes(32), policy_id="p", vid=0, auth_root_do=bytes(31)),
    ):
        try:
            commit_mod.policy_commitment(**kwargs)
        except commit_mod.CommitmentError:
            continue
        raise AssertionError("a wrong-width digest should be refused")


def test_commit_refuses_entries_disagreeing_with_the_record_policy():
    """Commit_i binds one (PID_i, VID_i); an entry under another contradicts it."""
    record, entries, auth_root_do, _ = committed_record()
    mixed = entries[:-1] + (
        entries[-1].with_policy(policy_id="dom0/other", vid=9),
    )
    try:
        commit_mod.commit_record(
            record_id=record.record_id,
            entries=mixed,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
            auth_root_do=auth_root_do,
        )
    except commit_mod.CommitmentError as exc:
        assert "single pair" in str(exc)
        return
    raise AssertionError("entries contradicting Commit_i should be refused")


def test_commit_verification_recomputes_from_inputs():
    """The Phase VIII Step 1 precondition."""
    record, _, auth_root_do, commitment = committed_record()
    assert commit_mod.verify_commitment(
        commitment,
        policy_id=record.policy_id,
        vid=record.metadata.vid,
        auth_root_do=auth_root_do,
    )
    assert not commit_mod.verify_commitment(
        commitment,
        policy_id=record.policy_id,
        vid=record.metadata.vid + 1,
        auth_root_do=auth_root_do,
    )


def test_commit_incremental_update_matches_a_rebuild():
    """Phase VII Step 3: MerkleUpdate, not a rebuild (global.yaml, Exp. 5 rule)."""
    record, entries, auth_root_do, commitment = committed_record(keywords=6)
    replacement = entries[2].with_policy(policy_id=record.policy_id, vid=2)
    updated, recomputed = commit_mod.update_record_commitment(
        commitment,
        entry_index=2,
        entry=replacement,
        policy_id=record.policy_id,
        vid=2,
        auth_root_do=auth_root_do,
    )
    rebuilt_entries = entries[:2] + (replacement,) + entries[3:]
    rebuilt_root, _ = commit_mod.record_root(rebuilt_entries)
    assert updated.root == rebuilt_root
    assert updated.root != commitment.root
    # Exp. 5 secondary metric: nodes recomputed, measured not derived.
    assert 0 < recomputed <= commitment.height


def test_commit_update_refreshes_the_policy_commitment():
    record, entries, auth_root_do, commitment = committed_record()
    updated, _ = commit_mod.update_record_commitment(
        commitment,
        entry_index=0,
        entry=entries[0].with_policy(policy_id=record.policy_id, vid=3),
        policy_id=record.policy_id,
        vid=3,
        auth_root_do=auth_root_do,
    )
    assert commit_mod.verify_commitment(
        updated, policy_id=record.policy_id, vid=3, auth_root_do=auth_root_do
    )


# ===========================================================================
# Phase IV: Steps 1, 3, 4, 5 together
# ===========================================================================
def test_phase_iv_end_to_end_without_step_2():
    """Extract, index, shard, commit — everything but the blocked token encoding."""
    config = config_mod.load()
    assignment = make_assignment(3)
    auth_root_do = hashes.sha256(b"AuthRoot_DO", domain=b"test/auth-root")
    shards = dsi_mod.build_shards(
        fsn_mod.assign_domains_to_fsns(DOMAINS, config.topology.fog_search_nodes)
    )
    by_domain = {d: s for s in shards for d in s.domains}

    commitments = []
    total_entries = 0
    for rid in range(12):
        record = extract_mod.extract(                              # Step 1
            make_corpus_record(
                rid=rid, patient=f"patient-{rid:04d}", dom=rid % 4, keywords=6
            ),
            assignment=assignment,
        )
        entries = make_entries(record, cid=f"Qm-cid-{rid}")        # Step 3 (tokens opaque)
        by_domain[record.domain].insert_record(entries, domain=record.domain)
        total_entries += len(entries)
        commitments.append(                                        # Steps 4-5
            commit_mod.commit_record(
                record_id=record.record_id,
                entries=entries,
                policy_id=record.policy_id,
                vid=record.metadata.vid,
                auth_root_do=auth_root_do,
            )
        )

    # Every entry accounted for, none double-counted.
    assert sum(shard.entry_count for shard in shards) == total_entries == 72
    # Every record has a distinct commitment and a verifiable tree.
    assert len({c.commit for c in commitments}) == 12
    for commitment in commitments:
        for index in range(commitment.entry_count):
            assert commitment.verify(commitment.prove(index))
    # A record's entries live only on the shard serving its domain.
    for shard in shards:
        for ordinal in range(len(shard._entries)):
            entry = shard._entries[ordinal]
            if entry is not None:
                assert entry.policy_id.split("/")[0] in shard.domains


def test_phase_iv_tokenization_lives_only_in_tokens_py():
    """Step 2 has exactly one home.

    Was written when Step 2 was undecided, to prove no module had settled the
    matching relation in passing. It still holds now that tokens.py exists: the
    other three modules must not grow a second, divergent token construction —
    two definitions of T_j is one too many, as with C_i^auth and Commit_i.
    """
    for module in (dsi_mod, commit_mod, extract_mod):
        names = {n for n in dir(module) if not n.startswith("_")}
        assert not {"index_token", "query_token", "encode_keyword"} & names
    assert hasattr(tokens_mod.TokenScheme, "index_token")


# ===========================================================================
# index/tokens.py — Phase IV Step 2, Option D
# ===========================================================================
SEARCH_KEY = hashes.sha256(b"test-search-key", domain=b"test/search-key")


def keyed_scheme() -> tokens_mod.TokenScheme:
    return tokens_mod.TokenScheme.keyed(SEARCH_KEY)


def test_tokens_index_and_query_tokens_are_identical():
    """THE Option D property: T_j == T_Q, so matching is an equality.

    Phase VI Step 4's relation was an undefined arrow; Option D makes it equality,
    and that is what lets one trapdoor serve every domain (Exp. 3).
    """
    scheme = keyed_scheme()
    for keyword in ("cond:44054006", "obs:8867-4:b3", "med:1049502"):
        assert scheme.index_token(keyword) == scheme.query_token(keyword)


def test_tokens_do_not_depend_on_policy_version_or_domain():
    """The change Option D makes, asserted directly.

    The published token bound all three. Under Option D none of them can reach
    the lookup key — there is no parameter by which they could — so the same
    keyword in two policies, two versions, or two domains yields one token.
    """
    scheme = keyed_scheme()
    token = scheme.index_token("cond:44054006")
    # A token is a function of the keyword alone: no signature accepts policy,
    # version or domain, so re-deriving under any of them is identical.
    assert scheme.index_token("cond:44054006") == token
    # And the policy tag — which does bind them — is a different value entirely.
    for policy_id, vid, domain in (
        ("dom0/pol0", 0, "dom0"),
        ("dom0/pol1", 1, "dom1"),
    ):
        tag = scheme.policy_tag(policy_id=policy_id, vid=vid, domain=domain)
        assert tag != token


def test_tokens_survive_a_version_bump():
    """No version in the token: skew degrades results instead of zeroing them.

    With a version-bearing token, any VID_U != VID_i yields zero matches — a
    silent empty answer. It also means an authority version bump would
    re-tokenize its whole domain (~9.0M entries).
    """
    scheme = keyed_scheme()
    shard, extracted = indexed_shard_tokenized(scheme, records=1, keywords=5)
    record = extracted[0]
    token = scheme.query_token(record.keywords[0])
    postings_before = dict(shard._postings)

    shard.repolicy(0, policy_id=f"{record.domain}/pol-new", vid=99)
    assert shard._postings == postings_before
    assert scheme.query_token(record.keywords[0]) == token


def test_tokens_are_deterministic_and_distinct():
    scheme = keyed_scheme()
    assert scheme.index_token("a") == scheme.index_token("a")
    assert scheme.index_token("a") != scheme.index_token("b")


def test_tokens_cannot_be_reframed_across_keywords():
    """canonical() length-prefixes, so no two keywords collide by framing."""
    scheme = keyed_scheme()
    assert scheme.index_token("ab") != scheme.index_token("a")


def test_tokens_require_an_explicit_keyed_or_unkeyed_choice():
    """No default: keying H is a security decision AND an Exp. 1 cost decision."""
    try:
        tokens_mod.TokenScheme()  # type: ignore[call-arg]
    except TypeError:
        return
    raise AssertionError("TokenScheme must not have a default keying mode")


def test_tokens_keyed_and_unkeyed_differ():
    keyword = "cond:44054006"
    assert (
        keyed_scheme().index_token(keyword)
        != tokens_mod.TokenScheme.unkeyed().index_token(keyword)
    )


def test_tokens_keyed_scheme_depends_on_the_key():
    other = hashes.sha256(b"another-key", domain=b"test/search-key")
    assert keyed_scheme().index_token("a") != tokens_mod.TokenScheme.keyed(
        other
    ).index_token("a")


def test_tokens_unkeyed_is_invertible_by_dictionary_attack():
    """The concrete risk, demonstrated rather than asserted.

    The frozen corpus has a 2,023-keyword vocabulary. An honest-but-curious node
    holding unkeyed tokens recovers every keyword by hashing that vocabulary —
    2,023 evaluations. Simulated here at a smaller scale; the arithmetic is the
    same.
    """
    scheme = tokens_mod.TokenScheme.unkeyed()
    vocabulary = [f"cond:{i:06d}" for i in range(500)]
    observed = scheme.index_token(vocabulary[137])

    rainbow = {scheme.index_token(word): word for word in vocabulary}
    assert rainbow[observed] == vocabulary[137]   # keyword fully recovered


def test_tokens_keyed_resists_the_same_dictionary_attack():
    """Without the key the same attack recovers nothing."""
    scheme = keyed_scheme()
    vocabulary = [f"cond:{i:06d}" for i in range(500)]
    observed = scheme.index_token(vocabulary[137])

    attacker = tokens_mod.TokenScheme.unkeyed()
    rainbow = {attacker.index_token(word): word for word in vocabulary}
    assert observed not in rainbow


def test_tokens_reject_a_short_search_key():
    """crypto.yaml fixes prf.key_bits: 256."""
    try:
        tokens_mod.TokenScheme.keyed(b"too-short")
    except tokens_mod.TokenError as exc:
        assert "32 bytes" in str(exc)
        return
    raise AssertionError("a short search key should be refused")


def test_tokens_reject_an_empty_keyword():
    try:
        keyed_scheme().index_token("")
    except tokens_mod.TokenError:
        return
    raise AssertionError("an empty keyword should be refused")


def test_tokens_are_full_width_by_default():
    """index.yaml sets token_bits: 256 — truncating would be an unclaimed win."""
    scheme = keyed_scheme()
    assert scheme.token_bits == 256
    assert len(scheme.index_token("a")) == 32


def test_tokens_honour_a_configured_width():
    narrow = tokens_mod.TokenScheme.keyed(SEARCH_KEY, token_bits=128)
    assert len(narrow.index_token("a")) == 16
    for bad in (0, 300, 100):        # zero, over 256, not a byte multiple
        try:
            tokens_mod.TokenScheme.keyed(SEARCH_KEY, token_bits=bad)
        except tokens_mod.TokenError:
            continue
        raise AssertionError(f"token_bits={bad} should be refused")


def test_tokens_from_config_matches_index_yaml():
    config = config_mod.load()
    scheme = tokens_mod.TokenScheme.from_config(config, SEARCH_KEY)
    assert scheme.token_bits == config.index.token_bits == 256
    assert scheme.is_keyed


def test_tokens_repr_flags_the_unkeyed_mode():
    """An unkeyed scheme should be visible in a log, not silently ordinary."""
    assert "UNKEYED" in repr(tokens_mod.TokenScheme.unkeyed())
    assert "UNKEYED" not in repr(keyed_scheme())


# -- the policy tag ---------------------------------------------------------
def test_policy_tag_binds_all_three_inputs():
    """PolicyTag_i = H(PID_i || VID_i || Dom_i): three assertions."""
    scheme = keyed_scheme()
    kwargs = dict(policy_id="dom0/pol0", vid=1, domain="dom0")
    base = scheme.policy_tag(**kwargs)
    for name, replacement in (
        ("policy_id", "dom0/pol1"),
        ("vid", 2),
        ("domain", "dom1"),
    ):
        assert scheme.policy_tag(**{**kwargs, name: replacement}) != base, (
            f"{name} not bound"
        )


def test_policy_tag_is_never_a_valid_lookup_key():
    """A tag must not be presentable as a keyword token, or one could search for
    a policy instead of a keyword.

    The guarantee is the canonical encoding's ARITY, not the domain tags: a token
    hashes a one-element sequence and a tag a three-element one, so no keyword can
    produce a tag value. Asserted over the whole vocabulary shape rather than one
    example, because a single-example test would pass for the wrong reason.
    """
    scheme = keyed_scheme()
    tag = scheme.policy_tag(policy_id="p", vid=0, domain="d")
    tokens = {scheme.index_token(w) for w in ("p", "d", "p0d", "pd", "0")}
    assert tag not in tokens
    # The payloads differ in arity, which is what makes the above hold generally.
    assert types.canonical(["p"]) != types.canonical(["p", 0, "d"])


def test_policy_tag_cannot_be_reframed():
    scheme = keyed_scheme()
    assert scheme.policy_tag(policy_id="ab", vid=0, domain="c") != (
        scheme.policy_tag(policy_id="a", vid=0, domain="bc")
    )


def test_policy_tag_is_recomputable_and_verifiable():
    scheme = keyed_scheme()
    record = extract_mod.extract(
        make_corpus_record(), assignment=make_assignment()
    )
    tag = scheme.policy_tag_for(record.metadata)
    assert scheme.verify_policy_tag(
        tag,
        policy_id=record.policy_id,
        vid=record.metadata.vid,
        domain=record.domain,
    )
    assert not scheme.verify_policy_tag(
        tag,
        policy_id=record.policy_id,
        vid=record.metadata.vid + 1,
        domain=record.domain,
    )


def test_policy_tag_is_unkeyed_and_therefore_recomputable_by_a_verifier():
    """The tag must be checkable by anyone holding (PID, VID, Dom).

    Deliberately independent of the search key: a verifier in Phase VIII holds
    the authorization metadata but not the data owner's search key.
    """
    kwargs = dict(policy_id="dom0/pol0", vid=1, domain="dom0")
    assert keyed_scheme().policy_tag(**kwargs) == (
        tokens_mod.TokenScheme.unkeyed().policy_tag(**kwargs)
    )


def test_policy_tag_rejects_invalid_inputs():
    scheme = keyed_scheme()
    for kwargs in (
        dict(policy_id="", vid=0, domain="d"),
        dict(policy_id="p", vid=0, domain=""),
        dict(policy_id="p", vid=-1, domain="d"),
    ):
        try:
            scheme.policy_tag(**kwargs)
        except ValueError:
            continue
        raise AssertionError(f"{kwargs} should be refused")


# -- the trapdoor -----------------------------------------------------------
def test_trapdoor_is_q_tokens_and_reports_its_size():
    """Exp. 1: latency over q = 1..20, with trapdoor size as the secondary metric."""
    scheme = keyed_scheme()
    for q in (1, 5, 20):
        trapdoor = tokens_mod.generate_trapdoor(
            scheme, [f"kw{i}" for i in range(q)]
        )
        assert trapdoor.keyword_count == q
        assert trapdoor.size_bytes == q * 32
        assert trapdoor.is_domain_independent


def test_trapdoor_rejects_empty_and_duplicate_queries():
    scheme = keyed_scheme()
    for keywords in ([], ["a", "a"]):
        try:
            tokens_mod.generate_trapdoor(scheme, keywords)
        except tokens_mod.TokenError:
            continue
        raise AssertionError(f"keywords={keywords} should be refused")


def test_trapdoor_default_query_size_matches_the_paper():
    """§VI fixes q = 5 ("each query contains five keywords")."""
    config = config_mod.load()
    scheme = tokens_mod.TokenScheme.from_config(config, SEARCH_KEY)
    trapdoor = tokens_mod.generate_trapdoor(
        scheme, [f"kw{i}" for i in range(config.defaults.keywords_per_query)]
    )
    assert trapdoor.keyword_count == 5


# -- integration: one trapdoor across domains (the Exp. 3 claim) ------------
def indexed_shard_tokenized(
    scheme: tokens_mod.TokenScheme,
    *,
    records: int = 4,
    keywords: int = 6,
    policies_per_domain: int = 2,
    dom: int = 0,
):
    """A shard whose entries carry REAL Option D tokens."""
    assignment = make_assignment(policies_per_domain)
    shard = make_shard((DOMAINS[dom],))
    extracted = []
    for rid in range(records):
        record = extract_mod.extract(
            make_corpus_record(
                rid=rid, patient=f"patient-{dom}{rid:04d}", dom=dom, keywords=keywords
            ),
            assignment=assignment,
        )
        entries = tuple(
            types.IndexEntry(
                token=scheme.index_token(keyword),
                cid=f"Qm-{dom}-{rid}",
                policy_id=record.policy_id,
                vid=record.metadata.vid,
            )
            for keyword in record.keywords
        )
        shard.insert_record(entries, domain=record.domain)
        extracted.append(record)
    return shard, extracted


def test_tokens_one_trapdoor_matches_across_domains():
    """Exp. 3's claim, end to end: ONE trapdoor, two domains, hits in both.

    Under the published four-input token this is impossible — the token would
    embed Dom_i and could not match the other domain's entries at all. That is
    the whole reason Option D exists.
    """
    scheme = keyed_scheme()
    shared_keyword = "cond:44054006"
    shards = {}
    authorized = []
    for dom in (0, 1):
        assignment = make_assignment(1)
        shard = make_shard((DOMAINS[dom],))
        record = extract_mod.extract(
            make_corpus_record(rid=dom, patient=f"patient-{dom}", dom=dom, keywords=5),
            assignment=assignment,
        )
        shard.insert(
            types.IndexEntry(
                token=scheme.index_token(shared_keyword),
                cid=f"Qm-{dom}",
                policy_id=record.policy_id,
                vid=record.metadata.vid,
            ),
            domain=record.domain,
        )
        shards[DOMAINS[dom]] = shard
        authorized.append((record.domain, record.policy_id))

    trapdoor = tokens_mod.generate_trapdoor(scheme, [shared_keyword])
    assert trapdoor.keyword_count == 1        # ONE trapdoor, not one per domain

    hits = 0
    for domain, shard in shards.items():
        found, stats = shard.lookup(trapdoor.tokens, authorized)
        assert len(found) == 1, f"{domain} did not match the shared trapdoor"
        assert stats.n_eff == 1
        hits += len(found)
    assert hits == 2


def test_tokens_integrate_with_commitments():
    """Real tokens flow through Steps 3-5 unchanged."""
    scheme = keyed_scheme()
    assignment = make_assignment(2)
    record = extract_mod.extract(
        make_corpus_record(keywords=6), assignment=assignment
    )
    entries = tuple(
        types.IndexEntry(
            token=scheme.index_token(keyword),
            cid="Qm-cid",
            policy_id=record.policy_id,
            vid=record.metadata.vid,
        )
        for keyword in record.keywords
    )
    auth_root_do = hashes.sha256(b"AuthRoot_DO", domain=b"test/auth-root")
    commitment = commit_mod.commit_record(
        record_id=record.record_id,
        entries=entries,
        policy_id=record.policy_id,
        vid=record.metadata.vid,
        auth_root_do=auth_root_do,
    )
    for index in range(len(entries)):
        assert commitment.verify(commitment.prove(index))
    assert commit_mod.verify_commitment(
        commitment,
        policy_id=record.policy_id,
        vid=record.metadata.vid,
        auth_root_do=auth_root_do,
    )


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
