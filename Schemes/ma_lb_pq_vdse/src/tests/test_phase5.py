#!/usr/bin/env python3
"""Verification tests for MA-LB-PQ-VDSE Phase V Steps 4-5.

Each test checks a DEFINING PROPERTY. A propagation that inserts a record's
entries onto every node has passed the shallow test and destroyed the selectivity
Exp. 6 exists to measure.

Runs standalone with no test framework::

    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase5.py            # all
    python3 Schemes/ma_lb_pq_vdse/src/tests/test_phase5.py catalog    # one area

and is also collectible by pytest if it is installed.

Covers ``shard/propagation.py``. Phase V Steps 1-3 (IPFS outsourcing, metadata
registration, ``BC_i``) have no implementation, so ``CID_i`` is a labelled
placeholder throughout — the same treatment ``SK_{U,i}`` had while Phase III
Step 2 was open.
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
from Schemes.ma_lb_pq_vdse.src.index import commit as commit_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import dsi as dsi_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import extract as extract_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import tokens as tokens_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.shard import propagation as prop_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.tests import test_phase4 as base  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


DOMAINS = extract_mod.DEFAULT_DOMAIN_NAMES
SEARCH_KEY = hashes.sha256(b"phase5-search-key", domain=b"test/search-key")


# ===========================================================================
# Fixtures
# ===========================================================================
def scheme() -> tokens_mod.TokenScheme:
    return tokens_mod.TokenScheme.keyed(SEARCH_KEY)


def make_record(rid: int = 0, dom: int = 0, keywords: int = 6):
    """An extracted record with Option D tokens and its Sync_i payload."""
    record = extract_mod.extract(
        base.make_corpus_record(
            rid=rid, patient=f"patient-{dom}{rid:04d}", dom=dom, keywords=keywords
        ),
        assignment=base.make_assignment(2),
    )
    cid = prop_mod.placeholder_cid(rid)
    entries = tuple(
        types.IndexEntry(
            token=scheme().index_token(keyword),
            cid=cid,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
        )
        for keyword in record.keywords
    )
    payload = prop_mod.build_sync_payload(
        entries=entries, metadata=record.metadata, cid=cid
    )
    return record, entries, payload


def make_endpoints(domains=DOMAINS, node_count: int = 4):
    """The Fog Search Node set. Each node owns its own shard now, so there is no
    separate endpoint object to keep in step with it."""
    return fsn_mod.build_fsn_set(domains, node_count)


# ===========================================================================
# Sync_i — the payload
# ===========================================================================
def test_sync_payload_carries_the_published_tuple():
    """Sync_i = (I_i, PID_i, VID_i, CID_i)."""
    record, entries, payload = make_record(keywords=6)
    assert payload.entries == entries
    assert payload.policy_id == record.policy_id
    assert payload.vid == record.metadata.vid
    assert payload.cid == prop_mod.placeholder_cid(0)
    assert payload.entry_count == 6


def test_sync_payload_binds_every_field():
    record, entries, payload = make_record()
    base_digest = payload.digest()
    variants = (
        types.SyncPayload(
            entries=entries[:-1], policy_id=payload.policy_id, vid=payload.vid,
            cid=payload.cid,
        ),
        types.SyncPayload(
            entries=tuple(e.with_policy(policy_id="dom0/other", vid=payload.vid)
                          for e in entries),
            policy_id="dom0/other", vid=payload.vid, cid=payload.cid,
        ),
        types.SyncPayload(
            entries=tuple(e.with_policy(policy_id=payload.policy_id, vid=9)
                          for e in entries),
            policy_id=payload.policy_id, vid=9, cid=payload.cid,
        ),
    )
    for variant in variants:
        assert variant.digest() != base_digest


def test_sync_payload_carries_no_ciphertext():
    """Step 4: FSNs hold "only searchable-index shards and corresponding metadata".

    A payload carrying CT_i would turn every node into a replica of the encrypted
    store, which is exactly what the low-overhead claim rests on not happening.
    """
    _, _, payload = make_record()
    fields = set(payload.__dataclass_fields__)
    assert not fields & {"ciphertext", "ct", "data", "payload_bytes", "record"}
    # Size scales with the entry set only.
    assert payload.size_bytes == len(payload.encode())


def test_sync_payload_refuses_entries_under_another_policy():
    """Sync_i binds one (PID_i, VID_i), as Commit_i does."""
    record, entries, _ = make_record()
    mixed = entries[:-1] + (
        entries[-1].with_policy(policy_id="dom0/other", vid=7),
    )
    try:
        types.SyncPayload(
            entries=mixed,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
            cid=prop_mod.placeholder_cid(0),
        )
    except ValueError as exc:
        assert "single pair" in str(exc)
        return
    raise AssertionError("entries under a different policy should be refused")


def test_sync_payload_refuses_entries_from_another_record():
    """One payload, one CID: a multi-record payload could span domains."""
    record, entries, _ = make_record(rid=0)
    foreign = types.IndexEntry(
        token=entries[0].token,
        cid=prop_mod.placeholder_cid(99),
        policy_id=record.policy_id,
        vid=record.metadata.vid,
    )
    try:
        types.SyncPayload(
            entries=entries + (foreign,),
            policy_id=record.policy_id,
            vid=record.metadata.vid,
            cid=prop_mod.placeholder_cid(0),
        )
    except ValueError as exc:
        assert "spanning records" in str(exc)
        return
    raise AssertionError("a payload spanning records should be refused")


def test_sync_payload_refuses_an_empty_entry_set():
    record, _, _ = make_record()
    try:
        types.SyncPayload(
            entries=(), policy_id=record.policy_id, vid=0, cid="cid"
        )
    except ValueError:
        return
    raise AssertionError("an empty Sync_i should be refused")


def test_sync_payload_metadata_is_the_source_of_policy_and_version():
    """Built from Meta_i, so a payload cannot disagree with the record's metadata."""
    record, entries, payload = make_record()
    assert payload.policy_id == record.metadata.policy_id
    assert payload.vid == record.metadata.vid


def test_placeholder_cid_is_labelled():
    """It must be impossible to mistake for an IPFS identifier."""
    cid = prop_mod.placeholder_cid(7)
    assert cid.startswith(prop_mod.PLACEHOLDER_CID_PREFIX)
    assert "placeholder" in cid


# ===========================================================================
# Routing and propagation — Step 4
# ===========================================================================
def test_route_selects_only_the_serving_node():
    """d = m = 4: one domain per node, so one record touches one node."""
    endpoints = make_endpoints()
    for domain in DOMAINS:
        targets = prop_mod.route(domain, endpoints)
        assert len(targets) == 1
        assert targets[0].serves_domain(domain)


def test_route_refuses_an_unserved_domain():
    """A record indexed nowhere would be silently unsearchable."""
    endpoints = make_endpoints()
    try:
        prop_mod.route("atlantis-general", endpoints)
    except prop_mod.PropagationError as exc:
        assert "indexed nowhere" in str(exc)
        return
    raise AssertionError("an unserved domain should be refused")


def test_propagation_lands_only_on_the_serving_node():
    """The selectivity claim: entries reach one node in four, not all four."""
    endpoints = make_endpoints()
    record, _, payload = make_record(rid=0, dom=0, keywords=6)
    receipt = prop_mod.propagate_to_authorized(
        payload, domain=record.domain, nodes=endpoints
    )
    assert receipt.touched_count == 1
    assert receipt.entry_count == 6
    for endpoint in endpoints:
        expected = 6 if endpoint.serves_domain(record.domain) else 0
        assert endpoint.entry_count == expected


def test_propagation_raises_n_j_by_exactly_the_keyword_count():
    """N_j += |W_i| on the receiver, unchanged elsewhere."""
    endpoints = make_endpoints()
    before = {e.node_id: e.entry_count for e in endpoints}
    record, _, payload = make_record(rid=0, dom=1, keywords=6)
    prop_mod.propagate_to_authorized(
        payload, domain=record.domain, nodes=endpoints
    )
    for endpoint in endpoints:
        delta = endpoint.entry_count - before[endpoint.node_id]
        assert delta == (6 if endpoint.serves_domain(record.domain) else 0)


def test_propagation_keeps_the_node_and_shard_counts_in_step():
    """Two counters that can diverge would make the scheduler cost queries wrongly."""
    endpoints = make_endpoints()
    for rid in range(6):
        record, _, payload = make_record(rid=rid, dom=rid % 4)
        prop_mod.propagate_to_authorized(
            payload, domain=record.domain, nodes=endpoints
        )
        for endpoint in endpoints:
                assert endpoint.entry_count == endpoint.index.entry_count


def test_propagation_refuses_a_replay():
    """Re-applying one Sync_i would double-insert, and every duplicate entry
    would still be individually well-formed — no proof would catch it."""
    endpoints = make_endpoints()
    record, _, payload = make_record()
    prop_mod.propagate_to_authorized(
        payload, domain=record.domain, nodes=endpoints
    )
    try:
        prop_mod.propagate_to_authorized(
            payload, domain=record.domain, nodes=endpoints
        )
    except prop_mod.PropagationError as exc:
        assert "already applied" in str(exc)
        return
    raise AssertionError("a replayed Sync_i must be refused")


def test_propagation_refuses_a_node_that_does_not_serve_the_domain():
    endpoints = make_endpoints()
    record, _, payload = make_record(dom=0)
    wrong = [e for e in endpoints if not e.serves_domain(record.domain)][0]
    try:
        wrong.apply_sync(payload, domain=record.domain)
    except fsn_mod.FSNError as exc:
        # The node owns the check now; propagate() re-raises it as a
        # PropagationError so callers have one type to handle.
        assert "not an authorized node" in str(exc)
        return
    raise AssertionError("a non-serving node should refuse the payload")


def test_propagation_has_no_broadcast_helper():
    """Phase VII's selectivity is the measured claim; a fan-out would void it."""
    names = {n for n in dir(prop_mod) if not n.startswith("_")}
    assert not {"broadcast", "propagate_all", "sync_all", "propagate_everywhere"} & names


def test_propagation_reports_the_payload_size():
    """Step 4's "low synchronization overhead" needs a measured figure."""
    endpoints = make_endpoints()
    record, _, payload = make_record(keywords=6)
    receipt = prop_mod.propagate_to_authorized(
        payload, domain=record.domain, nodes=endpoints
    )
    assert receipt.payload_bytes == payload.size_bytes > 0
    assert receipt.cid == payload.cid


def test_propagation_scales_when_domains_exceed_nodes():
    """Exp. 3 sweeps d to 10 against m = 4."""
    domains = tuple(f"dom{i}" for i in range(10))
    endpoints = make_endpoints(domains, node_count=4)
    assert len(endpoints) == 4
    assert all(endpoint.domains for endpoint in endpoints)   # no idle node

    total = 0
    for index, domain in enumerate(domains):
        record = extract_mod.extract(
            base.make_corpus_record(rid=index, patient=f"p{index}", dom=0),
            assignment=base.make_assignment(2),
        )
        cid = prop_mod.placeholder_cid(index)
        entries = tuple(
            types.IndexEntry(
                token=scheme().index_token(kw),
                cid=cid,
                policy_id=record.policy_id,
                vid=record.metadata.vid,
            )
            for kw in record.keywords
        )
        payload = types.SyncPayload(
            entries=entries,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
            cid=cid,
        )
        # The shard for this domain must accept an entry tagged to it.
        target = prop_mod.route(domain, endpoints)
        assert len(target) == 1
        total += payload.entry_count
    assert total == 10 * 6


def test_propagation_accounts_for_every_entry_across_shards():
    """Nothing dropped, nothing double-counted."""
    endpoints = make_endpoints()
    total = 0
    for rid in range(12):
        record, _, payload = make_record(rid=rid, dom=rid % 4, keywords=6)
        prop_mod.propagate_to_authorized(
            payload, domain=record.domain, nodes=endpoints
        )
        total += payload.entry_count
    assert sum(endpoint.entry_count for endpoint in endpoints) == total == 72


def test_node_and_shard_domains_cannot_disagree():
    """The node owns its shard, so there is no pairing to get wrong.

    Previously a node and a shard were separate objects that had to be matched;
    a mismatched pairing would have routed entries to the wrong shard. Now the
    node builds its own index over its own domains, so the two cannot differ.
    """
    node = fsn_mod.FogSearchNode.create("FSN1", [DOMAINS[0]])
    assert node.domains == node.index.domains == frozenset([DOMAINS[0]])


def test_every_node_in_the_set_owns_a_distinct_shard():
    nodes = fsn_mod.build_fsn_set(DOMAINS, 4)
    indexes = [id(node.index) for node in nodes]
    assert len(set(indexes)) == 4
    for node in nodes:
        assert node.domains == node.index.domains


# ===========================================================================
# The catalog — Step 5
# ===========================================================================
def test_catalog_records_the_published_triple():
    """Catalog <- Catalog ∪ (CID_i, PID_i, VID_i)."""
    catalog = prop_mod.IndexCatalog()
    record, _, payload = make_record()
    entry = catalog.record(payload, domain=record.domain)
    assert (entry.cid, entry.policy_id, entry.vid) == (
        payload.cid,
        payload.policy_id,
        payload.vid,
    )
    assert entry.domain == record.domain      # needed to locate the shard
    assert len(catalog) == 1
    assert payload.cid in catalog


def test_catalog_add_is_a_set_union():
    """Re-adding an identical row is a no-op, as ∪ implies."""
    catalog = prop_mod.IndexCatalog()
    record, _, payload = make_record()
    catalog.record(payload, domain=record.domain)
    catalog.record(payload, domain=record.domain)
    assert len(catalog) == 1


def test_catalog_refuses_a_conflicting_row_for_one_cid():
    """One record under two policies would resolve by whichever row was read."""
    catalog = prop_mod.IndexCatalog()
    record, entries, payload = make_record()
    catalog.record(payload, domain=record.domain)
    conflicting = types.SyncPayload(
        entries=tuple(
            e.with_policy(policy_id="dom0/other", vid=e.vid) for e in entries
        ),
        policy_id="dom0/other",
        vid=payload.vid,
        cid=payload.cid,
    )
    try:
        catalog.record(conflicting, domain=record.domain)
    except prop_mod.PropagationError as exc:
        assert "already catalogued" in str(exc)
        return
    raise AssertionError("a conflicting catalog row should be refused")


def test_catalog_locates_only_authorized_records():
    """The Phase VI Step 2 shortcut: no scan of the encrypted repository."""
    catalog = prop_mod.IndexCatalog()
    recorded = []
    for rid in range(8):
        record, _, payload = make_record(rid=rid, dom=rid % 4)
        catalog.record(payload, domain=record.domain)
        recorded.append((record.domain, record.policy_id))
    assert len(catalog) == 8

    authorized = [recorded[0]]
    located = catalog.locate(authorized)
    assert 0 < len(located) < 8
    for entry in located:
        assert (entry.domain, entry.policy_id) in set(authorized)


def test_catalog_locate_returns_nothing_for_an_unauthorized_pair():
    catalog = prop_mod.IndexCatalog()
    record, _, payload = make_record()
    catalog.record(payload, domain=record.domain)
    assert catalog.locate([(record.domain, "dom0/not-my-policy")]) == ()


def test_catalog_get_raises_for_an_unknown_cid():
    try:
        prop_mod.IndexCatalog().get("no-such-cid")
    except prop_mod.PropagationError:
        return
    raise AssertionError("an unknown CID should raise")


def test_catalog_entry_binds_every_field():
    fields = dict(cid="c", policy_id="p", vid=1, domain="d")
    base_digest = types.CatalogEntry(**fields).digest()
    for name, replacement in (
        ("cid", "c2"), ("policy_id", "p2"), ("vid", 2), ("domain", "d2")
    ):
        assert types.CatalogEntry(**{**fields, name: replacement}).digest() != (
            base_digest
        ), f"{name} not bound"


# ===========================================================================
# Phase IV -> V end to end
# ===========================================================================
def test_phase_v_end_to_end_index_shard_catalog_search():
    """Extract, tokenize, commit, propagate, catalogue, then search a shard.

    The first point where a query issued against a propagated shard returns the
    record that was outsourced — the property everything before this exists for.
    """
    config = config_mod.load()
    token_scheme = tokens_mod.TokenScheme.from_config(config, SEARCH_KEY)
    endpoints = make_endpoints()
    catalog = prop_mod.IndexCatalog()
    auth_root_do = hashes.sha256(b"AuthRoot_DO", domain=b"test/auth-root")

    outsourced = []
    for rid in range(8):
        record = extract_mod.extract(
            base.make_corpus_record(
                rid=rid, patient=f"patient-{rid:04d}", dom=rid % 4, keywords=6
            ),
            assignment=base.make_assignment(2),
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
        # Phase IV Steps 4-5 — the commitment travels on-chain, not to the FSNs.
        commitment = commit_mod.commit_record(
            record_id=rid,
            entries=entries,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
            auth_root_do=auth_root_do,
        )
        assert commitment.verify(commitment.prove(0))

        payload = prop_mod.build_sync_payload(
            entries=entries, metadata=record.metadata, cid=cid
        )
        receipt = prop_mod.propagate_to_authorized(      # Phase V Step 4
            payload, domain=record.domain, nodes=endpoints
        )
        assert receipt.touched_count == 1
        catalog.record(payload, domain=record.domain)     # Phase V Step 5
        outsourced.append((record, entries, cid))

    assert len(catalog) == 8
    assert sum(e.entry_count for e in endpoints) == 8 * 6
    for endpoint in endpoints:
        # N_j has a single source now, so this is the count itself, not a
        # reconciliation between two counters.
        assert endpoint.entry_count == endpoint.index.entry_count

    # A query for a record's keyword, on the shard serving its domain, returns it.
    record, entries, cid = outsourced[0]
    trapdoor = tokens_mod.generate_trapdoor(token_scheme, [record.keywords[0]])
    endpoint = prop_mod.route(record.domain, endpoints)[0]
    found, stats = endpoint.index.lookup(
        trapdoor.tokens, [(record.domain, record.policy_id)]
    )
    assert len(found) == 1
    assert found[0].cid == cid
    assert stats.n_eff == 1
    # And the catalog resolves the same record without scanning the repository.
    located = catalog.locate([(record.domain, record.policy_id)])
    assert cid in {entry.cid for entry in located}


def test_phase_v_ciphertext_never_reaches_a_node():
    """FSNs hold index shards and metadata only; CT_i stays in IPFS."""
    endpoints = make_endpoints()
    marker = b"ENCRYPTED-RECORD-BODY"
    record, _, payload = make_record()
    prop_mod.propagate_to_authorized(
        payload, domain=record.domain, nodes=endpoints
    )
    assert marker not in payload.encode()
    for endpoint in endpoints:
        for ordinal in range(len(endpoint.index._entries)):
            entry = endpoint.index._entries[ordinal]
            if entry is not None:
                assert marker not in entry.encode()
                # Only a CID reference, never the data itself.
                assert entry.cid.startswith(prop_mod.PLACEHOLDER_CID_PREFIX)


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
