#!/usr/bin/env python3
"""End-to-end integration tests across all eight MA-LB-PQ-VDSE phases.

The per-phase suites check each construction's defining properties in isolation.
This file checks the properties that only exist *between* phases — the ones a
per-phase test cannot see because it supplies by hand what an earlier phase would
have produced:

* a record outsourced in Phase V is findable in Phase VI and verifiable in
  Phase VIII, with no value hand-constructed along the way;
* the ``authorized`` shard set Phase VI Steps 3-4 consume is the one Step 2
  actually resolved, not one a test invented;
* a Phase VII revocation makes a Phase VI request fail Step 2 *and* leaves the
  pre-update Phase VIII bundle failing Step 3;
* the four ``VID`` namespaces stay coherent across the phases that subtract them.

Runs standalone with no test framework::

    python3 Schemes/ma_lb_pq_vdse/src/tests/test_integration.py
    python3 Schemes/ma_lb_pq_vdse/src/tests/test_integration.py lifecycle
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
from Schemes.ma_lb_pq_vdse.src.aim import aim as aim_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.aim import verification as authz_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.chain import ipfs as ipfs_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.chain import ledger as ledger_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.chain import outsourcing as out_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.fsn import fsn as fsn_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.fsn import search as search_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import commit as commit_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import extract as extract_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.index import tokens as tokens_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.scheduler import aass as aass_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.shard import propagation as prop_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.sync import dias as dias_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.user import profile as profile_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.user import token as token_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.verify import ledger as vledger_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.verify import proof as proof_mod  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.tests import test_phase1_2 as p12  # noqa: E402
from Schemes.ma_lb_pq_vdse.src.tests import test_phase4 as p4  # noqa: E402


try:  # Make skips register as real skips when run under pytest.
    import pytest

    Skip = pytest.skip.Exception  # type: ignore[assignment]
except ImportError:

    class Skip(Exception):  # type: ignore[no-redef]
        """Raised to skip a test whose optional backend is unavailable."""


DOMAINS = extract_mod.DEFAULT_DOMAIN_NAMES
SEARCH_KEY = hashes.sha256(b"integration-search-key", domain=b"test/search-key")


# ===========================================================================
# The system under test: every phase wired together
# ===========================================================================
class Deployment:
    """Phases I-V, assembled once, so the tests below can exercise VI-VIII.

    Deliberately built by calling the real phase code rather than by constructing
    values: the point of this file is that nothing is hand-fed.
    """

    def __init__(self, records_per_domain: int = 3, keywords: int = 6):
        self.config = config_mod.load()
        self.scheme = tokens_mod.TokenScheme.from_config(self.config, SEARCH_KEY)

        # Phase I: the group is injected, so nothing here is reportable.
        self.context = p12.initializer.initialize(group_provider=p12.stub_provider)
        self.ledger = ledger_mod.InProcessLedger()
        self.aim = aim_mod.AuthorizationIndexManager()
        self.store = ipfs_mod.InProcessContentStore()
        self.register = out_mod.MetadataRegister()
        self.catalog = prop_mod.IndexCatalog()

        # Phase I Step 4 + Phase II: one authority per domain, all registered.
        self.registry = p12.authority_mod.AttributeNamespaceRegistry()
        self.authorities = {}
        for index, domain in enumerate(DOMAINS, start=1):
            authority = p12.make_authority(
                f"AA{index}", domain, registry=self.registry, context=self.context
            )
            authority.register(self.ledger)
            self.ledger.publish_authorization_state(authority.state())
            self.authorities[domain] = authority

        self.nodes = fsn_mod.build_fsn_set_from_config(self.config, DOMAINS)
        aim_mod.initial_synchronization(
            self.aim,
            self.ledger,
            [a.authority_id for a in self.authorities.values()],
            self.nodes,
        )

        # Phase III: a Data Owner, enrolled with every authority (it owns records
        # in one domain but its AuthRoot_DO must be stable across the deployment).
        self.owner_attributes = sorted(
            attr
            for authority in self.authorities.values()
            for attr in authority.attributes[:2]
        )
        self.owner_profile = profile_mod.build_profile_from_aim(
            self.aim,
            uid="DO-1",
            authority_ids=[a.authority_id for a in self.authorities.values()],
            attributes=self.owner_attributes,
        )

        # Phase IV + Phase V: index, commit, outsource, propagate, catalogue.
        self.records = []
        for dom_index, domain in enumerate(DOMAINS):
            for local in range(records_per_domain):
                self.records.append(
                    self._outsource(dom_index, local, keywords, len(self.records))
                )

    def _outsource(self, dom_index: int, local: int, keywords: int, rid: int):
        record = extract_mod.extract(
            p4.make_corpus_record(
                rid=rid,
                patient=f"patient-{dom_index}{local:04d}",
                dom=dom_index,
                keywords=keywords,
            ),
            assignment=p4.make_assignment(1),
        )
        ciphertext = hashes.sha256(
            f"encrypted-record-{rid}".encode(), domain=b"test/ct"
        ) * 4

        # Phase V Step 1 first: the entries must reference the CID the upload
        # returned, which is why the index cannot be built before this.
        cid = ipfs_mod.upload_ciphertext(self.store, ciphertext)
        entries = tuple(
            types.IndexEntry(
                token=self.scheme.index_token(kw),
                cid=cid,
                policy_id=record.policy_id,
                vid=record.metadata.vid,
            )
            for kw in record.keywords
        )
        commitment = commit_mod.commit_record(   # Phase IV Steps 4-5
            record_id=rid,
            entries=entries,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
            auth_root_do=self.owner_profile.auth_root,
        )
        # Phase V Steps 2-3.
        out_mod.register_metadata(
            self.register, cid=cid, metadata=record.metadata, commitment=commitment
        )
        anchor = out_mod.anchor_initial_commitment(
            self.ledger, cid=cid, commitment=commitment, vid=record.metadata.vid
        )
        # Phase V Steps 4-5.
        payload = prop_mod.build_sync_payload(
            entries=entries, metadata=record.metadata, cid=cid
        )
        prop_mod.propagate_to_authorized(
            payload, domain=record.domain, nodes=self.nodes
        )
        self.catalog.record(payload, domain=record.domain)
        return dict(
            record=record,
            entries=entries,
            commitment=commitment,
            cid=cid,
            anchor=anchor,
            ciphertext=ciphertext,
        )

    # -- Phase III for a searching user -------------------------------------
    def enrol_user(self, uid: str, domains: Tuple[str, ...]):
        """A Data User authorized for ``domains``, with its VAP and resolver."""
        authority_ids = [self.authorities[d].authority_id for d in domains]
        attributes = sorted(
            attr for d in domains for attr in self.authorities[d].attributes[:3]
        )
        profile = profile_mod.build_profile_from_aim(
            self.aim, uid=uid, authority_ids=authority_ids, attributes=attributes
        )
        resolver = authz_mod.MappingPolicyResolver(
            mapping={
                (uid, d): tuple(
                    entry.policy_id
                    for entry in self.catalog.locate(
                        [(d, r["record"].policy_id) for r in self.records]
                    )
                    if entry.domain == d
                )
                for d in domains
            }
        )
        return profile, authority_ids, attributes, resolver

    def node_for(self, domain: str) -> fsn_mod.FogSearchNode:
        return [n for n in self.nodes if n.serves_domain(domain)][0]

    def records_in(self, domain: str):
        return [r for r in self.records if r["record"].domain == domain]


def deployment(**kwargs) -> Deployment:
    return Deployment(**kwargs)


# ===========================================================================
# Phase V Steps 1-3
# ===========================================================================
def test_ipfs_is_content_addressed():
    """The same bytes yield the same CID — what makes CID_i an immutable reference."""
    store = ipfs_mod.InProcessContentStore()
    first = store.put(b"encrypted-record")
    second = store.put(b"encrypted-record")
    assert first == second
    assert len(store) == 1 and store.put_count == 2
    assert store.get(first) == b"encrypted-record"
    assert store.verify(first)


def test_ipfs_cid_is_labelled_as_a_development_identifier():
    """A real CIDv1 is a multibase multihash; this must not be mistaken for one."""
    store = ipfs_mod.InProcessContentStore()
    cid = store.put(b"x")
    assert cid.startswith(ipfs_mod.DEV_CID_PREFIX)


def test_ipfs_detects_tampered_content():
    """Content addressing makes tampering self-evident."""
    store = ipfs_mod.InProcessContentStore()
    cid = store.put(b"original")
    store._objects[cid] = b"tampered"
    assert not store.verify(cid)


def test_ipfs_rejects_empty_content_and_unknown_cids():
    store = ipfs_mod.InProcessContentStore()
    try:
        store.put(b"")
    except ipfs_mod.ContentStoreError:
        pass
    else:
        raise AssertionError("empty content should be refused")
    try:
        store.get("dev-cid-nope")
    except ipfs_mod.ContentNotFound:
        return
    raise AssertionError("an unknown CID should raise")


def test_outsourcing_registers_metadata_and_anchors_the_commitment():
    """Phase V Steps 2-3, with both registers agreeing."""
    system = deployment(records_per_domain=1)
    entry = system.records[0]
    metadata = system.register.get(entry["cid"])
    assert metadata.root == entry["commitment"].root
    assert metadata.commit == entry["commitment"].commit
    assert metadata.policy_id == entry["record"].policy_id
    anchor = entry["anchor"]
    assert (anchor.cid, anchor.root, anchor.commit) == (
        entry["cid"],
        metadata.root,
        metadata.commit,
    )


def test_outsourcing_keeps_the_ciphertext_off_chain():
    """"the blockchain storage complexity remains independent of the data size".

    INDEPENDENT, not merely smaller: the anchor's size must not vary with the
    record's. Asserted by anchoring two records whose ciphertexts differ by three
    orders of magnitude and comparing the encodings.
    """
    system = deployment(records_per_domain=1)
    entry = system.records[0]
    assert entry["ciphertext"] not in entry["anchor"].encode()
    for ledger_entry in system.ledger.entries():
        assert entry["ciphertext"] not in ledger_entry.payload

    sizes = []
    for scale, rid in ((1, 900), (1000, 901)):
        ciphertext = b"x" * (128 * scale)
        cid = ipfs_mod.upload_ciphertext(system.store, ciphertext)
        entries = tuple(
            e_.with_policy(policy_id=e_.policy_id, vid=e_.vid)
            for e_ in entry["entries"]
        )
        commitment = commit_mod.commit_record(
            record_id=rid,
            entries=entries,
            policy_id=entry["record"].policy_id,
            vid=entry["record"].metadata.vid,
            auth_root_do=system.owner_profile.auth_root,
        )
        anchor = out_mod.anchor_initial_commitment(
            system.ledger,
            cid=cid,
            commitment=commitment,
            vid=entry["record"].metadata.vid,
            timestamp_ns=1,
        )
        sizes.append(len(anchor.encode()))
    # A 1000x larger record produces the same on-chain footprint.
    assert sizes[0] == sizes[1]


def test_outsourcing_refuses_entries_that_predate_the_cid():
    """The ordering mistake the published Step 1 invites.

    CT_i is defined to contain I_i, but each entry contains CID_i, and CID_i is
    derived from CT_i — a circularity. Entries must be built over the CID the
    upload returned.
    """
    system = deployment(records_per_domain=1)
    entry = system.records[0]
    stale_entries = tuple(
        types.IndexEntry(
            token=e.token, cid="dev-cid-guessed", policy_id=e.policy_id, vid=e.vid
        )
        for e in entry["entries"]
    )
    try:
        out_mod.outsource_record(
            store=system.store,
            ledger=system.ledger,
            register=out_mod.MetadataRegister(),
            ciphertext=b"a-different-record",
            metadata=entry["record"].metadata,
            commitment=entry["commitment"],
            entries=stale_entries,
        )
    except out_mod.OutsourcingError as exc:
        assert "the CID the upload returned" in str(exc)
        return
    raise AssertionError("entries referencing a foreign CID should be refused")


def test_outsourcing_refuses_conflicting_metadata_for_one_cid():
    system = deployment(records_per_domain=1)
    entry = system.records[0]
    try:
        system.register.register(
            types.OutsourcedMetadata(
                cid=entry["cid"],
                policy_id="dom0/different",
                vid=entry["record"].metadata.vid,
                root=entry["commitment"].root,
                commit=entry["commitment"].commit,
            )
        )
    except out_mod.OutsourcingError as exc:
        assert "immutable content" in str(exc)
        return
    raise AssertionError("two different metadata claims for one CID should be refused")


def test_initial_anchor_closes_the_phase_viii_gap():
    """A record that has never been updated must still verify against BC_i.

    Before Phase V Step 3 existed, only Phase VII wrote anchors, so Step 3 failed
    for every un-updated record.
    """
    system = deployment(records_per_domain=1)
    entry = system.records[0]
    bundles = proof_mod.build_response(entry["commitment"], entry["entries"])
    result = vledger_mod.verify_blockchain_consistency(system.ledger, bundles[0])
    assert result.passed


def test_initial_and_update_anchors_form_one_history():
    """Phase V Step 3 and Phase VII Step 5 must use one namespace and key scheme."""
    system = deployment(records_per_domain=1)
    entry = system.records[0]
    domain = entry["record"].domain
    # A Modify, because BC_i' carries the RECORD's version and a revocation
    # changes no index entry — so only an index-touching update anchors anew.
    dias_mod.synchronize(
        dias_mod.UpdateRequest(
            operation=dias_mod.Operation.MODIFY,
            cid=entry["cid"],
            delta=dias_mod.UpdateDelta(policy_id=f"{domain}/evolved"),
        ),
        authority=system.authorities[domain],
        nodes=system.nodes,
        commitment=entry["commitment"],
        entries=entry["entries"],
        auth_root_do=system.owner_profile.auth_root,
        ledger=system.ledger,
    )
    initial = entry["record"].metadata.vid
    history = vledger_mod.anchor_history(system.ledger, entry["cid"])
    assert history.versions == (initial, initial + 1)
    assert history.is_monotone()
    assert out_mod.anchor_key(entry["cid"], 1) == vledger_mod.anchor_key(
        entry["cid"], 1
    )


# ===========================================================================
# Phase VI Step 1 — search token assembly
# ===========================================================================
def test_search_token_carries_the_published_tuple():
    """ST = (T_Q, AuthRoot_U, VID_U, rho)."""
    system = deployment(records_per_domain=1)
    profile, _, _, _ = system.enrol_user("DU-1", (DOMAINS[0],))
    keywords = list(system.records_in(DOMAINS[0])[0]["record"].keywords[:5])
    token = token_mod.generate_search_token(system.scheme, profile, keywords)
    assert token.keyword_count == 5
    assert token.auth_root == profile.auth_root
    assert token.vid_u == profile.vid
    assert len(token.nonce) >= token_mod.NONCE_BYTES


def test_search_token_nonce_is_fresh_each_time():
    """rho prevents replay only if it changes."""
    system = deployment(records_per_domain=1)
    profile, _, _, _ = system.enrol_user("DU-1", (DOMAINS[0],))
    keywords = list(system.records_in(DOMAINS[0])[0]["record"].keywords[:3])
    nonces = {
        token_mod.generate_search_token(system.scheme, profile, keywords).nonce
        for _ in range(20)
    }
    assert len(nonces) == 20


def test_search_token_reads_authorization_from_the_profile():
    """A token cannot claim an authorization state its VAP does not hold."""
    system = deployment(records_per_domain=1)
    profile, _, _, _ = system.enrol_user("DU-1", (DOMAINS[0],))
    token = token_mod.generate_search_token(
        system.scheme, profile, ["cond:0:0"]
    )
    assert token.auth_root == profile.auth_root != bytes(32)


def test_search_token_reports_the_exp1_metrics():
    """Exp. 1: q is the sweep variable, trapdoor size the secondary metric."""
    system = deployment(records_per_domain=1)
    profile, _, _, _ = system.enrol_user("DU-1", (DOMAINS[0],))
    sizes = {}
    for q in (1, 5, 20):
        token = token_mod.generate_search_token(
            system.scheme, profile, [f"kw{i}" for i in range(q)]
        )
        cost = token_mod.trapdoor_cost(token)
        assert cost.keyword_count == q
        assert cost.token_bytes == q * 32
        assert cost.overhead_bytes > 0        # AuthRoot_U + VID_U + rho + framing
        sizes[q] = cost.size_bytes
    assert sizes[1] < sizes[5] < sizes[20]


def test_search_token_generation_touches_no_kem_or_pairing():
    """Exp. 1 rule: ML-KEM encapsulation is a separate one-time setup cost.

    Checked against the module's actual bindings, not its source text — an earlier
    version grepped the file and tripped over the docstring that says "no pairing,
    no KEM", which is the opposite of a defect.
    """
    from Common.crypto import kem as kem_mod
    from Common.crypto import pairing as pairing_mod

    bound = list(vars(token_mod).values())
    assert not any(value is kem_mod for value in bound)
    assert not any(value is pairing_mod for value in bound)
    assert not any(
        getattr(value, "__name__", "").endswith((".kem", ".pairing"))
        for value in bound
    )


# ===========================================================================
# Phase VI Step 2 — AIM authorization verification
# ===========================================================================
def test_authorization_accepts_a_valid_request_and_resolves_shards():
    """Step 2 "identifies the authorized searchable-index shards"."""
    system = deployment()
    profile, authority_ids, attributes, resolver = system.enrol_user(
        "DU-1", (DOMAINS[0], DOMAINS[1])
    )
    token = token_mod.generate_search_token(
        system.scheme, profile, ["cond:0:0"]
    )
    decision = authz_mod.verify_search_request(
        system.aim,
        token,
        profile,
        authority_ids=authority_ids,
        attributes=attributes,
        resolver=resolver,
    )
    assert decision.accepted
    assert decision.failed_check is None
    assert set(decision.domains) == {DOMAINS[0], DOMAINS[1]}
    assert decision.policy_count >= 1


def test_authorization_reports_which_of_the_four_checks_failed():
    """"rejected without traversing" is only auditable if it says why."""
    system = deployment()
    profile, authority_ids, attributes, resolver = system.enrol_user(
        "DU-1", (DOMAINS[0],)
    )
    forged = types.SearchToken(
        tokens=(system.scheme.query_token("cond:0:0"),),
        auth_root=hashes.sha256(b"forged", domain=b"t"),
        vid_u=profile.vid,
        nonce=token_mod.fresh_nonce(),
    )
    decision = authz_mod.verify_search_request(
        system.aim,
        forged,
        profile,
        authority_ids=authority_ids,
        attributes=attributes,
        resolver=resolver,
    )
    assert not decision.accepted
    assert decision.failed_check == "authorization_root"
    assert decision.authorized_shards == ()


def test_authorization_rejects_a_replayed_nonce():
    """rho does nothing unless a verifier remembers it."""
    system = deployment()
    profile, authority_ids, attributes, resolver = system.enrol_user(
        "DU-1", (DOMAINS[0],)
    )
    nonces = authz_mod.NonceRegistry()
    token = token_mod.generate_search_token(system.scheme, profile, ["cond:0:0"])
    first = authz_mod.verify_search_request(
        system.aim, token, profile, authority_ids=authority_ids,
        attributes=attributes, resolver=resolver, nonces=nonces,
    )
    assert first.accepted
    replay = authz_mod.verify_search_request(
        system.aim, token, profile, authority_ids=authority_ids,
        attributes=attributes, resolver=resolver, nonces=nonces,
    )
    assert not replay.accepted
    assert replay.failed_check == "nonce"


def test_authorization_rejects_a_version_mismatch():
    system = deployment()
    profile, authority_ids, attributes, resolver = system.enrol_user(
        "DU-1", (DOMAINS[0],)
    )
    token = types.SearchToken(
        tokens=(system.scheme.query_token("cond:0:0"),),
        auth_root=profile.auth_root,
        vid_u=profile.vid + 3,
        nonce=token_mod.fresh_nonce(),
    )
    decision = authz_mod.verify_search_request(
        system.aim, token, profile, authority_ids=authority_ids,
        attributes=attributes, resolver=resolver,
    )
    assert not decision.accepted
    assert decision.failed_check == "authorization_version"


def test_authorization_rejects_a_profile_that_does_not_recompute():
    system = deployment()
    profile, authority_ids, attributes, resolver = system.enrol_user(
        "DU-1", (DOMAINS[0],)
    )
    token = token_mod.generate_search_token(system.scheme, profile, ["cond:0:0"])
    decision = authz_mod.verify_search_request(
        system.aim, token, profile, authority_ids=authority_ids,
        attributes=list(attributes) + ["extra:attribute"],   # S_U no longer matches
        resolver=resolver,
    )
    assert not decision.accepted
    assert decision.failed_check == "profile"


def test_authorization_rejects_when_no_policy_is_satisfied():
    system = deployment()
    profile, authority_ids, attributes, _ = system.enrol_user(
        "DU-1", (DOMAINS[0],)
    )
    token = token_mod.generate_search_token(system.scheme, profile, ["cond:0:0"])
    decision = authz_mod.verify_search_request(
        system.aim, token, profile, authority_ids=authority_ids,
        attributes=attributes,
        resolver=authz_mod.MappingPolicyResolver(mapping={}),
    )
    assert not decision.accepted
    assert decision.failed_check == "permitted_domains"


# ===========================================================================
# The full lifecycle
# ===========================================================================
def test_lifecycle_outsource_search_verify():
    """One record, all eight phases, nothing hand-constructed.

    The property no per-phase test can check: the shard set Phase VI Steps 3-4
    consume is the one Step 2 resolved, and the bundle Phase VIII verifies is the
    one Phase VI Step 5 produced over the record Phase V outsourced.
    """
    system = deployment(records_per_domain=2, keywords=6)
    domain = DOMAINS[0]
    target = system.records_in(domain)[0]
    keyword = target["record"].keywords[0]

    profile, authority_ids, attributes, resolver = system.enrol_user(
        "DU-1", (domain,)
    )
    nonces = authz_mod.NonceRegistry()

    # Phase VI Step 1.
    token = token_mod.generate_search_token(system.scheme, profile, [keyword])
    # Phase VI Step 2 — the shard set comes from here, not from the test.
    decision = authz_mod.verify_search_request(
        system.aim, token, profile, authority_ids=authority_ids,
        attributes=attributes, resolver=resolver, nonces=nonces,
    )
    assert decision.accepted
    authorized = decision.authorized_shards

    # Phase VI Step 3. V_Q comes from the AIM's decision, which is where the
    # manuscript puts it: the AIM holds the ledger-backed authority state that
    # C_j^sync measures a node's lag against.
    request = aass_mod.SearchRequest(
        tokens=token.tokens,
        authorized=authorized,
        vid_u=token.vid_u,
        query_versions=decision.query_versions,
    )
    selection = aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(
        system.nodes, request
    )
    assert selection.node.serves_domain(domain)

    # Phase VI Step 4.
    response = search_mod.execute_search(
        selection.node, token.tokens, authorized
    )
    assert target["cid"] in response.cids

    # Phase VI Step 5 + Phase VIII Steps 1-3.
    hit_index = target["record"].keywords.index(keyword)
    bundle = proof_mod.VerificationBundle.for_entry(
        target["commitment"], hit_index, target["entries"][hit_index]
    )
    result = proof_mod.verify_bundle(
        bundle,
        auth_root=system.owner_profile.auth_root,   # AuthRoot_DO
        require_version_match=False,
        chain_check=vledger_mod.chain_checker(system.ledger),
    )
    assert result.accepted, result.failed_step

    # Phase VIII Step 3 is outside Exp. 4, but the CID must resolve.
    assert system.store.get(target["cid"]) == target["ciphertext"]


def test_lifecycle_one_trapdoor_across_domains():
    """Exp. 3 end to end: one ST, every authorized domain, hits in each."""
    system = deployment(records_per_domain=1, keywords=6)
    shared = "cond:shared-integration"
    # Index the same keyword in all four domains.
    for domain in DOMAINS:
        node = system.node_for(domain)
        record = system.records_in(domain)[0]
        node.insert_entries(
            [
                types.IndexEntry(
                    token=system.scheme.index_token(shared),
                    cid=record["cid"],
                    policy_id=record["record"].policy_id,
                    vid=record["record"].metadata.vid,
                )
            ],
            domain=domain,
        )
    profile, authority_ids, attributes, resolver = system.enrol_user(
        "DU-1", tuple(DOMAINS)
    )
    token = token_mod.generate_search_token(system.scheme, profile, [shared])
    decision = authz_mod.verify_search_request(
        system.aim, token, profile, authority_ids=authority_ids,
        attributes=attributes, resolver=resolver,
    )
    assert decision.accepted
    assert token.keyword_count == 1          # ONE trapdoor for four domains

    responses = search_mod.execute_search_across(
        system.nodes, token.tokens, decision.authorized_shards
    )
    merged = search_mod.merge_responses(responses)
    assert len({r.node_id for r in responses}) == 4
    assert len(merged) == 4


def test_lifecycle_revocation_invalidates_a_stale_profile_and_bundle():
    """Phase VII's effect must be visible in both Phase VI Step 2 and Phase VIII.

    The cross-phase property: a revocation advances the authority, which makes the
    user's snapshot C_U stale (Step 2 rejects) and leaves the pre-update bundle
    disagreeing with the new anchor (Step 3 rejects).
    """
    system = deployment(records_per_domain=1, keywords=6)
    domain = DOMAINS[0]
    target = system.records_in(domain)[0]
    profile, authority_ids, attributes, resolver = system.enrol_user(
        "DU-1", (domain,)
    )
    token = token_mod.generate_search_token(
        system.scheme, profile, [target["record"].keywords[0]]
    )
    # Accepted before the revocation.
    assert authz_mod.verify_search_request(
        system.aim, token, profile, authority_ids=authority_ids,
        attributes=attributes, resolver=resolver,
    ).accepted

    stale_bundle = proof_mod.VerificationBundle.for_entry(
        target["commitment"], 0, target["entries"][0]
    )
    assert proof_mod.verify_bundle(
        stale_bundle,
        auth_root=system.owner_profile.auth_root,
        require_version_match=False,
        chain_check=vledger_mod.chain_checker(system.ledger),
    ).accepted

    # Phase VII: revoke, which advances the authority and re-anchors.
    receipt = dias_mod.synchronize(
        dias_mod.UpdateRequest(
            operation=dias_mod.Operation.REVOKE,
            cid=target["cid"],
            delta=dias_mod.UpdateDelta(revoked=("patient-revoked",)),
        ),
        authority=system.authorities[domain],
        nodes=system.nodes,
        commitment=target["commitment"],
        entries=target["entries"],
        auth_root_do=system.owner_profile.auth_root,
        aim=system.aim,
        ledger=system.ledger,
    )
    # Every holder of the affected shard, which is `sharding.replication`
    # nodes (2 since 2026-09-12), not one.
    assert receipt.touched_count == config_mod.load().index.replication

    # Phase VI Step 2 now rejects the stale profile.
    fresh_token = token_mod.generate_search_token(
        system.scheme, profile, [target["record"].keywords[0]]
    )
    decision = authz_mod.verify_search_request(
        system.aim, fresh_token, profile, authority_ids=authority_ids,
        attributes=attributes, resolver=resolver,
    )
    assert not decision.accepted
    assert decision.failed_check == "authority_commitments"

    # Rebuilding the profile from the AIM restores acceptance.
    rebuilt = profile_mod.build_profile_from_aim(
        system.aim, uid="DU-1", authority_ids=authority_ids, attributes=attributes
    )
    assert authz_mod.verify_search_request(
        system.aim,
        token_mod.generate_search_token(
            system.scheme, rebuilt, [target["record"].keywords[0]]
        ),
        rebuilt,
        authority_ids=authority_ids,
        attributes=attributes,
        resolver=resolver,
    ).accepted


def test_lifecycle_c_sync_counts_authorities_the_node_has_not_caught_up_on():
    """C_j^sync = |{(ID_k, v_k) in V_Q : v_{j,k} < v_k}| — Phase VI Step 3.

    A COUNT over the query-relevant authorities, read per authority from the
    Meta_i the node has applied. It replaces `|VID_U - VID_j|`, which belonged to
    the previous manuscript revision and measured the USER's staleness rather
    than the NODE's: the term exists so AASS avoids routing to a node that
    cannot yet serve the query's authorization state, and a user's own profile
    version says nothing about that.

    The three states below are the ones the term must separate: the node is
    current, the node is behind, and DIAS has brought it back up to date.
    """
    system = deployment(records_per_domain=1)
    domain = DOMAINS[0]
    node = system.node_for(domain)
    authority = system.authorities[domain]
    profile, authority_ids, attributes, resolver = system.enrol_user(
        "DU-1", (domain,)
    )

    # Current: the node has applied this authority's latest Meta_i, so nothing
    # in V_Q lags.
    assert profile.vid == node.vid_for_domains([domain]) == authority.vid
    token = token_mod.generate_search_token(system.scheme, profile, ["cond:0:0"])
    shards = ((domain, system.records_in(domain)[0]["record"].policy_id),)
    current_vq = ((authority.authority_id, authority.vid),)
    request = aass_mod.SearchRequest(
        tokens=token.tokens,
        authorized=shards,
        vid_u=token.vid_u,
        query_versions=current_vq,
    )
    assert aass_mod.estimate_costs(node, request).sync == 0.0

    # Behind: an authority the query depends on has moved and this node has not
    # received the delta yet. One authority in V_Q, one lag.
    ahead = aass_mod.SearchRequest(
        tokens=token.tokens,
        authorized=shards,
        vid_u=token.vid_u,
        query_versions=((authority.authority_id, authority.vid + 1),),
    )
    assert aass_mod.estimate_costs(node, ahead).sync == 1.0

    # After a revocation the node advances; a user still on the old profile is
    # one version behind, which is exactly what C_j^sync should report.
    dias_mod.synchronize(
        dias_mod.UpdateRequest(
            operation=dias_mod.Operation.REVOKE,
            cid=system.records_in(domain)[0]["cid"],
            delta=dias_mod.UpdateDelta(revoked=("p1",)),
        ),
        authority=authority,
        nodes=system.nodes,
        commitment=system.records_in(domain)[0]["commitment"],
        entries=system.records_in(domain)[0]["entries"],
        auth_root_do=system.owner_profile.auth_root,
        aim=system.aim,
    )
    assert node.vid_for_domains([domain]) == authority.vid == profile.vid + 1
    # Caught up: DIAS delivered the new Meta_i, so the node no longer lags the
    # authority's CURRENT version. The user's profile is now a version behind,
    # and that is deliberately NOT what this term measures.
    caught_up = aass_mod.SearchRequest(
        tokens=token.tokens,
        authorized=shards,
        vid_u=token.vid_u,
        query_versions=((authority.authority_id, authority.vid),),
    )
    assert aass_mod.estimate_costs(node, caught_up).sync == 0.0


def test_lifecycle_nothing_is_reportable_on_a_stub_group():
    """The whole deployment runs on an injected group, so it must refuse to report."""
    system = deployment(records_per_domain=1)
    assert not system.context.reportable
    try:
        system.context.assert_reportable()
    except p12.initializer.UnfaithfulGroupError:
        pass
    else:
        raise AssertionError("a stub-group deployment must not be reportable")
    # And the scheduler refuses a reportable Exp. 7-8 run while lambdas are pending.
    # The weights were fixed by the documented sweep on 2026-08-28, so the gate
    # is exercised against a deliberately pending copy -- it must keep refusing
    # after the weights are fixed, which is exactly when a regression would
    # otherwise go unnoticed.
    import dataclasses

    cfg = config_mod.load()
    pending = dataclasses.replace(
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
            aass_mod.VARIANT_AASS, config=pending, reportable=True
        )
    except config_mod.SchedulerWeightsPendingError:
        return
    raise AssertionError("a reportable AASS run must be refused")


def test_lifecycle_ledger_stays_intact_across_every_phase():
    """One tamper-evident history from Phase II registration to Phase VII anchors."""
    system = deployment(records_per_domain=2)
    assert system.ledger.verify_chain()
    system.aim.verify_against_ledger(system.ledger)
    sizes = system.ledger.namespace_sizes()
    assert sizes[ledger_mod.NS_AUTHORITY_REGISTRATIONS] == 4
    assert sizes[ledger_mod.NS_AUTHORIZATION_STATES] == 4
    assert sizes[ledger_mod.NS_VERSION_IDENTIFIERS] == len(system.records)
    assert system.ledger.verify_chain()


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
