"""The eight experiments of README §5, as measurable objects.

Each declares its sweep variable, its primary and secondary metrics, an **untimed**
``prepare`` and a **timed** ``measure``. The split is the measurement boundary: what
``measure`` touches is what the reported number covers, and each class's docstring
quotes the rule it implements.

The boundaries, from README §5 and ``SCHEME.md``:

* Exp. 1 — online trapdoor generation only; ML-KEM encapsulation excluded.
* Exp. 2 — AIM check → AASS selection → shard search → response assembly; index
  construction offline.
* Exp. 3 — one trapdoor reused across ``d`` domains; count trapdoors issued.
* Exp. 4 — client-side verification only; IPFS fetch and decryption excluded.
* Exp. 5 — incremental update only; a global rebuild is a Phase VII bug.
* Exp. 6 — IAS end-to-end until every affected FSN reports the new VID.
* Exp. 7–8 — one closed-loop workload per variant, both metric sets from the
  same runs.

**Records come from a source, not from the corpus directly.** The committed
``dataset_manifest.json`` is the superseded v1, so ``load_verified_corpus()``
refuses to load anything; :class:`SyntheticRecordSource` lets the harness be built
and tested now. It reports ``corpus_type = "synthetic"``, which
``provenance.reportability`` rejects — so nothing it produces can be quoted, by
construction rather than by discipline.
"""

from __future__ import annotations

import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402

from .. import config as scheme_config  # noqa: E402
from .. import types  # noqa: E402
from ..aim import aim as aim_mod  # noqa: E402
from ..aim import verification as authz_mod  # noqa: E402
from ..authority import authority as authority_mod  # noqa: E402
from ..authority import initializer as init_mod  # noqa: E402
from ..chain import ipfs as ipfs_mod  # noqa: E402
from ..chain import ledger as ledger_mod  # noqa: E402
from ..chain import outsourcing as out_mod  # noqa: E402
from ..fsn import fsn as fsn_mod  # noqa: E402
from ..fsn import search as search_mod  # noqa: E402
from ..index import commit as commit_mod  # noqa: E402
from ..index import extract as extract_mod  # noqa: E402
from ..index import tokens as tokens_mod  # noqa: E402
from ..scheduler import aass as aass_mod  # noqa: E402
from ..shard import propagation as prop_mod  # noqa: E402
from ..sync import ias as ias_mod  # noqa: E402
from ..user import profile as profile_mod  # noqa: E402
from ..user import token as token_mod  # noqa: E402
from ..verify import ledger as vledger_mod  # noqa: E402
from ..verify import proof as proof_mod  # noqa: E402
from .runner import MetricSpec, Sample  # noqa: E402

MS = "ms"
BYTES = "B"
KB = "KB"
QPS = "queries/s"
COUNT = "count"


# ===========================================================================
# Record sources
# ===========================================================================
@dataclass
class SyntheticRecordSource:
    """In-process records with the frozen corpus's shape but none of its content.

    ``corpus_type`` is ``"synthetic"``, which makes every run built on it
    non-reportable — README §4 admits only ``synthea``. This exists so the harness
    can be written and tested while the v2 manifest is missing, not as a substitute
    for the corpus: keyword co-occurrence here is arbitrary, and Exp. 2's ``n_eff``
    depends on exactly that.
    """

    keywords_per_record: int = 6
    domains: Tuple[str, ...] = extract_mod.DEFAULT_DOMAIN_NAMES
    vocabulary: int = 2006
    corpus_type: str = "synthetic"
    corpus_sha256: Optional[str] = None

    def records(self, count: int, *, domains: Optional[int] = None):
        domain_count = len(self.domains) if domains is None else domains
        assignment = extract_mod.BucketedPolicyAssignment(
            policies_per_domain=2, domains=max(domain_count, 1)
        )
        names = self.domains[:domain_count] or (f"dom{i}" for i in range(domain_count))
        names = tuple(names) if isinstance(names, tuple) else tuple(names)
        for rid in range(count):
            dom_index = rid % domain_count
            record = _SyntheticRecord(
                rid=rid,
                pid=f"patient-{rid:06d}",
                vid=1,
                dom=dom_index,
                ts="2026-08-12T00:00:00Z",
                kw=[
                    f"kw:{(rid * self.keywords_per_record + k) % self.vocabulary:05d}"
                    for k in range(self.keywords_per_record)
                ],
            )
            yield extract_mod.extract(
                record, assignment=assignment, domain_names=names
            )


@dataclass
class _SyntheticRecord:
    """Mirrors ``Dataset.corpus.Record``'s field names and shape."""

    rid: int
    pid: str
    vid: int
    dom: int
    ts: str
    kw: List[str]


# ===========================================================================
# A deployment the experiments measure against
# ===========================================================================
@dataclass
class Deployment:
    """Phases I-V, assembled. Built in ``prepare``, so never on a measured path."""

    config: scheme_config.Configuration
    scheme: tokens_mod.TokenScheme
    context: init_mod.GlobalContext
    ledger: ledger_mod.InProcessLedger
    aim: aim_mod.AuthorizationIndexManager
    store: ipfs_mod.InProcessContentStore
    register: out_mod.MetadataRegister
    catalog: prop_mod.IndexCatalog
    authorities: Dict[str, authority_mod.Authority]
    nodes: Tuple[fsn_mod.FogSearchNode, ...]
    owner_profile: types.VersionBoundAuthorizationProfile
    records: List[Dict[str, Any]] = field(default_factory=list)
    domains: Tuple[str, ...] = ()

    def node_for(self, domain: str) -> fsn_mod.FogSearchNode:
        return next(n for n in self.nodes if n.serves_domain(domain))


def build_deployment(
    *,
    config: scheme_config.Configuration,
    source: SyntheticRecordSource,
    records: int,
    domains: Optional[int] = None,
    group_provider=None,
    search_key: Optional[bytes] = None,
) -> Deployment:
    """Phases I-V for one sweep point. Untimed by construction.

    ``group_provider`` is injected because no faithful Type-III backend exists; the
    resulting context reports ``reportable = False`` and provenance records it.
    """
    if group_provider is None:
        group_provider = _unfaithful_group_provider
    domain_count = len(source.domains) if domains is None else domains
    domain_names = tuple(
        source.domains[:domain_count]
        if domain_count <= len(source.domains)
        else tuple(f"dom{i}" for i in range(domain_count))
    )

    context = init_mod.initialize(config, group_provider=group_provider)
    scheme = tokens_mod.TokenScheme.from_config(
        config, search_key or hashes.sha256(b"harness", domain=b"harness/search-key")
    )
    ledger = ledger_mod.InProcessLedger()
    aim = aim_mod.AuthorizationIndexManager()
    store = ipfs_mod.InProcessContentStore()
    register = out_mod.MetadataRegister()
    catalog = prop_mod.IndexCatalog()

    registry = authority_mod.AttributeNamespaceRegistry()
    operations = _HarnessGroupOperations()
    authorities: Dict[str, authority_mod.Authority] = {}
    for index, domain in enumerate(domain_names, start=1):
        authority = authority_mod.Authority.create(
            context,
            authority_id=f"AA{index}",
            domain=domain,
            attributes=authority_mod.default_attributes(
                f"AA{index}", config.authorities.attributes_per_authority
            ),
            operations=operations,
            registry=registry,
        )
        authority.register(ledger)
        ledger.publish_authorization_state(authority.state())
        authorities[domain] = authority

    nodes = fsn_mod.build_fsn_set(
        domain_names,
        min(config.topology.fog_search_nodes, len(domain_names)),
        bloom_bits_per_entry=config.index.bloom_bits_per_entry,
        bloom_num_hashes=config.index.bloom_num_hashes,
    )
    aim_mod.initial_synchronization(
        aim, ledger, [a.authority_id for a in authorities.values()], nodes
    )

    owner_profile = profile_mod.build_profile_from_aim(
        aim,
        uid="DO-1",
        authority_ids=[a.authority_id for a in authorities.values()],
        attributes=sorted(
            attr for a in authorities.values() for attr in a.attributes[:2]
        ),
    )

    deployment = Deployment(
        config=config,
        scheme=scheme,
        context=context,
        ledger=ledger,
        aim=aim,
        store=store,
        register=register,
        catalog=catalog,
        authorities=authorities,
        nodes=nodes,
        owner_profile=owner_profile,
        domains=domain_names,
    )

    for record in source.records(records, domains=domain_count):
        deployment.records.append(_outsource(deployment, record))
    return deployment


def _outsource(deployment: Deployment, record) -> Dict[str, Any]:
    """Phase IV Steps 3-5 and Phase V Steps 1-5 for one record."""
    rid = record.record_id
    ciphertext = hashes.sha256(f"ct-{rid}".encode(), domain=b"harness/ct") * 4
    cid = ipfs_mod.upload_ciphertext(deployment.store, ciphertext)
    entries = tuple(
        types.IndexEntry(
            token=deployment.scheme.index_token(kw),
            cid=cid,
            policy_id=record.policy_id,
            vid=record.metadata.vid,
        )
        for kw in record.keywords
    )
    commitment = commit_mod.commit_record(
        record_id=rid,
        entries=entries,
        policy_id=record.policy_id,
        vid=record.metadata.vid,
        auth_root_do=deployment.owner_profile.auth_root,
    )
    out_mod.register_metadata(
        deployment.register, cid=cid, metadata=record.metadata, commitment=commitment
    )
    out_mod.anchor_initial_commitment(
        deployment.ledger, cid=cid, commitment=commitment, vid=record.metadata.vid
    )
    payload = prop_mod.build_sync_payload(
        entries=entries, metadata=record.metadata, cid=cid
    )
    prop_mod.propagate_to_authorized(
        payload, domain=record.domain, nodes=deployment.nodes
    )
    deployment.catalog.record(payload, domain=record.domain)
    return dict(
        record=record, entries=entries, commitment=commitment, cid=cid,
        ciphertext=ciphertext,
    )


def _unfaithful_group_provider(pairing_params):
    """A group for the harness. NOT from a faithful backend, and it says so.

    ``faithful=False`` propagates into ``GlobalContext.reportable`` and from there
    into ``run_meta.json``'s ``not_reportable_because``, so a figure produced this
    way cannot be quoted without the reason travelling with it.
    """
    return init_mod.GroupDescription(
        curve=str(pairing_params.get("curve", "BN254")),
        backend="harness-injected-not-a-backend",
        g1=b"g1", g2=b"g2", e_g1_g2=b"egt",
        faithful=False,
    )


class _HarnessGroupOperations:
    """Hash-based stand-ins. Not a group; see the Phase III test discussion."""

    def __init__(self) -> None:
        self._counter = 0

    def random_exponent(self) -> bytes:
        self._counter += 1
        return hashes.sha256(
            self._counter.to_bytes(4, "big"), domain=b"harness/exponent"
        )

    def exponentiate_gt(self, base: bytes, exponent: bytes) -> bytes:
        return hashes.sha256(base, exponent, domain=b"harness/gt")

    def exponentiate_g1(self, base: bytes, exponent: bytes) -> bytes:
        return hashes.sha256(base, exponent, domain=b"harness/g1")

    def multiply_g1(self, left: bytes, right: bytes) -> bytes:
        return hashes.sha256(left, right, domain=b"harness/g1-mul")

    def hash_to_g1(self, data: bytes) -> bytes:
        return hashes.sha256(data, domain=b"harness/g1-hash")


def _enrol(deployment: Deployment, uid: str, domains: Sequence[str]):
    """A Data User authorized across ``domains``, with its resolver."""
    authority_ids = [deployment.authorities[d].authority_id for d in domains]
    attributes = sorted(
        attr for d in domains for attr in deployment.authorities[d].attributes[:3]
    )
    profile = profile_mod.build_profile_from_aim(
        deployment.aim, uid=uid, authority_ids=authority_ids, attributes=attributes
    )
    mapping = {}
    for domain in domains:
        policies = {
            r["record"].policy_id
            for r in deployment.records
            if r["record"].domain == domain
        }
        mapping[(uid, domain)] = tuple(sorted(policies))
    return profile, authority_ids, attributes, authz_mod.MappingPolicyResolver(mapping)


# ===========================================================================
# Exp. 1 — Trapdoor Generation Latency
# ===========================================================================
@dataclass
class Exp1TrapdoorGeneration:
    """"online trapdoor generation only… ML-KEM encapsulation is excluded".

    ``measure`` calls ``generate_search_token`` and nothing else: ``q`` PRF
    evaluations plus a nonce draw. The KEM keypair and the VAP are built in
    ``prepare``, which is where session establishment belongs — reporting it here
    would fold a one-time cost into a per-query curve.
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    name: str = "exp1_trapdoor_generation"
    number: int = 1
    variable: str = "keywords_per_query"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("trapdoor_size", BYTES),
        MetricSpec("tokens", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(
                self.config.experiment("exp1").values
            )

    def prepare(self, value: Any) -> Any:
        deployment = build_deployment(
            config=self.config, source=self.source, records=8
        )
        profile, _, _, _ = _enrol(deployment, "DU-1", deployment.domains[:1])
        keywords = [f"kw:{i:05d}" for i in range(int(value))]
        return deployment.scheme, profile, keywords

    def measure(self, prepared: Any) -> Sample:
        scheme, profile, keywords = prepared
        started = time.perf_counter_ns()
        token = token_mod.generate_search_token(scheme, profile, keywords)
        elapsed = time.perf_counter_ns() - started
        cost = token_mod.trapdoor_cost(token)
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "trapdoor_size": float(cost.size_bytes),
                "tokens": float(cost.keyword_count),
            },
        )


# ===========================================================================
# Exp. 2 — Search Latency
# ===========================================================================
@dataclass
class Exp2SearchLatency:
    """"the full online path: AIM authorization check → AASS selection → shard
    search → response assembly. Index construction is offline and excluded."

    All four stages are inside ``measure``; the index is built in ``prepare``.
    ``n_eff`` is reported alongside latency because it is "the only thing that can
    demonstrate the paper's claim" (README §5).
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    name: str = "exp2_search_latency"
    number: int = 2
    variable: str = "index_size"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("n_eff", COUNT),
        MetricSpec("entries_traversed", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp2").values)

    def prepare(self, value: Any) -> Any:
        # value is the index size N in entries; records carry |W_i| entries each.
        record_count = max(1, int(value) // self.source.keywords_per_record)
        deployment = build_deployment(
            config=self.config, source=self.source, records=record_count
        )
        domain = deployment.domains[0]
        profile, authority_ids, attributes, resolver = _enrol(
            deployment, "DU-1", (domain,)
        )
        target = next(
            r for r in deployment.records if r["record"].domain == domain
        )
        keyword = target["record"].keywords[0]
        return dict(
            deployment=deployment, profile=profile, authority_ids=authority_ids,
            attributes=attributes, resolver=resolver, keyword=keyword,
        )

    def measure(self, prepared: Any) -> Sample:
        d = prepared["deployment"]
        started = time.perf_counter_ns()
        token = token_mod.generate_search_token(
            d.scheme, prepared["profile"], [prepared["keyword"]]
        )
        decision = authz_mod.verify_search_request(          # AIM check
            d.aim, token, prepared["profile"],
            authority_ids=prepared["authority_ids"],
            attributes=prepared["attributes"],
            resolver=prepared["resolver"],
        )
        if not decision.accepted:
            raise RuntimeError(f"authorization rejected: {decision.reason}")
        request = aass_mod.SearchRequest(
            tokens=token.tokens,
            authorized=decision.authorized_shards,
            vid_u=token.vid_u,
        )
        selection = aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(  # AASS
            d.nodes, request
        )
        response = search_mod.execute_search(                # shard search
            selection.node, token.tokens, decision.authorized_shards
        )
        hits = tuple(response.hits)                          # response assembly
        elapsed = time.perf_counter_ns() - started
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "n_eff": float(response.n_eff),
                "entries_traversed": float(response.statistics.entries_traversed),
            },
        )


# ===========================================================================
# Exp. 3 — Cross-Domain Search Scalability
# ===========================================================================
@dataclass
class Exp3CrossDomain:
    """"Issues ONE authorization-bound trapdoor reused across domains. Count
    trapdoors issued as a secondary metric."

    The secondary is the point: it stays at 1 as ``d`` grows, where a baseline
    issues ``d``.
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    name: str = "exp3_crossdomain_scalability"
    number: int = 3
    variable: str = "domains"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("trapdoors_issued", COUNT),
        MetricSpec("nodes_searched", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp3").values)

    def prepare(self, value: Any) -> Any:
        domain_count = int(value)
        deployment = build_deployment(
            config=self.config, source=self.source,
            records=domain_count * 4, domains=domain_count,
        )
        shared = "kw:00000"
        # Index one shared keyword in every domain so a single trapdoor can hit
        # all of them — the property this experiment measures.
        for domain in deployment.domains:
            node = deployment.node_for(domain)
            record = next(
                r for r in deployment.records if r["record"].domain == domain
            )
            node.insert_entries(
                [
                    types.IndexEntry(
                        token=deployment.scheme.index_token(shared),
                        cid=record["cid"],
                        policy_id=record["record"].policy_id,
                        vid=record["record"].metadata.vid,
                    )
                ],
                domain=domain,
            )
        profile, authority_ids, attributes, resolver = _enrol(
            deployment, "DU-1", deployment.domains
        )
        return dict(
            deployment=deployment, profile=profile, authority_ids=authority_ids,
            attributes=attributes, resolver=resolver, keyword=shared,
        )

    def measure(self, prepared: Any) -> Sample:
        d = prepared["deployment"]
        started = time.perf_counter_ns()
        token = token_mod.generate_search_token(
            d.scheme, prepared["profile"], [prepared["keyword"]]
        )
        decision = authz_mod.verify_search_request(
            d.aim, token, prepared["profile"],
            authority_ids=prepared["authority_ids"],
            attributes=prepared["attributes"],
            resolver=prepared["resolver"],
        )
        if not decision.accepted:
            raise RuntimeError(f"authorization rejected: {decision.reason}")
        responses = search_mod.execute_search_across(
            d.nodes, token.tokens, decision.authorized_shards
        )
        search_mod.merge_responses(responses)
        elapsed = time.perf_counter_ns() - started
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                # ONE trapdoor, however many domains. This is the claim.
                "trapdoors_issued": 1.0,
                "nodes_searched": float(len(responses)),
            },
        )


# ===========================================================================
# Exp. 4 — Verification Overhead
# ===========================================================================
@dataclass
class Exp4Verification:
    """"Verification is client-side: Merkle proof check, ``Commit_i*``
    recomputation, and blockchain-consistency check. IPFS fetch and decryption are
    EXCLUDED."

    ``measure`` calls ``verify_response`` and nothing else; the bundles are built
    in ``prepare``, since generating them is the Fog Search Node's Phase VI Step 5
    work, not the client's.
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    name: str = "exp4_verification_overhead"
    number: int = 4
    variable: str = "returned_results"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("proof_size", KB),
        MetricSpec("path_length", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp4").values)

    def prepare(self, value: Any) -> Any:
        wanted = int(value)
        per_record = self.source.keywords_per_record
        record_count = max(1, -(-wanted // per_record))
        deployment = build_deployment(
            config=self.config, source=self.source, records=record_count
        )
        bundles: List[proof_mod.VerificationBundle] = []
        for record in deployment.records:
            bundles.extend(
                proof_mod.build_response(record["commitment"], record["entries"])
            )
            if len(bundles) >= wanted:
                break
        return dict(
            deployment=deployment,
            bundles=tuple(bundles[:wanted]),
            auth_root=deployment.owner_profile.auth_root,
        )

    def measure(self, prepared: Any) -> Sample:
        d = prepared["deployment"]
        checker = vledger_mod.chain_checker(d.ledger, check_chain_integrity=False)
        started = time.perf_counter_ns()
        batch = proof_mod.verify_response(
            prepared["bundles"],
            auth_root=prepared["auth_root"],
            # Phase VIII Step 2's VID_i = VID_U compares two different counters;
            # see SCHEME.md. Skipped so the measurement is of the cryptographic
            # work rather than of a check that rejects every record.
            require_version_match=False,
            chain_check=checker,
        )
        elapsed = time.perf_counter_ns() - started
        if batch.accepted_count != batch.record_count:
            raise RuntimeError(
                f"{len(batch.rejected)} of {batch.record_count} bundles failed "
                f"verification"
            )
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "proof_size": batch.total_proof_kb,
                "path_length": batch.mean_path_length,
            },
        )


# ===========================================================================
# Exp. 5 — Dynamic Keyword Update
# ===========================================================================
@dataclass
class Exp5KeywordUpdate:
    """"Measure incremental update only. A global index rebuild indicates a Phase
    VII implementation bug."

    ``k`` counts (keyword, document) pairs. The secondaries are the evidence that
    the update was incremental: Merkle nodes recomputed, and entries rewritten.
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    name: str = "exp5_keyword_update"
    number: int = 5
    variable: str = "keyword_document_pairs"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("merkle_nodes_recomputed", COUNT),
        MetricSpec("entries_rewritten", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp5").values)

    def prepare(self, value: Any) -> Any:
        pairs = int(value)
        per_record = self.source.keywords_per_record
        record_count = max(1, -(-pairs // per_record))
        deployment = build_deployment(
            config=self.config, source=self.source, records=record_count
        )
        return dict(deployment=deployment, pairs=pairs)

    def measure(self, prepared: Any) -> Sample:
        d = prepared["deployment"]
        pairs = prepared["pairs"]
        applied = 0
        nodes_recomputed = 0
        entries_rewritten = 0
        started = time.perf_counter_ns()
        for record in d.records:
            if applied >= pairs:
                break
            domain = record["record"].domain
            receipt = ias_mod.synchronize(
                ias_mod.UpdateRequest(
                    operation=ias_mod.Operation.MODIFY,
                    cid=record["cid"],
                    delta=ias_mod.UpdateDelta(
                        policy_id=f"{domain}/updated-{applied}"
                    ),
                ),
                authority=d.authorities[domain],
                nodes=d.nodes,
                commitment=record["commitment"],
                entries=record["entries"],
                auth_root_do=d.owner_profile.auth_root,
            )
            applied += receipt.index_evolution.entries_touched
            nodes_recomputed += receipt.merkle_nodes_recomputed
            entries_rewritten += receipt.entries_rewritten
            if receipt.commitment_evolution.rebuilt:
                raise RuntimeError(
                    "a Modify rebuilt the record's tree; Step 4 must path-update "
                    "when the leaf count is unchanged"
                )
        elapsed = time.perf_counter_ns() - started
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "merkle_nodes_recomputed": float(nodes_recomputed),
                "entries_rewritten": float(entries_rewritten),
            },
        )


# ===========================================================================
# Exp. 6 — Authorization Synchronization
# ===========================================================================
@dataclass
class Exp6AuthorizationSync:
    """"IAS end-to-end: authority commitment recomputation → Merkle path update →
    IAS message → selective FSN propagation, until all affected FSNs report the new
    VID. Report FSNs touched."

    ``synchronize`` verifies that postcondition itself, so a run that returns has
    reached it.
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    name: str = "exp6_authorization_sync"
    number: int = 6
    variable: str = "authorization_updates"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("ias_message_size", KB),
        MetricSpec("fsns_touched", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp6").values)

    def prepare(self, value: Any) -> Any:
        deployment = build_deployment(
            config=self.config, source=self.source, records=8
        )
        return dict(deployment=deployment, updates=int(value))

    def measure(self, prepared: Any) -> Sample:
        d = prepared["deployment"]
        record = d.records[0]
        domain = record["record"].domain
        authority = d.authorities[domain]
        total_bytes = 0.0
        touched = 0
        started = time.perf_counter_ns()
        for index in range(prepared["updates"]):
            receipt = ias_mod.synchronize(
                ias_mod.UpdateRequest(
                    operation=ias_mod.Operation.REVOKE,
                    cid=record["cid"],
                    delta=ias_mod.UpdateDelta(revoked=(f"patient-{index}",)),
                ),
                authority=authority,
                nodes=d.nodes,
                commitment=record["commitment"],
                entries=record["entries"],
                auth_root_do=d.owner_profile.auth_root,
                aim=d.aim,
            )
            total_bytes += receipt.message.size_kb
            touched += receipt.touched_count
        elapsed = time.perf_counter_ns() - started
        updates = max(1, prepared["updates"])
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "ias_message_size": total_bytes / updates,
                "fsns_touched": touched / updates,
            },
        )


# ===========================================================================
# Exp. 7 / 8 — throughput and load balancing, from ONE set of runs
# ===========================================================================
@dataclass
class _WorkloadOutcome:
    """Both metric sets from a single closed-loop replay."""

    throughput: float
    p50_ms: float
    p95_ms: float
    rejected: int
    utilization_stddev: float
    max_utilization: float
    cross_node_forwards: int


@dataclass
class SchedulerAblation:
    """The shared engine for Exp. 7 and Exp. 8.

    README §5: "Exp. 7 and Exp. 8 report different metrics from **the same runs**
    — run the trace once per variant and emit both." So the workload is replayed
    once here and both experiments read the same outcome.

    **Not reportable, for two reasons beyond the λ sweep.** README §1 requires each
    FSN to be an independent process; this replays in one interpreter, so a
    concurrency figure would not measure the stated topology. Both reasons are
    recorded in ``run_meta.json``.
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    variant: str = aass_mod.VARIANT_AASS

    def replay(self, deployment: Deployment, requests, concurrency: int) -> _WorkloadOutcome:
        scheduler = aass_mod.Scheduler(
            self.variant, config=self.config, reportable=False
        )
        latencies: List[float] = []
        rejected = 0
        forwards = 0
        started = time.perf_counter()
        for token, decision in requests:
            request = aass_mod.SearchRequest(
                tokens=token.tokens,
                authorized=decision.authorized_shards,
                vid_u=token.vid_u,
            )
            try:
                selection = scheduler.select(deployment.nodes, request)
            except aass_mod.SchedulerError:
                rejected += 1
                continue
            began = time.perf_counter_ns()
            try:
                search_mod.execute_search(
                    selection.node, token.tokens, decision.authorized_shards
                )
            except search_mod.SearchRejected:
                rejected += 1
                continue
            latencies.append((time.perf_counter_ns() - began) / 1e6)
            if not selection.node.serves_domain(request.domains[0]):
                forwards += 1
        wall = time.perf_counter() - started

        window_ns = max(1, int(wall * 1e9))
        utilizations = [node.utilization(window_ns) for node in deployment.nodes]
        ordered = sorted(latencies) or [0.0]
        return _WorkloadOutcome(
            throughput=(len(latencies) / wall) if wall > 0 else 0.0,
            p50_ms=ordered[len(ordered) // 2],
            p95_ms=ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
            rejected=rejected,
            utilization_stddev=(
                statistics.pstdev(utilizations) if len(utilizations) > 1 else 0.0
            ),
            max_utilization=max(utilizations) if utilizations else 0.0,
            cross_node_forwards=forwards,
        )

    def prepare(self, value: Any) -> Any:
        """Build the deployment and RECORD the arrival trace once.

        "All 4 variants see byte-identical workloads" — so the request list is
        materialised here and replayed, not regenerated per variant.
        """
        concurrency = int(value)
        deployment = build_deployment(
            config=self.config, source=self.source, records=32
        )
        profile, authority_ids, attributes, resolver = _enrol(
            deployment, "DU-1", deployment.domains
        )
        requests = []
        for index in range(concurrency):
            record = deployment.records[index % len(deployment.records)]
            token = token_mod.generate_search_token(
                deployment.scheme, profile, [record["record"].keywords[0]]
            )
            decision = authz_mod.verify_search_request(
                deployment.aim, token, profile,
                authority_ids=authority_ids, attributes=attributes,
                resolver=resolver,
            )
            if decision.accepted:
                requests.append((token, decision))
        return dict(
            deployment=deployment, requests=tuple(requests), concurrency=concurrency
        )


@dataclass
class Exp7Throughput(SchedulerAblation):
    """Exp. 7: throughput (queries/s), with p50/p95 and rejections."""

    name: str = "exp7_search_throughput"
    number: int = 7
    variable: str = "concurrency"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("throughput", QPS)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("latency_p95", MS),
        MetricSpec("rejected", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp7").values)

    def measure(self, prepared: Any) -> Sample:
        outcome = self.replay(
            prepared["deployment"], prepared["requests"], prepared["concurrency"]
        )
        return Sample(
            primary=outcome.throughput,
            secondaries={
                "latency_p95": outcome.p95_ms,
                "rejected": float(outcome.rejected),
            },
        )


@dataclass
class Exp8LoadBalance(SchedulerAblation):
    """Exp. 8: the utilization spread of the SAME runs Exp. 7 measures."""

    name: str = "exp8_load_balance"
    number: int = 8
    variable: str = "concurrency"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("utilization_stddev", COUNT)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("max_node_utilization", COUNT),
        MetricSpec("cross_node_forwards", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp8").values)

    def measure(self, prepared: Any) -> Sample:
        outcome = self.replay(
            prepared["deployment"], prepared["requests"], prepared["concurrency"]
        )
        return Sample(
            primary=outcome.utilization_stddev,
            secondaries={
                "max_node_utilization": outcome.max_utilization,
                "cross_node_forwards": float(outcome.cross_node_forwards),
            },
        )


EXPERIMENTS = {
    1: Exp1TrapdoorGeneration,
    2: Exp2SearchLatency,
    3: Exp3CrossDomain,
    4: Exp4Verification,
    5: Exp5KeywordUpdate,
    6: Exp6AuthorizationSync,
    7: Exp7Throughput,
    8: Exp8LoadBalance,
}


def build_experiment(
    number: int,
    config: scheme_config.Configuration,
    source: Optional[SyntheticRecordSource] = None,
):
    """Instantiate one experiment by its README §5 number."""
    if number not in EXPERIMENTS:
        raise KeyError(
            f"no experiment {number}; README §5 defines 1-8"
        )
    return EXPERIMENTS[number](
        config=config, source=source or SyntheticRecordSource()
    )


__all__ = [
    "SyntheticRecordSource",
    "Deployment",
    "build_deployment",
    "EXPERIMENTS",
    "build_experiment",
    "Exp1TrapdoorGeneration",
    "Exp2SearchLatency",
    "Exp3CrossDomain",
    "Exp4Verification",
    "Exp5KeywordUpdate",
    "Exp6AuthorizationSync",
    "Exp7Throughput",
    "Exp8LoadBalance",
]
