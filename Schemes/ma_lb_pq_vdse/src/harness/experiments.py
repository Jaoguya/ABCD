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

import dataclasses

import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes  # noqa: E402
from Common.crypto.rng import DeterministicRNG  # noqa: E402

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
from ..fsn import pool as fsn_pool  # noqa: E402
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
        # Slicing past the end truncates silently, and a short-but-non-empty
        # slice is still truthy — so an `or` fallback never fires and Exp. 3
        # raised ExtractionError at d=6,8,10 against the 4 default names.
        # Generate names whenever the configured list cannot cover domain_count.
        names = tuple(self.domains[:domain_count])
        if len(names) < domain_count:
            names = tuple(f"dom{i}" for i in range(domain_count))
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
class CorpusRecordSource:
    """Records streamed from the frozen Synthea corpus — the reportable source.

    Interface-compatible with :class:`SyntheticRecordSource` so the experiments
    do not care which one they were given, but with three real differences:

    * ``corpus_type`` is ``"synthea"`` and ``corpus_sha256`` is the verified
      digest, so runs built on it can actually satisfy README §4/§15.
    * Keyword co-occurrence is the corpus's own. Exp. 2's ``n_eff`` depends on
      exactly that, which is why the synthetic source can never stand in for a
      reportable number.
    * It **streams**. ``load_verified_corpus()`` materialises all 1.14M records
      (~1-2 GB per process — README §14 issue #9); every experiment here needs
      only the first ``count``, so this verifies the digest and then reads
      lazily, taking what it needs and stopping.

    DOMAIN LIMIT — a real constraint, deliberately not papered over. The frozen
    corpus carries exactly ``len(per_domain_counts)`` domains (4: balanced
    whole-organization buckets, README §4). Exp. 3 sweeps ``d = 2..10``. For
    ``d <= 4`` each record keeps its real ``dom``, which is the point of using
    the corpus at all. For ``d > 4`` the corpus simply has no such partition,
    and inventing one by re-bucketing ``rid`` would silently replace real
    institutional boundaries with a synthetic split *while still reporting
    ``corpus_type: synthea``* — the exact class of misrepresentation README §13
    forbids. So it raises instead, naming the decision.
    """

    corpus_dir: Optional[Path] = None
    manifest_path: Optional[Path] = None

    corpus_type: str = field(init=False, default="synthea")
    corpus_sha256: Optional[str] = field(init=False, default=None)
    keywords_per_record: int = field(init=False, default=6)
    domains: Tuple[str, ...] = field(init=False, default=extract_mod.DEFAULT_DOMAIN_NAMES)
    vocabulary: int = field(init=False, default=0)

    _corpus_path: Path = field(init=False, repr=False)
    _available_domains: int = field(init=False, repr=False, default=0)

    def __post_init__(self) -> None:
        from Common.crypto.config import REPO_ROOT
        from Dataset.corpus import verify_corpus
        from Common.crypto.config import load_dataset_config

        config = load_dataset_config()
        output_cfg = config["output"]
        corpus_dir = Path(self.corpus_dir) if self.corpus_dir else (
            REPO_ROOT / "Dataset" / "derived"
        )
        self._corpus_path = corpus_dir / output_cfg["corpus_filename"]
        manifest_path = Path(self.manifest_path) if self.manifest_path else (
            REPO_ROOT / "Dataset" / output_cfg["manifest_filename"]
        )

        # Verifies the corpus against its manifest (SHA-256) and refuses on
        # mismatch. The manifest-vs-dataset.yaml freeze pin is a separate,
        # stricter gate; it is applied by provenance.build_metadata(), which is
        # what decides reportability, so a development run can proceed here
        # while a pin mismatch still correctly marks the run non-reportable.
        manifest = verify_corpus(
            self._corpus_path, manifest_path, require_reportable=False
        )
        self.corpus_type = str(manifest.get("corpus_type", "unknown"))
        self.corpus_sha256 = manifest.get("corpus_sha256")
        self.vocabulary = int(manifest.get("keyword_universe_size", 0))

        # Exp. 2 sizes its record count as `index_size // keywords_per_record`,
        # so this must be the corpus's real mean |W_i|, not a nominal constant.
        kpr = manifest.get("keywords_per_record") or {}
        mean = kpr.get("mean")
        self.keywords_per_record = max(1, int(round(float(mean)))) if mean else 6

        per_domain = manifest.get("per_domain_counts") or {}
        self._available_domains = len(per_domain)
        if self._available_domains:
            self.domains = tuple(
                extract_mod.DEFAULT_DOMAIN_NAMES[i]
                if i < len(extract_mod.DEFAULT_DOMAIN_NAMES) else f"dom{i}"
                for i in range(self._available_domains)
            )

    def records(self, count: int, *, domains: Optional[int] = None):
        from Dataset.corpus import read_corpus

        domain_count = self._available_domains if domains is None else domains
        domain_count = max(int(domain_count), 1)
        if domain_count > self._available_domains:
            raise ValueError(
                f"the frozen corpus has {self._available_domains} domains "
                f"(per_domain_counts in the manifest), but d={domain_count} was "
                f"requested. Splitting it further would replace real "
                f"institutional boundaries with a synthetic partition while "
                f"still reporting corpus_type={self.corpus_type!r}, which "
                f"README §13 forbids. This needs a recorded benchmark decision: "
                f"either cap Exp. 3 at d<={self._available_domains}, or "
                f"regenerate the corpus with more domains and re-freeze "
                f"(results-affecting), or state in §V that d>"
                f"{self._available_domains} uses a sub-partitioned corpus."
            )

        assignment = extract_mod.BucketedPolicyAssignment(
            policies_per_domain=2, domains=domain_count
        )
        names = self.domains[:domain_count]

        # Emitted ROUND-ROBIN across domains, not in raw corpus order.
        #
        # Each record keeps its own real `dom` — nothing is remapped — but the
        # ORDER is balanced. Callers that need every domain represented in a
        # small draw depend on this: Exp3CrossDomain.prepare asks for only
        # `d * 4` records and then does `next(r for r in records if
        # r.domain == domain)` for each domain. The synthetic source made that
        # safe implicitly (`dom = rid % domain_count` is round-robin by
        # construction); the corpus's natural order is grouped, so the first 8
        # records can all be domain 0 and that `next()` died with a bare
        # StopIteration — which took out every Exp. 3 point, d=2 included.
        #
        # Record order is not a measured property of any experiment here, so
        # balancing it changes no reported number; it only makes a small draw
        # representative, which is what the callers already assumed.
        from collections import deque

        buckets: Dict[int, Any] = {d: deque() for d in range(domain_count)}
        emitted = 0
        stream = read_corpus(self._corpus_path)
        exhausted = False
        while emitted < count:
            # Top up until every domain can supply one, or the corpus runs out.
            while not exhausted and not all(buckets[d] for d in range(domain_count)):
                try:
                    record = next(stream)
                except StopIteration:
                    exhausted = True
                    break
                if record.dom < domain_count:
                    buckets[record.dom].append(record)
            progressed = False
            for d in range(domain_count):
                if emitted >= count:
                    break
                if buckets[d]:
                    yield extract_mod.extract(
                        buckets[d].popleft(), assignment=assignment,
                        domain_names=names,
                    )
                    emitted += 1
                    progressed = True
            if not progressed:
                break

        if emitted < count:
            raise ValueError(
                f"corpus exhausted after {emitted} records but {count} were "
                f"requested at d={domain_count}; the sweep point does not fit "
                f"this corpus"
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

    Prefers the real Type-III backend (``charm_type3``, added 2026-08-28) and
    falls back to the injected stand-in only where it is unavailable — on a
    machine without charm, i.e. any non-Linux dev host. The fallback still
    marks the context ``reportable = False`` and provenance still records why,
    so a stand-in run can never be mistaken for a real one; the difference is
    that the real backend is now the default rather than the only option being
    a stub.
    """
    faithful_ops: Optional[Any] = None
    if group_provider is None:
        try:
            from Common.crypto import pairing as _pairing_mod

            _backend = _pairing_mod.get_backend("ma_lb_pq_vdse", reportable=True)
            group_provider = _faithful_group_provider
            faithful_ops = _BackedGroupOperations(_backend)
        except Exception:  # noqa: BLE001 - absence is expected off the host
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
    operations = faithful_ops if faithful_ops is not None else _HarnessGroupOperations()
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


def _faithful_group_provider(pairing_params):
    """A real Type-III bilinear group from ``Common.crypto.pairing``.

    Replaces ``_unfaithful_group_provider`` when ``charm_type3`` is available.
    ``faithful=True`` is what lets ``group_faithful`` reach
    ``provenance.reportability()`` as satisfied — the proposed scheme could not
    produce a quotable number at all while the stand-in below was the only
    option (``crypto.yaml: backend_implemented: false``).
    """
    from Common.crypto import pairing as pairing_mod

    backend = pairing_mod.get_backend("ma_lb_pq_vdse", reportable=True)
    g1, g2 = backend.random_g1(), backend.random_g2()
    return init_mod.GroupDescription(
        curve=backend.curve,
        backend=backend.name,
        g1=backend.serialize(g1),
        g2=backend.serialize(g2),
        e_g1_g2=backend.serialize(backend.pair(g1, g2)),
        faithful=True,
    )


class _BackedGroupOperations:
    """Real group operations over the configured Type-III backend.

    Elements cross this interface as serialised bytes (that is the shape the
    scheme's phases already use), so each operation deserialises, works in the
    group, and re-serialises. That costs a little per call but keeps the
    measured cost *real* rather than the hash stand-in's constant-time SHA-256,
    which understated every group operation in the scheme.
    """

    def __init__(self, backend) -> None:
        self._b = backend
        self._group = backend.group

    def _g1(self, raw: bytes):
        return self._group.deserialize(raw)

    def random_exponent(self) -> bytes:
        return self._b.serialize(self._b.random_zr())

    def exponentiate_gt(self, base: bytes, exponent: bytes) -> bytes:
        return self._b.serialize(self._g1(base) ** self._g1(exponent))

    def exponentiate_g1(self, base: bytes, exponent: bytes) -> bytes:
        return self._b.serialize(self._g1(base) ** self._g1(exponent))

    def multiply_g1(self, left: bytes, right: bytes) -> bytes:
        return self._b.serialize(self._g1(left) * self._g1(right))

    def hash_to_g1(self, data: bytes) -> bytes:
        return self._b.serialize(self._b.hash_to_g1(data))


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
#: Seed for Exp. 2's query draw. Fixed so a sweep is reproducible, and separate
#: from the corpus seed so re-drawing queries cannot change which records exist.
EXP2_QUERY_SEED = 20260903

#: A keyword must appear in at least this many records to be worth querying, and
#: in at most this share of them. Both bounds are taken verbatim from
#: ``yue_ge/src/workload.py::select_keywords``, which in turn mirrors
#: ``guo_vdsse/src/exp2_search.py`` -- the point is that all three schemes draw
#: queries at comparable selectivity, so the numbers compare.
QUERY_MIN_FREQUENCY = 5
QUERY_MAX_SHARE = 0.5


def select_query_keywords(
    freq: "Counter[str]",
    rng: DeterministicRNG,
    count: int,
    *,
    total_records: Optional[int] = None,
) -> List[str]:
    """Draw ``count`` query keywords at the selectivity the baselines use.

    Skip keywords too rare to produce a measurable traversal, and ones so common
    they swamp the scan and hide the scaling. Falls back to the whole vocabulary
    when the bounds leave too few -- a small point must still produce a query
    rather than failing the sweep.
    """
    ceiling = total_records * QUERY_MAX_SHARE if total_records else float("inf")
    eligible = [
        kw for kw, n in freq.items() if n >= QUERY_MIN_FREQUENCY and n <= ceiling
    ]
    if len(eligible) < count:
        eligible = sorted(freq)
    if not eligible:
        raise ValueError("no keyword in the built index is queryable")
    eligible.sort()
    return list(rng.choice(eligible, size=min(count, len(eligible)), replace=False))


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
        # WAS: keywords[0] of the FIRST record in the domain, reused for every
        # run. That made this experiment measure the repeatability of one
        # arbitrary query while guo and yue_ge each draw a NEW keyword per run
        # (yue_ge/exp2_search_latency/runner.py:130,158). The two are not the
        # same estimand: Peony++ is output-sensitive, so its spread across a
        # keyword draw is the measurement, and our flat curve was an artefact of
        # never varying the query rather than evidence of stable latency.
        #
        # Now: draw warmups+repetitions keywords at the baselines' selectivity
        # and advance one per call, so all three schemes answer the same
        # question. n_eff varies run to run as a result -- that is the point.
        frequency: "Counter[str]" = Counter()
        in_domain = 0
        for entry in deployment.records:
            if entry["record"].domain == domain:
                in_domain += 1
                frequency.update(entry["record"].keywords)
        measurement = self.config.measurement
        draws = measurement.warmup_runs + measurement.repetitions
        rng = DeterministicRNG(EXP2_QUERY_SEED).spawn(f"exp2/N={value}")
        keywords = select_query_keywords(
            frequency, rng, draws, total_records=in_domain
        )
        return dict(
            deployment=deployment, profile=profile, authority_ids=authority_ids,
            attributes=attributes, resolver=resolver,
            keywords=keywords, cursor=[0],
        )

    def measure(self, prepared: Any) -> Sample:
        d = prepared["deployment"]
        # One keyword per call, cycling. Warm-ups consume the first entries, as
        # they do for yue_ge, so the retained runs see the same draw the
        # baselines' retained runs see.
        pool = prepared["keywords"]
        cursor = prepared["cursor"]
        keyword = pool[cursor[0] % len(pool)]
        cursor[0] += 1
        started = time.perf_counter_ns()
        token = token_mod.generate_search_token(
            d.scheme, prepared["profile"], [keyword]
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
#: Exp. 6 ablation — one variant per half of the IAS claim.
#:
#:   ``ias``          the published rule: selective delivery, and only the
#:                    affected authority evolves. The default.
#:   ``broadcast``    tests SELECTIVE. IAS_i goes to every FSN rather than only
#:                    those holding the affected shard — the alternative
#:                    ``:1111`` names and rejects.
#:   ``full_rebuild`` tests INCREMENTAL. Every authority recomputes its
#:                    commitment and the AIM republishes it, instead of
#:                    ``:1045``'s "only the affected authority updates its
#:                    commitment, while all other authorities retain their
#:                    existing authorization states".
#:
#: These are ABLATIONS of the proposed scheme, not baselines from other papers,
#: exactly as Exp. 7-8's four scheduler variants are. Neither is a strawman built
#: on a known-slow implementation: ``full_rebuild`` calls the SAME
#: ``Authority.commitment()`` the proposed path calls and differs only in how many
#: authorities it calls it for. The superseded O(delta^2) ``RevocationList`` is
#: deliberately NOT used here — measuring against an old bug would overstate the
#: advantage.
VARIANT_IAS = "ias"
VARIANT_BROADCAST = "broadcast"
VARIANT_FULL_REBUILD = "full_rebuild"
EXP6_VARIANTS: Tuple[str, ...] = (
    VARIANT_IAS, VARIANT_BROADCAST, VARIANT_FULL_REBUILD
)


def _broadcast_selector(message, nodes):
    """Every FSN, not only those serving the affected domain."""
    return tuple(nodes)


@dataclass
class Exp6AuthorizationSync:
    """"IAS propagation: authority commitment recomputation → Merkle path update
    → IAS message → selective FSN propagation, until all affected FSNs report the
    new VID. Report FSNs touched."

    ``synchronize`` verifies that postcondition itself, so a run that returns has
    reached it.

    **Boundary.** Phase VII Step 7 (anchoring ``BC_i'``) is OUTSIDE this
    measurement: no ledger is passed to ``synchronize``, so nothing is anchored on
    the timed path. That matches README §5, whose Exp. 6 boundary ends at "until
    all affected FSNs report the new ``VID``", and ``tab:cost``'s authorization-
    synchronization row ``O(delta)T_H + O(log d)T_MT``, which carries no chain
    term. Anchoring is also identical across all three variants, so including it
    could not change which one wins — only add a constant. §V must state the
    exclusion and report the anchor cost separately, the way README §5 already
    handles ML-KEM encapsulation for Exp. 1.

    **What ``fsns_touched`` can and cannot show.** ``assign_domains_to_fsns`` gives
    each domain to exactly ONE node, and an ``IASMessage`` carries exactly one
    domain, so selective delivery touches exactly one node for ANY ``d`` and ``m``.
    Under ``ias`` the metric is therefore a constant 1 BY CONSTRUCTION, and is
    evidence of nothing unless read against ``broadcast``'s ``m``. Every run before
    2026-09-03 reported it alone, which is why README §5's "selective propagation
    is the claim" had no measurement behind it.
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    name: str = "exp6_authorization_sync"
    number: int = 6
    variable: str = "authorization_updates"
    values: Tuple[Any, ...] = ()
    variant: str = VARIANT_IAS
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("ias_message_size", KB),
        MetricSpec("fsns_touched", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp6").values)
        if self.variant not in EXP6_VARIANTS:
            raise ValueError(
                f"unknown Exp. 6 variant {self.variant!r}; "
                f"valid: {', '.join(EXP6_VARIANTS)}"
            )

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
        others = tuple(a for dom, a in d.authorities.items() if dom != domain)
        selector = (
            _broadcast_selector if self.variant == VARIANT_BROADCAST else None
        )
        rebuild = self.variant == VARIANT_FULL_REBUILD
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
                select_nodes=selector,
            )
            total_bytes += receipt.message.size_kb
            touched += receipt.touched_count
            if rebuild:
                # Global authorization reconstruction: every OTHER authority
                # recomputes C_k^auth and the AIM republishes it to every node.
                # Authority.commitment() is uncached by design, so this is the
                # real recomputation rather than a re-read of a stored value.
                for other in others:
                    meta = other.meta()
                    d.aim.register_meta(other.authority_id, meta)
                    for node in d.nodes:
                        node.apply_meta(other.authority_id, meta)
                        touched += 1
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
    max_queue_depth: int


def _default_ramp_seconds() -> float:
    """README §7's ramp, from global.yaml with a hard fallback.

    Resolved once at import rather than per call so there is a single name to
    override -- the test suite zeroes RAMP_SECONDS in conftest, and reading the
    config inside _ramp() would silently defeat that.
    """
    try:
        configured = scheme_config.load().experiment("exp8").ramp_seconds
    except Exception:  # noqa: BLE001 - a missing key must not break collection
        configured = None
    return 30.0 if configured is None else float(configured)


#: README §7: "Cold vs warm. Defaults: Exp. 1-6 warm, Exp. 7-8 warm after a 30 s
#: ramp." Applied once per sweep point, inside prepare(), which run_point()
#: excludes from every timing.
RAMP_SECONDS = _default_ramp_seconds()


@dataclass
class SchedulerAblation:
    """The shared engine for Exp. 7 and Exp. 8.

    README §5: "Exp. 7 and Exp. 8 report different metrics over **the same
    recorded arrival trace**, replayed once per experiment per variant." The
    trace is recorded once in prepare() and both experiments record the same
    one; they do NOT share a replay. Each runs its own, so the two differ by
    timing noise and Exp. 8's sigma cannot be paired run-for-run with a
    specific Exp. 7 throughput. The per-point cross-variant comparison the
    figures show is unaffected.

    **Not reportable, for two reasons beyond the λ sweep.** README §1 requires each
    FSN to be an independent process; this replays in one interpreter, so a
    concurrency figure would not measure the stated topology. Both reasons are
    recorded in ``run_meta.json``.
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    variant: str = aass_mod.VARIANT_AASS

    #: Set False only to compare against the legacy single-interpreter path.
    #: README §1 requires independent FSN processes and
    #: provenance.reportability() blocks a concurrency result without them.
    independent_processes: bool = True

    def replay(self, deployment: Deployment, requests, concurrency: int) -> _WorkloadOutcome:
        if self.independent_processes:
            try:
                return self._replay_multiprocess(deployment, requests, concurrency)
            except RuntimeError as exc:
                # Only fork-unavailability (macOS/Windows dev hosts) falls back.
                # The run is then correctly NOT reportable, and says why rather
                # than quietly measuring a different topology.
                print(f"  FSN pool unavailable ({exc}); falling back to the "
                      f"single-interpreter path — NOT reportable", flush=True)
        return self._replay_single_interpreter(deployment, requests, concurrency)

    def _replay_multiprocess(
        self, deployment: Deployment, requests, concurrency: int
    ) -> _WorkloadOutcome:
        """Each FSN in its own OS process, as README §1 requires.

        The scheduler still chooses the node in the parent — that decision IS
        the thing Exp. 7-8 ablate. What changes is that the chosen node then
        executes in its own process, so nodes genuinely contend for cores and
        per-node utilization can actually differ.
        """
        scheduler = aass_mod.Scheduler(
            self.variant, config=self.config, reportable=False
        )
        node_ids = [node.node_id for node in deployment.nodes]
        by_id = {node.node_id: node for node in deployment.nodes}
        rejected = 0
        forwards = 0
        dispatched = 0
        latency_starts: Dict[int, int] = {}
        collected: List[fsn_pool.NodeOutcome] = []
        peak_depth = 0

        with fsn_pool.FogSearchNodePool(deployment.nodes) as pool:
            self._worker_pids = pool.worker_pids
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
                latency_starts[dispatched] = time.perf_counter_ns()
                # Enqueue BEFORE dispatch, so the depth the next select() reads
                # already includes this request. The parent's node objects carry
                # the queue the scheduler reasons about; the worker holds the
                # index. Both are the same node, split across the fork.
                depth = selection.node.enqueue(str(dispatched))
                if depth > peak_depth:
                    peak_depth = depth
                pool.dispatch(
                    dispatched, selection.node.node_id,
                    token.tokens, decision.authorized_shards,
                )
                dispatched += 1
                # Retire what has finished, so depth falls as well as rises.
                for outcome in pool.drain():
                    by_id[outcome.node_id].dequeue()
                    collected.append(outcome)
                # A forward per authorized domain the chosen node does NOT hold:
                # those shards are served from another node, which is the
                # cross-node communication §V claims AASS minimizes. The former
                # test -- serves_domain(request.domains[0]) -- compared against
                # the alphabetically FIRST authorized domain, so with every
                # request authorized for all four domains it only ever asked
                # "did you pick the dom0 node?".
                forwards += sum(
                    1 for domain in request.domains
                    if not selection.node.serves_domain(domain)
                )
            tail = pool.collect(dispatched - len(collected))
            # Retire the tail too. Every enqueue must have its dequeue or the
            # depth carries over into the next replay, and prepare()'s ramp plus
            # 30 measured runs would leave `least_loaded` and `C_j^queue`
            # reading a queue that only ever grew.
            for outcome in tail:
                by_id[outcome.node_id].dequeue()
            outcomes = collected + tail
            wall = time.perf_counter() - started

        latencies = [o.service_ns / 1e6 for o in outcomes if o.ok]
        rejected += sum(1 for o in outcomes if not o.ok)

        window_ns = max(1, int(wall * 1e9))
        util_map = fsn_pool.utilization_by_node(outcomes, node_ids, window_ns)
        utilizations = list(util_map.values())
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
            max_queue_depth=peak_depth,
        )

    def _replay_single_interpreter(
        self, deployment: Deployment, requests, concurrency: int
    ) -> _WorkloadOutcome:
        scheduler = aass_mod.Scheduler(
            self.variant, config=self.config, reportable=False
        )
        latencies: List[float] = []
        rejected = 0
        forwards = 0
        peak_depth = 0
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
            depth = selection.node.enqueue(str(len(latencies)))
            if depth > peak_depth:
                peak_depth = depth
            try:
                search_mod.execute_search(
                    selection.node, token.tokens, decision.authorized_shards
                )
            except search_mod.SearchRejected:
                selection.node.dequeue()
                rejected += 1
                continue
            selection.node.dequeue()
            latencies.append((time.perf_counter_ns() - began) / 1e6)
            # Same forward count as the multiprocess path -- see there for why
            # the previous single serves_domain(domains[0]) test was wrong.
            forwards += sum(
                1 for domain in request.domains
                if not selection.node.serves_domain(domain)
            )
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
            max_queue_depth=peak_depth,
        )

    def _population(self, deployment: Deployment) -> List[Any]:
        """Data Users spanning 1..d authorized domains, no domain favoured.

        A single user authorized across every domain — which is what this was —
        makes two of AASS's five terms constant by construction: ``C_j^auth``
        (``|P_Q|``) is the same for every request, and ``cross_node_forwards`` is
        pinned at ``d-1`` per request for EVERY variant, because each FSN serves
        one domain and a request needing all four must forward to three of them
        whichever node is chosen. §V's claim that AASS "minimizes unnecessary
        cross-node communication" is untestable on such a workload: there is no
        unnecessary communication to remove.

        **Benchmark choice, not published.** Neither §V nor README fixes how many
        domains one query spans; §V fixes only d=4. Uniform over subset sizes
        1..d with the starting domain rotated is the neutral choice — it spans
        the range from single-domain queries (where authorization locality
        decides everything) to all-domain queries (where it cannot matter), and
        rotating the offset makes every domain appear equally often, so no FSN is
        structurally favoured.
        """
        domains = tuple(deployment.domains)
        # Computed ONCE. _enrol() rescans deployment.records per domain per user,
        # which at N=10^5 over 16 users would be ~10^7 record comparisons.
        policies_by_domain: Dict[str, Tuple[str, ...]] = {}
        for domain in domains:
            policies_by_domain[domain] = tuple(sorted({
                r["record"].policy_id
                for r in deployment.records
                if r["record"].domain == domain
            }))

        population = []
        for size in range(1, len(domains) + 1):
            for offset in range(len(domains)):
                subset = sorted(
                    domains[(offset + i) % len(domains)] for i in range(size)
                )
                uid = f"DU-d{size}-o{offset}"
                authority_ids = [
                    deployment.authorities[d].authority_id for d in subset
                ]
                attributes = sorted(
                    attr for d in subset
                    for attr in deployment.authorities[d].attributes[:3]
                )
                profile = profile_mod.build_profile_from_aim(
                    deployment.aim, uid=uid,
                    authority_ids=authority_ids, attributes=attributes,
                )
                resolver = authz_mod.MappingPolicyResolver({
                    (uid, d): policies_by_domain[d] for d in subset
                })
                population.append(
                    (profile, authority_ids, attributes, resolver, tuple(subset))
                )
        return population

    def _ramp(self, deployment: Deployment, requests, concurrency: int) -> None:
        """README §7: "Exp. 7-8 warm after a 30 s ramp."

        Here rather than in ``measure`` because ``run_point`` calls ``prepare``
        once per point and excludes it from every timing — which is what "warm
        AFTER a ramp" means: ramp once, then take the 10 runs on a warm system.
        Putting it in ``measure`` would ramp 10 times per point and cost ~1.7 h
        across the campaign to measure the same steady state.
        """
        if not requests:
            return
        if RAMP_SECONDS <= 0:
            return
        deadline = time.perf_counter() + RAMP_SECONDS
        while time.perf_counter() < deadline:
            self.replay(deployment, requests, concurrency)

    def prepare(self, value: Any) -> Any:
        """Build the deployment, RECORD the arrival trace, then ramp.

        All variants and both experiments see the same workload — so the
        request list is materialised here and replayed, not regenerated per
        variant. Identical in CONTENT, not in bytes: every SearchToken carries
        a fresh random nonce, which must vary. Locked by
        test_exp7_and_exp8_record_the_same_arrival_trace, which digests the
        trace excluding the nonce, and by
        test_search_token_nonce_is_fresh_per_token, which pins that the nonce
        itself is never reproducible.
        """
        concurrency = int(value)
        # README §6 fixes index_size at 10^5 for every experiment that does not
        # sweep it, and Exp. 7-8 sweep concurrency. This built `records=32` —
        # 8 entries per shard, 3,125x under the default. Measured consequence:
        # execute_search is linear in shard size while select() is flat, so at
        # 32 records the scheduler cost 23.8us against a 9.0us search and no
        # variant could saturate a node, because the work unit was cheaper than
        # the IPC round-trip delivering it. At 8,000 records the same search is
        # 297us. Sized as Exp. 2 sizes it, so "N" means the same thing in both.
        record_count = max(
            1, int(self.config.defaults.index_size) // self.source.keywords_per_record
        )
        deployment = build_deployment(
            config=self.config, source=self.source, records=record_count
        )
        population = self._population(deployment)
        by_domain: Dict[str, List[Any]] = {d: [] for d in deployment.domains}
        for entry in deployment.records:
            by_domain[entry["record"].domain].append(entry)

        requests = []
        for index in range(concurrency):
            profile, authority_ids, attributes, resolver, subset = (
                population[index % len(population)]
            )
            # Draw from a domain this user actually holds, or the AIM rejects
            # the request and the trace silently shrinks.
            domain = subset[index % len(subset)]
            pool_for_domain = by_domain[domain]
            if not pool_for_domain:
                continue
            record = pool_for_domain[index % len(pool_for_domain)]
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
        requests = tuple(requests)
        self._ramp(deployment, requests, concurrency)
        return dict(
            deployment=deployment, requests=requests, concurrency=concurrency
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
        # `cross_node_forwards` was here and is deliberately NOT reported.
        # At the §V default d = m = 4, assign_domains_to_fsns gives each FSN one
        # domain and _candidates() already restricts the choice to nodes serving
        # an authorized domain, so the chosen node serves exactly one of the k
        # authorized domains WHICHEVER node it is: the count is k-1 under every
        # variant. Measured over 400 requests it was 600 for all four arms.
        # A secondary that cannot vary is not evidence, and putting it in an
        # ablation table invites the reviewer to check it and find it flat.
        # `test_cross_node_forwards_is_scheduler_invariant_at_one_domain_per_node`
        # fails if the topology ever makes it meaningful again.
        #
        # Peak queue depth replaces it because it measures the thing §V actually
        # claims for Exp. 8 -- "prevents node congestion" -- and it is only
        # measurable at all now that the enqueue/dequeue loop is wired.
        MetricSpec("max_queue_depth", COUNT),
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
                "max_queue_depth": float(outcome.max_queue_depth),
            },
        )


# ===========================================================================
# Exp. 9 — Verification Granularity under Tampering
# ===========================================================================
@dataclass
class Exp9VerificationGranularity:
    """What verification BUYS, where Exp. 4 measures what it COSTS.

    The result-set size is PINNED (``global.yaml``: ``returned_results: 20000``)
    and the number of tampered records is swept. The question is not how fast a
    scheme verifies but what it can do once verification fails.

    **Why this is a fair comparison and not a strawman.** Guo's Alg. 4 checks a
    single XOR-accumulated tag computed over the COMPLETE result set
    (``guo_vdsse/src/scheme.py:566-590``), and Peony++'s prooflist entry commits
    to every file added at that level in that batch (``yue_ge`` §VI-A). In both,
    a subset does not balance -- ``yue_ge``'s own runner docstring says
    "verifying a truncated subset is *supposed* to fail -- the XOR would not
    cancel". So neither construction can bisect its way to the bad record
    without the server issuing fresh proofs per sub-batch, which neither paper
    defines. The all-or-nothing outcome is a property of the published designs,
    not of this implementation, and §V must say so in those terms.

    **The tamper.** One byte of an index entry's ``T_j``, leaving ``CID_i``
    intact so the bundle stays well-formed. ``entry_leaf`` covers every field, so
    Phase VIII Step 1 rejects it as "the proof's leaf is not the entry this
    bundle names" -- a detected tamper, not a malformed bundle. Those are
    different code paths (``VerificationError`` vs ``accepted = False``) and
    timing the wrong one would measure parse failure.

    **Not swept at t = 0.** The figure is log-log and the untampered case is
    Exp. 4. ``test_exp9_granularity.py`` pins the t=0 behaviour instead, which is
    where a false-positive rejection would show up.
    """

    config: scheme_config.Configuration
    source: SyntheticRecordSource
    name: str = "exp9_verification_granularity"
    number: int = 9
    variable: str = "tampered_records"
    values: Tuple[Any, ...] = ()
    #: Not a timing. The primary is how many records the client must throw away,
    #: which is the whole point of the comparison; latency rides along as a
    #: secondary so the price of the granularity stays visible in the same table.
    primary: MetricSpec = MetricSpec("records_discarded", COUNT)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("usable_recovered", COUNT),
        MetricSpec("tampered_localised", COUNT),
        MetricSpec("latency", MS, is_timing=True),
    )
    returned_results: int = 0

    def __post_init__(self) -> None:
        spec = self.config.experiment("exp9")
        if not self.values:
            self.values = tuple(spec.values)
        if not self.returned_results:
            held = spec.held_constant or {}
            if "returned_results" not in held:
                raise scheme_config.ConfigError(
                    "exp9 must pin returned_results in global.yaml's "
                    "held_constant block; sweeping both would make the figure "
                    "unreadable"
                )
            self.returned_results = int(held["returned_results"])

    def _tampered(
        self, bundle: proof_mod.VerificationBundle
    ) -> proof_mod.VerificationBundle:
        """One flipped bit in ``T_j``. ``CID_i`` is untouched on purpose."""
        token = bytearray(bundle.entry.token)
        token[0] ^= 0x01
        entry = dataclasses.replace(bundle.entry, token=bytes(token))
        return dataclasses.replace(bundle, entry=entry)

    def prepare(self, value: Any) -> Any:
        tampered = int(value)
        wanted = self.returned_results
        if tampered > wanted:
            raise ValueError(
                f"cannot tamper {tampered} of {wanted} returned records"
            )
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
        if len(bundles) < wanted:
            raise RuntimeError(
                f"built {len(bundles)} bundles but exp9 pins {wanted}; the "
                f"deployment is too small"
            )
        bundles = bundles[:wanted]

        # Evenly spaced rather than clustered or random: a run whose tampered
        # records all land in one region would measure locality, not
        # granularity, and a seeded shuffle would put a different set under each
        # sweep point.
        marked = sorted(
            {(i * wanted) // tampered for i in range(tampered)}
        ) if tampered else []
        for index in marked:
            bundles[index] = self._tampered(bundles[index])

        return dict(
            deployment=deployment,
            bundles=tuple(bundles),
            auth_root=deployment.owner_profile.auth_root,
            tampered=len(marked),
        )

    def measure(self, prepared: Any) -> Sample:
        d = prepared["deployment"]
        checker = vledger_mod.chain_checker(d.ledger, check_chain_integrity=False)
        started = time.perf_counter_ns()
        batch = proof_mod.verify_response(
            prepared["bundles"],
            auth_root=prepared["auth_root"],
            require_version_match=False,
            chain_check=checker,
        )
        elapsed = time.perf_counter_ns() - started

        discarded = len(batch.rejected)
        expected = prepared["tampered"]
        # A mismatch either way is a real failure, not a metric: fewer means a
        # tamper went undetected (soundness), more means an intact record was
        # thrown away (completeness). Both invalidate the figure, so neither is
        # allowed to be silently averaged into it.
        if discarded != expected:
            raise RuntimeError(
                f"{discarded} records rejected but {expected} were tampered; "
                f"verification is neither sound nor complete under this build"
            )
        return Sample(
            primary=float(discarded),
            secondaries={
                "usable_recovered": float(batch.accepted_count),
                "tampered_localised": float(len(batch.rejected)),
                "latency": elapsed / 1e6,
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
    9: Exp9VerificationGranularity,
}


def build_experiment(
    number: int,
    config: scheme_config.Configuration,
    source: Optional[SyntheticRecordSource] = None,
    variant: Optional[str] = None,
):
    """Instantiate one experiment by its README §5 number.

    ``variant`` selects the scheduler for Exp. 7-8, which README §5 defines as a
    four-way ablation (no_lb / round_robin / least_loaded / aass). It was
    reachable only by editing the dataclass default, so every campaign so far
    measured `aass` alone and the ablation the paper claims had never been run.

    It is ignored for Exp. 1-6, and deliberately so for Exp. 6: that experiment
    measures IAS propagation -- commitment recomputation, Merkle path update,
    selective FSN delivery -- and the scheduler decides which FSN serves a
    QUERY. It plays no part in propagating an authorization change, so running
    four variants there would measure the same thing four times.
    """
    if number not in EXPERIMENTS:
        raise KeyError(
            f"no experiment {number}; README §5 defines 1-8, and Exp. 9 is "
            f"the tamper-granularity companion to Exp. 4"
        )
    kwargs = dict(config=config, source=source or SyntheticRecordSource())
    if variant and "variant" in {f.name for f in dataclasses.fields(EXPERIMENTS[number])}:
        kwargs["variant"] = variant
    return EXPERIMENTS[number](**kwargs)


__all__ = [
    "SyntheticRecordSource",
    "CorpusRecordSource",
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
    "Exp9VerificationGranularity",
]
