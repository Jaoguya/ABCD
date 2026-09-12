"""D6-D9 — the experiments the manuscript's construction calls for.

Divergences D7-D9 are experiment-design divergences and D6 is a
cost-table one. They cannot be measured against the implemented scheme, because
each is a consequence of the construction in ``src/psa/`` (D1-D5). This module
supplies them.

======  =========================================================  ============
D       What it measures                                           Class
======  =========================================================  ============
D7      Token generation over BOTH ``q`` and ``|P_U|``, where the   ``PsaExp1``
        manuscript's Exp. 1 has ``|T_Q| = q·|P_U|``
D9      Tokens a cross-domain query must issue as ``d`` grows.      ``PsaExp3``
        Option D issues 1; this construction cannot.
D1      Re-tokenization cost of an authority-state change -- the    ``PsaExp5``
        work Option D does not do at all
D8      DIAS under a swept AFFECTED-POLICY RATIO (10%-100%),        ``PsaExp6``
        which is the manuscript's Exp. 6 x-axis
======  =========================================================  ============

SCOPE, STATED PLAINLY
---------------------
These measure the **construction**, not end-to-end search. There is no FSN pool,
no bitmap filter and no ledger on any timed path here, because
``index/dsi.py``, ``fsn/`` and ``verify/`` are all written against
``types.IndexEntry`` and its scalar ``vid``; running Exp. 2's full online path
under this construction needs those forked too, which is a larger change than
D1-D9 describe.

So a number from this module answers "what does the manuscript's token cost?"
and never "what is the search latency of the manuscript's scheme?". The metrics
are named accordingly, and ``PsaExp1``'s latency is directly comparable with
Exp. 1's because Exp. 1's measured path is also token derivation and nothing
else -- that comparison is the point of the module.

REPORTABILITY
-------------
Every run here is built on ``SyntheticRecordSource``-style in-process data with
no corpus behind it, so ``provenance.reportability()`` refuses it for the same
reason it refuses any ``corpus_type: synthetic`` run. These numbers are for
deciding whether to adopt D1-D5, not for quoting in §VI.
"""

from __future__ import annotations

import random
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes, merkle  # noqa: E402
from Common.crypto import config as crypto_config  # noqa: E402
from Common.crypto.rng import DeterministicRNG  # noqa: E402
from Common.timing import gc_quiesced  # noqa: E402

from ..index import dsi as dsi_mod  # noqa: E402
from ..aim import verification as authz_mod  # noqa: E402
from ..user import token as token_mod  # noqa: E402
from ..user import profile as profile_mod  # noqa: E402
from ..scheduler import aass as aass_mod  # noqa: E402
from .. import types as types_mod  # noqa: E402
from . import experiments as experiments_mod  # noqa: E402
from ..chain import outsourcing as out_mod  # noqa: E402
from ..chain import select as chain_select  # noqa: E402
from ..verify import ledger as vledger_mod  # noqa: E402

from .. import config as scheme_config  # noqa: E402
from ..psa import commit as psa_commit  # noqa: E402
from ..psa import governance as psa_gov  # noqa: E402
from ..psa import records as psa_records  # noqa: E402
from ..psa import state as psa_state  # noqa: E402
from ..psa import tokens as psa_tokens  # noqa: E402
from ..psa import verify as psa_verify  # noqa: E402
from .runner import MetricSpec, Sample  # noqa: E402

MS = "ms"
COUNT = "count"
KB = "KB"
BYTES = "B"

#: Domains, matching ``global.yaml: defaults.domains``. One AA each, as
#: ``authority_to_domain: one_to_one`` requires.
DOMAIN_NAMES = ("emergency", "hospital", "laboratory", "research")

#: Seed for Exp. 1's keyword draw. Separate from the corpus seed so re-drawing
#: query keywords cannot change which records exist.
EXP1_KEYWORD_SEED = 20260907

#: Fixed so a sweep is reproducible and independent of the corpus seed.
PSA_SEARCH_KEY = b"psa-harness-search-key-32-bytes!"


def _authorities(domains: Sequence[str]) -> Dict[str, str]:
    return {domain: f"AA{i + 1}" for i, domain in enumerate(domains)}


def _keyed_scheme() -> psa_tokens.PolicyStateTokenScheme:
    """HMAC-SHA256, per ``crypto.yaml → global.prf``. See ``psa/tokens.py``."""
    return psa_tokens.PolicyStateTokenScheme.keyed(PSA_SEARCH_KEY)


@dataclass
class _World:
    """Authorities, policies and their derived states. Built in ``prepare``."""

    domains: Tuple[str, ...]
    authorities: Dict[str, str]
    governance: psa_gov.PolicyGovernance
    versions: Dict[str, int]
    commitments: Dict[str, bytes]
    policies: Tuple[str, ...]

    def pv(self, policy_id: str) -> bytes:
        return psa_state.PolicyVersionState.build(
            self.versions, self.governance.governing(policy_id)
        ).digest()

    def auth_state(self, policy_id: str) -> bytes:
        return psa_state.PolicyAuthorityState.build(
            self.commitments, self.governance.governing(policy_id)
        ).digest()

    def scope(self, policy_id: str) -> psa_tokens.PolicyScopedQuery:
        return psa_tokens.PolicyScopedQuery(
            policy_id=policy_id,
            domain=policy_id.split("/", 1)[0],
            pv=self.pv(policy_id),
        )


def build_world(
    *,
    domains: int = len(DOMAIN_NAMES),
    policies_per_domain: int = 2,
    authorities_per_policy: int = psa_gov.DEFAULT_AUTHORITIES_PER_POLICY,
    overrides: Dict[str, Tuple[str, ...]] | None = None,
) -> _World:
    names = tuple(
        DOMAIN_NAMES[:domains]
        if domains <= len(DOMAIN_NAMES)
        else tuple(f"dom{i}" for i in range(domains))
    )
    authorities = _authorities(names)
    governance = psa_gov.PolicyGovernance.from_domains(
        authorities, authorities_per_policy=min(authorities_per_policy, len(names))
    )
    if overrides:
        governance = governance.with_overrides(overrides)
    roster = sorted(authorities.values())
    return _World(
        domains=names,
        authorities=authorities,
        governance=governance,
        versions={a: 1 for a in roster},
        commitments={a: bytes([i + 1]) * 32 for i, a in enumerate(roster)},
        policies=tuple(
            f"{d}/pol{i}" for d in names for i in range(policies_per_domain)
        ),
    )


# ===========================================================================
# The corpus seam — a PSA deployment built from the SAME records Option D reads
# ===========================================================================
@dataclass
class PsaDeployment:
    """Phases I-V under the policy-state-aware construction, from a real source.

    **Why this exists.** Every PSA experiment before this built its own world
    with :func:`build_world` -- invented policies (``hospital/pol0``), invented
    CIDs (``bafyPSA00000001``) and invented keywords (``kw:00042``). Those
    numbers price the CONSTRUCTION and nothing else, which is why
    ``psa_in_process`` is refused by the reportability gate.

    A number for §VI has to come from the frozen corpus, with its real keyword
    co-occurrence and its real ``|W_i|`` (~32, not the hardcoded 6). This
    builder therefore takes the same ``source`` object ``build_deployment``
    takes, so both constructions index the identical records and a difference
    between their curves is a difference between the constructions.

    Policy ids from ``extract`` are already ``<domain>/polN``, which is exactly
    what :class:`~..psa.governance.PolicyGovernance` parses, so the governing
    set of every corpus policy is derived rather than stipulated.
    """

    config: scheme_config.Configuration
    world: _World
    scheme: psa_tokens.PolicyStateTokenScheme
    nodes: Tuple[Any, ...]
    records: List[Dict[str, Any]] = field(default_factory=list)
    corpus_type: str = "psa_in_process"
    corpus_sha256: Optional[str] = None
    #: Phase I-III, shared with Option D so both constructions authorize the
    #: same way. Without these the PSA track could not run the AIM check §VI
    #: puts inside the measured path.
    aim: Any = None
    authorities: Dict[str, Any] = field(default_factory=dict)
    owner_profile: Any = None
    scaffold: Any = None

    @property
    def entry_count(self) -> int:
        return sum(len(r["entries"]) for r in self.records)


def psa_build_deployment(
    *,
    config: scheme_config.Configuration,
    source,
    records: int,
    domains: Optional[int] = None,
    authorities_per_policy: int = psa_gov.DEFAULT_AUTHORITIES_PER_POLICY,
) -> PsaDeployment:
    """Build a PSA deployment over ``source``'s records — untimed by construction."""
    # §VI's four domains, from the config — see build_deployment's note.
    domain_count = (
        int(config.defaults.domains) if domains is None else domains
    )
    names = tuple(source.domains[:domain_count])
    if len(names) < domain_count:
        names = tuple(f"dom{i}" for i in range(domain_count))

    authorities = _authorities(names)
    roster = sorted(authorities.values())
    world = _World(
        domains=names,
        authorities=authorities,
        governance=psa_gov.PolicyGovernance.from_domains(
            authorities,
            authorities_per_policy=min(authorities_per_policy, len(names)),
        ),
        versions={a: 1 for a in roster},
        commitments={a: bytes([i + 1]) * 32 for i, a in enumerate(roster)},
        policies=(),
    )
    scheme = _keyed_scheme()

    # REAL `FogSearchNode`s, sharing Option D's Phase I-III scaffolding.
    #
    # This built bare `(node_id, served, DynamicSearchIndex)` tuples, which gave
    # the PSA track no AIM, no VAP and no scheduler — so `PsaExp2` and
    # `PsaExp3` timed token derivation plus a posting-list lookup while §VI
    # describes four stages: *"the Authorization Index Manager validates the
    # current VAP and derives … AASS then assigns each required shard"*. Option
    # D's Exp. 2/3 ran all four, so the two tracks were not measuring the same
    # path and could not be compared. Exp. 7-8 ran the AIM check in BOTH tracks,
    # so the PSA track was also inconsistent with itself.
    #
    # `build_deployment` with `records=0` yields exactly the scaffolding —
    # context, ledger, AIM, real `Authority` objects, the FSN set and an owner
    # VAP — with empty indexes for the PSA entries below. Reused rather than
    # reimplemented because the AIM is construction-agnostic: it validates the
    # authorization envelope (nonce, `AuthRoot_U`, version) and never inspects
    # the keyword tokens.
    scaffold = experiments_mod.build_deployment(
        config=config, source=source, records=0, domains=domain_count
    )
    nodes = scaffold.nodes

    deployment = PsaDeployment(
        config=config, world=world, scheme=scheme, nodes=nodes,
        corpus_type=getattr(source, "corpus_type", "psa_in_process"),
        corpus_sha256=getattr(source, "corpus_sha256", None),
        aim=scaffold.aim,
        authorities=scaffold.authorities,
        owner_profile=scaffold.owner_profile,
        scaffold=scaffold,
    )

    seen: set = set()
    for record in source.records(records, domains=domain_count):
        policy = record.policy_id
        seen.add(policy)
        domain = record.domain
        pv = world.pv(policy)
        cid = f"bafyPSA{record.record_id:08d}"
        entries = [
            psa_records.PolicyStateIndexEntry(
                token=scheme.index_token(kw, policy_id=policy, pv=pv, domain=domain),
                cid=cid, policy_id=policy, pv=pv,
            )
            for kw in record.keywords
        ]
        commitment = psa_commit.commit_record(
            record_id=record.record_id, cid=cid, entries=entries,
            policy_id=policy, pv=pv, auth_state=world.auth_state(policy),
        )
        for node in nodes:
            if domain in node.domains:
                node.index.insert_record(entries, domain=domain)
        deployment.records.append(
            dict(cid=cid, policy=policy, domain=domain,
                 keywords=list(record.keywords), entries=entries,
                 commitment=commitment)
        )
    world.policies = tuple(sorted(seen))
    return deployment



#: Records read to discover the corpus's real policies and keyword vocabulary.
#:
#: Exp. 1 times token DERIVATION, so it needs no index -- only the real strings
#: that go into the hash and the real ``AA(PID)`` behind each ``PV_ell``. Reading
#: a sample rather than building a deployment keeps `prepare` cheap while making
#: the measured inputs genuinely corpus-derived: keyword length feeds the HMAC,
#: and the policy set fixes how many distinct ``PV`` digests exist.
#:
#: 4,000 is well above what is needed to see every policy (there are
#: ``policies_per_domain x domains``) and yields a vocabulary in the thousands.
EXP1_SAMPLE_RECORDS = 4000


def psa_enrol(deployment, uid: str, domains: Sequence[str]):
    """A Data User authorized across ``domains``, for the PSA track.

    Mirrors ``experiments._enrol``, but reads the PSA deployment's own record
    dicts (`policy`/`domain` keys) rather than Option D's ``record`` objects.
    The AIM, the authorities and the VAP are the SAME objects Option D uses —
    the authorization layer is construction-agnostic, because
    ``verify_search_request`` validates the envelope (nonce, ``AuthRoot_U``,
    version) and never inspects the keyword tokens.
    """
    authority_ids = [deployment.authorities[d].authority_id for d in domains]
    attributes = sorted(
        attr for d in domains for attr in deployment.authorities[d].attributes[:3]
    )
    profile = profile_mod.build_profile_from_aim(
        deployment.aim, uid=uid, authority_ids=authority_ids,
        attributes=attributes,
    )
    mapping = {
        (uid, domain): tuple(sorted(
            r["policy"] for r in deployment.records if r["domain"] == domain
        ))
        for domain in domains
    }
    return (
        profile, authority_ids, attributes,
        authz_mod.MappingPolicyResolver(mapping),
    )


def psa_search_token(profile, tokens):
    """``ST = (T_Q, AuthRoot_U, VID_U, rho)`` carrying the PSA token set.

    ``generate_search_token`` builds the trapdoor itself with Option D's
    scheme, so the envelope is assembled directly here while the tokens come
    from ``psa_tokens.generate_query_tokens``.
    """
    return types_mod.SearchToken(
        tokens=tuple(tokens),
        auth_root=profile.auth_root,
        vid_u=profile.vid,
        nonce=token_mod.fresh_nonce(),
    )


def corpus_world(
    source,
    *,
    records: int,
    domains: Optional[int] = None,
    policies_per_domain: Optional[int] = None,
    collect: bool = False,
):
    """A ``_World`` whose policies come from the corpus, plus its vocabulary.

    The policy ids ``extract`` produces are already ``<domain>/polN``, which is
    exactly what :class:`~..psa.governance.PolicyGovernance` parses, so every
    governing set -- and therefore every ``PV_ell`` -- is derived from the real
    corpus rather than stipulated.

    ``policies_per_domain`` overrides the campaign default only for callers
    whose measurement is a function of the policy COUNT -- Exp. 6, whose sweep
    is a fraction of the policy population. Everything else leaves it alone.

    ``collect`` additionally returns the drawn records grouped by their real
    policy id, so a caller can follow the manuscript's dependency chain
    ``AA_k -> P_k^aff -> R_k^aff`` on real records instead of synthesising one
    record per policy. Grouping is free here: the draw already happens.

    Returns ``(world, vocabulary)``, or ``(world, vocabulary, by_policy)`` when
    ``collect`` is set. The vocabulary is sorted for determinism.
    """
    domain_count = len(source.domains) if domains is None else domains
    names = tuple(source.domains[:domain_count])
    if len(names) < domain_count:
        names = tuple(f"dom{i}" for i in range(domain_count))

    authorities = _authorities(names)
    roster = sorted(authorities.values())
    seen_policies: set = set()
    vocabulary: set = set()
    by_policy: Dict[str, List[Any]] = {}
    for record in source.records(
        records, domains=domain_count, policies_per_domain=policies_per_domain
    ):
        seen_policies.add(record.policy_id)
        vocabulary.update(record.keywords)
        if collect:
            by_policy.setdefault(record.policy_id, []).append(record)
    if not seen_policies:
        raise RuntimeError(
            f"no policy found in {records} corpus records; PV_ell cannot be derived"
        )

    world = _World(
        domains=names,
        authorities=authorities,
        governance=psa_gov.PolicyGovernance.from_domains(
            authorities,
            authorities_per_policy=min(
                psa_gov.DEFAULT_AUTHORITIES_PER_POLICY, len(names)
            ),
        ),
        versions={a: 1 for a in roster},
        commitments={a: bytes([i + 1]) * 32 for i, a in enumerate(roster)},
        policies=tuple(sorted(seen_policies)),
    )
    if collect:
        return world, tuple(sorted(vocabulary)), by_policy
    return world, tuple(sorted(vocabulary))


# ===========================================================================
# D7 — Exp. 1 over q AND |P_U|
# ===========================================================================
#: ``|P_U| ∈ {1,2,4,8}`` — the manuscript's Exp. 1 authorization scope.
POLICY_SCOPES: Tuple[int, ...] = (1, 2, 4, 8)


#: One arm per ``|P_U|``, so the figure renders §VI's two-variable sweep the way
#: §VI states it: "q is varied as {1,5,10,15,20}, WHILE |P_U| is varied as
#: {1,2,4,8}" -- q on the x-axis, one curve per authorization scope.
#:
#: This replaced a single sweep over an INDEX into the 20 (q, |P_U|) pairs. That
#: index was injective and ordered, but it was not a quantity: the axis read
#: 0..19, the mapping survived only in run_meta.json, and two points a reader
#: would want side by side (q=5 at |P_U|=2 and at |P_U|=8) sat six positions
#: apart. A family of curves is how a 2-D sweep is normally drawn and it needs
#: no legend table to read.
PSA_EXP1_VARIANTS: Tuple[str, ...] = tuple(f"pu{p}" for p in POLICY_SCOPES)


def policy_scope_of(variant: str) -> int:
    """``pu4`` -> 4. The arm name carries its own parameter."""
    if not variant.startswith("pu") or not variant[2:].isdigit():
        raise ValueError(
            f"unknown PSA Exp. 1 variant {variant!r}; "
            f"valid: {', '.join(PSA_EXP1_VARIANTS)}"
        )
    return int(variant[2:])


@dataclass
class PsaExp1TokenGeneration:
    """"the number of generated tokens is ``|T_Q| = q|P_U|``" — manuscript Exp. 1.

    §VI varies ``q ∈ {1,5,10,15,20}`` while varying ``|P_U| ∈ {1,2,4,8}``. The
    runner sweeps one variable, so ``q`` is the sweep and ``|P_U|`` is the ARM:
    one run per scope, written to ``exp1_trapdoor_generation__pu<N>/``, drawn
    as one curve each. ``|T_Q| = q·|P_U|`` is checked on every sample rather
    than assumed, and reported as the ``tokens`` secondary.

    WHY THIS CANNOT LIVE ON THE IMPLEMENTED SCHEME
    ----------------------------------------------
    ``index/tokens.py``'s ``generate_trapdoor(scheme, keywords)`` takes no
    policy argument at all: Option D's token is ``H(w)``, so ``|T_Q| = q``
    whatever ``|P_U|`` is and the second dimension is structurally inert. §VI's
    Exp. 1 is a measurement OF the policy-bound token (D1), which is why it is
    here and not in ``experiments.py``. That is divergence D7.
    """

    config: scheme_config.Configuration
    source: Any = None
    name: str = "exp1_trapdoor_generation"
    number: int = 1
    variable: str = "keywords"
    values: Tuple[Any, ...] = ()
    #: ``|P_U|`` — how many authorized policies this arm derives tokens under.
    policy_scope: int = 1
    #: Reads the corpus for its policies and keywords, so it inherits the
    #: corpus provenance and can be reportable. See `corpus_world`.
    CORPUS_BACKED: ClassVar[bool] = True
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("tokens", COUNT),
        MetricSpec("keywords", COUNT),
        MetricSpec("policies", COUNT),
        MetricSpec("token_bytes", BYTES),
    )

    def __post_init__(self) -> None:
        if self.policy_scope < 1:
            raise ValueError(f"|P_U| must be >= 1, got {self.policy_scope}")
        if self.source is None:
            raise ValueError(
                "PsaExp1TokenGeneration reads the corpus for its policies and "
                "keywords; pass the same source build_deployment is given"
            )
        if not self.values:
            self.values = tuple(self.config.experiment("exp1").values)

    def prepare(self, value: Any) -> Any:
        q = int(value)
        # REAL policies and REAL keywords. Both reach the measured hash: the
        # keyword string is hashed directly, and the policy fixes PID and the
        # PV digest derived from AA(PID). Synthetic `kw:00000` strings and
        # stipulated `hospital/pol0` policies were what made this experiment
        # `psa_in_process` and therefore unquotable.
        world, vocabulary = corpus_world(
            self.source, records=EXP1_SAMPLE_RECORDS,
            # §VI's four domains. Left to `corpus_world`'s own default this
            # took the corpus's width (10), so Exp. 1 derived its policy set
            # over ten domains while every other non-sweeping experiment is
            # pinned to four. `corpus_world` keeps its `None` default rather
            # than taking a config, because its other callers are tests that
            # want the source's own width.
            domains=int(self.config.defaults.domains),
        )
        if len(world.policies) < self.policy_scope:
            raise RuntimeError(
                f"|P_U| = {self.policy_scope} needs that many DISTINCT policies, "
                f"but the corpus yields {len(world.policies)} "
                f"({len(world.domains)} domains x policies_per_domain). Raise "
                f"`policies_per_domain` in index/extract.py or lower |P_U|; "
                f"repeating a policy would collapse distinct tokens and "
                f"understate |T_Q|, the identity this experiment checks."
            )
        scopes = [world.scope(p) for p in world.policies[: self.policy_scope]]
        if len(vocabulary) < q:
            raise RuntimeError(
                f"q = {q} distinct keywords requested, corpus sample has "
                f"{len(vocabulary)}"
            )
        # A representative draw rather than the alphabetically-first q: keyword
        # LENGTH is what the HMAC costs, and the short end of a sorted
        # vocabulary is not representative of it.
        rng = DeterministicRNG(EXP1_KEYWORD_SEED).spawn(
            f"psa_exp1/q={q}/pu={self.policy_scope}"
        )
        keywords = list(rng.choice(list(vocabulary), size=q, replace=False))
        return dict(
            scheme=_keyed_scheme(),
            keywords=keywords,
            scopes=scopes,
            q=q,
            policies=self.policy_scope,
        )

    def measure(self, prepared: Any) -> Sample:
        with gc_quiesced():
            started = time.perf_counter_ns()
            produced = psa_tokens.generate_query_tokens(
                prepared["scheme"], prepared["keywords"], prepared["scopes"]
            )
            elapsed = time.perf_counter_ns() - started
        expected = prepared["q"] * prepared["policies"]
        if len(produced) != expected:
            raise RuntimeError(
                f"|T_Q| = {len(produced)} but q·|P_U| = {expected}; the "
                f"manuscript's Exp. 1 identity does not hold"
            )
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "tokens": float(len(produced)),
                "keywords": float(prepared["q"]),
                "policies": float(prepared["policies"]),
                "token_bytes": float(sum(len(t) for t in produced)),
            },
        )


# ===========================================================================
# D9 — trapdoors a cross-domain query must issue


# ===========================================================================
# §VI Exp. 3 — cross-domain SEARCH LATENCY under the policy-bound token
# ===========================================================================
@dataclass
class PsaExp3CrossDomainLatency:
    """§VI Exp. 3, which measures LATENCY — the figure the manuscript includes.

    §VI: *"This experiment evaluates encrypted-search latency as the number of
    participating healthcare domains d increases from 2 to 10 … compared with
    Schemes [30], [35], [41], [54],"* captioned *"Cross-domain search latency
    versus number of participating domains."*

    The PSA track had no such experiment. :class:`PsaExp3CrossDomainTokens`
    reports a token COUNT, which is the D9 companion claim, not §VI's Fig. 3 —
    so under the PSA construction seven of the manuscript's eight figures had a
    source and Fig. 3 did not. This is that source.

    **Per-domain index size is fixed**, per §VI's own sentence, at
    ``global.yaml``'s ``exp3 -> held_constant.per_domain_index_size``. Total
    data therefore grows with ``d``. The four baselines fixed *total* instead
    and sharded by ``d``, which shrank their per-domain size as ``d`` grew and
    is why [35]'s latency FELL across the sweep; all five now hold the same
    quantity constant.

    **Authorization scope grows with ``d``**, and that is the measurement, not
    an accident. A cross-domain query is authorized under one policy per
    participating domain, so ``|P_U| = d`` and the token count is ``q·d`` where
    Option D issues ``q``. That cost is D9, and it is what §VI's Exp. 3 buys
    for the policy-state binding.

    The query is posed the way :class:`PsaExp2SearchLatency` poses it — a
    disjunction across authorized policies of a conjunction over keywords —
    because a flat ``q·|P_U|`` token set asks one record to satisfy tokens bound
    to several policies at once, which no record can.
    """

    config: scheme_config.Configuration
    source: Any
    name: str = "exp3_crossdomain_scalability"
    number: int = 3
    variable: str = "domains"
    values: Tuple[Any, ...] = ()
    #: Reads the corpus, so it inherits the corpus provenance.
    CORPUS_BACKED: ClassVar[bool] = True
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("tokens_issued", COUNT),
        MetricSpec("nodes_searched", COUNT),
        MetricSpec("n_eff", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp3").values)

    def prepare(self, value: Any) -> Any:
        domain_count = int(value)
        held = self.config.experiment("exp3").held_constant or {}
        per_domain = int(held.get("per_domain_index_size", 0))
        if per_domain <= 0:
            raise ValueError(
                "global.yaml exp3_crossdomain_scalability.held_constant."
                "per_domain_index_size must be a positive record count; §VI "
                "fixes the per-domain index size and the value cannot come "
                "from a literal here"
            )
        record_count = per_domain * domain_count
        # Refuse rather than be OOM-killed, exactly as Exp. 2 and Option D's
        # Exp. 3 do. An OOM is SIGKILL: no traceback, no partial results.
        crypto_config.assert_memory_for(
            record_count * 6_800 * self.source.keywords_per_record / 6,
            f"psa exp3 index at d={domain_count} x {per_domain:,} records/domain",
        )
        deployment = psa_build_deployment(
            config=self.config, source=self.source,
            records=record_count, domains=domain_count,
        )
        world = deployment.world
        # ONE AUTHORIZED POLICY PER PARTICIPATING DOMAIN, so |P_U| = d. Picked
        # from the policies the corpus actually produced, first per domain, so
        # the scope is derived rather than stipulated.
        by_domain: Dict[str, str] = {}
        for policy in world.policies:
            domain = policy.split("/", 1)[0]
            by_domain.setdefault(domain, policy)
        scopes = [
            world.scope(by_domain[d]) for d in world.domains if d in by_domain
        ]
        if not scopes:
            raise RuntimeError(
                f"no policy found for any of {len(world.domains)} domains; "
                f"a cross-domain query needs at least one authorized policy"
            )
        pool = [r["keywords"] for r in deployment.records]
        # Phase III enrolment across every participating domain — untimed, as
        # session establishment is not per query.
        profile, authority_ids, attributes, resolver = psa_enrol(
            deployment, "DU-1", deployment.world.domains
        )
        return dict(
            deployment=deployment, scopes=scopes, pool=pool, cursor=[0],
            profile=profile, authority_ids=authority_ids,
            attributes=attributes, resolver=resolver,
        )

    def measure(self, prepared: Any) -> Sample:
        deployment = prepared["deployment"]
        pool, cursor = prepared["pool"], prepared["cursor"]
        keywords = pool[cursor[0] % len(pool)]
        cursor[0] += 1
        q = min(self.config.defaults.keywords_per_query, len(keywords))
        query = list(dict.fromkeys(keywords))[:q]

        issued = 0
        hits = 0
        searched: set = set()
        with gc_quiesced():
            started = time.perf_counter_ns()
            # §VI Exp. 3: "The AIM first validates the current VAP and derives
            # policy-state-aware tokens and the required authorized shard set
            # S_Q. AASS then assigns each required shard to an eligible FSN."
            # Both stages were outside the timed region until 2026-09-10.
            all_tokens = tuple(
                t for scope in prepared["scopes"]
                for t in psa_tokens.generate_query_tokens(
                    deployment.scheme, query, [scope]
                )
            )
            decision = authz_mod.verify_search_request(
                deployment.aim,
                psa_search_token(prepared["profile"], all_tokens),
                prepared["profile"],
                authority_ids=prepared["authority_ids"],
                attributes=prepared["attributes"],
                resolver=prepared["resolver"],
            )
            if not decision.accepted:
                raise RuntimeError(f"authorization rejected: {decision.reason}")
            aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(
                deployment.nodes,
                aass_mod.SearchRequest(
                    tokens=all_tokens,
                    authorized=decision.authorized_shards,
                    vid_u=prepared["profile"].vid,
                    query_versions=decision.query_versions,
                ),
            )
            for scope in prepared["scopes"]:
                scope_tokens = psa_tokens.generate_query_tokens(
                    deployment.scheme, query, [scope]
                )
                issued += len(scope_tokens)
                for node in deployment.nodes:
                    if scope.domain not in node.domains:
                        continue
                    found, _stats = node.index.lookup(
                        scope_tokens, [(scope.domain, scope.policy_id)]
                    )
                    hits += len(found)
                    searched.add(node.node_id)
            elapsed = time.perf_counter_ns() - started

        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                # q*|P_U| = q*d, COUNTED from what was issued rather than
                # asserted. Option D issues q here, flat in d (D9).
                "tokens_issued": float(issued),
                "nodes_searched": float(len(searched)),
                "n_eff": float(hits),
            },
        )


# ===========================================================================
# D1 — what an authority-state change costs when the token depends on it
# ===========================================================================
@dataclass
class PsaExp5ReTokenization:
    """Phase VII Step 2 under eq:policy-bound-token: ``T'`` for every affected entry.

    ``Exp5KeywordUpdate`` measures a payload rewrite, because Option D's token
    does not depend on the policy state. Here the same update recomputes the
    token, the Merkle leaf and the authentication path for each of the ``k``
    affected entries, then rebuilds ``Commit_i``.

    The two curves against the same ``k`` are the price of D1, and
    Phase IV §1.3's ~9.0M-entry estimate is the thing they settle.
    """

    config: scheme_config.Configuration
    source: Any
    name: str = "exp5_keyword_update"
    number: int = 5
    variable: str = "keyword_document_pairs"
    values: Tuple[Any, ...] = ()
    #: Reads the corpus, so it inherits corpus provenance.
    CORPUS_BACKED: ClassVar[bool] = True
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("entries_retokenized", COUNT),
        MetricSpec("merkle_nodes_recomputed", COUNT),
        MetricSpec("commitments_rebuilt", COUNT),
    )
    #: WAS a hardcoded 6, commented "matching the frozen corpus's mean |W_i|".
    #: The frozen corpus's mean is **31.70** (`dataset_manifest.json`), so the
    #: constant was wrong by ~5x and this experiment sized its record pool from
    #: it. Read from the source, which reports the manifest's own figure.
    @property
    def keywords_per_record(self) -> int:
        return max(1, int(getattr(self.source, "keywords_per_record", 6)))

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp5").values)

    def prepare(self, value: Any) -> Any:
        pairs = int(value)
        # REAL policies and REAL keyword co-occurrence. This invented both
        # (`hospital/pol0`, `kw:00042`), which prices the construction and
        # nothing else — the reason the banked runs are `psa_in_process`.
        world, _vocabulary = corpus_world(
            self.source, records=EXP1_SAMPLE_RECORDS,
            domains=int(self.config.defaults.domains),
        )
        scheme = _keyed_scheme()
        corpus_records = list(
            self.source.records(
                EXP1_SAMPLE_RECORDS, domains=int(self.config.defaults.domains)
            )
        )
        # The pool is sized by the AFFECTED entries, not by every entry built.
        # `measure` skips records no governing authority touched (that skip IS
        # eq:unaffected-policy), so sizing at ceil(k / |W_i|) records left the
        # loop running out of dependent records at roughly the governance
        # fraction -- measured 0.500 of the swept k at every point with the
        # default 2-of-4 AA(PID). The x-axis said k while the work was k/2, and
        # the whole point of this experiment is to put that curve beside
        # Exp5KeywordUpdate's at the SAME k (which does reach k: 1002 entries
        # at k=1000). Independent records still make up the rest of the pool,
        # so the skip path stays on the timed loop.
        moved = sorted(world.authorities.values())[0]
        records: List[Dict[str, Any]] = []
        affected_entries = 0
        rid = -1
        while affected_entries < pairs:
            rid += 1
            corpus_record = corpus_records[rid % len(corpus_records)]
            policy = corpus_record.policy_id
            domain = policy.split("/", 1)[0]
            pv = world.pv(policy)
            cid = f"bafyPSA{rid:08d}"
            keywords = list(dict.fromkeys(corpus_record.keywords))
            entries = [
                psa_records.PolicyStateIndexEntry(
                    token=scheme.index_token(w, policy_id=policy, pv=pv, domain=domain),
                    cid=cid, policy_id=policy, pv=pv,
                )
                for w in keywords
            ]
            records.append(
                dict(
                    cid=cid, policy=policy, domain=domain, keywords=keywords,
                    entries=entries,
                    commitment=psa_commit.commit_record(
                        record_id=rid, cid=cid, entries=entries,
                        policy_id=policy, pv=pv,
                        auth_state=world.auth_state(policy),
                    ),
                )
            )
            if moved in world.governance.governing(policy):
                # The record's OWN entry count, not a nominal constant: with the
                # corpus, |W_i| varies per record (5..64, mean 31.70).
                affected_entries += len(entries)
        return dict(world=world, scheme=scheme, records=records, pairs=pairs)

    def measure(self, prepared: Any) -> Sample:
        world = prepared["world"]
        scheme = prepared["scheme"]
        pairs = prepared["pairs"]

        # One authority advances. Everything below is the dependency closure.
        moved = sorted(world.authorities.values())[0]
        bumped = {**world.versions, moved: world.versions[moved] + 1}

        applied = 0
        nodes = 0
        rebuilt = 0
        with gc_quiesced():
            started = time.perf_counter_ns()
            for record in prepared["records"]:
                if applied >= pairs:
                    break
                governing = world.governance.governing(record["policy"])
                if moved not in governing:
                    continue                       # eq:unaffected-policy
                pv2 = psa_state.PolicyVersionState.build(bumped, governing).digest()
                fresh = [
                    psa_records.PolicyStateIndexEntry(
                        token=scheme.index_token(
                            w, policy_id=record["policy"], pv=pv2,
                            domain=record["domain"],
                        ),
                        cid=record["cid"], policy_id=record["policy"], pv=pv2,
                    )
                    for w in record["keywords"]
                ]
                commitment = psa_commit.commit_record(
                    record_id=0, cid=record["cid"], entries=fresh,
                    policy_id=record["policy"], pv=pv2,
                    auth_state=psa_state.PolicyAuthorityState.build(
                        world.commitments, governing
                    ).digest(),
                )
                applied += len(fresh)
                # Every leaf moved, so the whole tree is recomputed: that IS the
                # cost. Reporting the internal-node count keeps it comparable
                # with Exp. 5's merkle_nodes_recomputed.
                nodes += max(0, 2 * len(fresh) - 1)
                rebuilt += 1
                record["entries"] = fresh
                record["commitment"] = commitment
            elapsed = time.perf_counter_ns() - started

        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "entries_retokenized": float(applied),
                "merkle_nodes_recomputed": float(nodes),
                "commitments_rebuilt": float(rebuilt),
            },
        )


# ===========================================================================
# D8 — Exp. 6 over the AFFECTED-POLICY RATIO
# ===========================================================================
@dataclass
class _PsaShard:
    """One Fog Search Node's view: the entries it serves, and its auth state.

    ``F_k^aff``, the last link of the manuscript's dependency chain
    ``AA_k -> P_k^aff -> R_k^aff -> S_k^aff -> F_k^aff``. Deliberately minimal
    -- ``fsn/`` is written against ``types.IndexEntry`` and its scalar ``vid``
    and cannot hold a ``PolicyStateIndexEntry`` -- but it is a real recipient
    that does real work, which is the part that matters: without one, "delivers
    to all FSNs" and "delivers only to affected FSNs" differ by a multiplier on
    a counter rather than by anything measured.
    """

    node_id: str
    domains: set
    index: Dict[bytes, Any] = field(default_factory=dict)
    #: Advances on every message this node accepts, whether or not it holds the
    #: affected shard -- which is the cost Incremental-All pays for its extra
    #: fan-out, and the reason its curve can differ from DIAS's at all.
    auth_view: bytes = b"\x00" * 32

    def apply(self, delta: "_PsaDelta") -> int:
        """Ingest one delivered delta. Returns entries rewritten on this node.

        Two effects, mirroring ``sync/dias.py::apply_dias``: the node's
        authorization view advances, and IF it holds the shard its entries are
        replaced. A node without the shard still pays the first -- that is the
        honest cost of an unnecessary delivery, not a penalty invented to make
        the ablation come out.
        """
        self.auth_view = hashes.sha256(
            self.auth_view, delta.auth_state, delta.payload,
            domain=b"psa-fsn-auth-view/v1",
        )
        if delta.domain not in self.domains:
            return 0
        for token in delta.retired:
            self.index.pop(token, None)
        for entry in delta.entries:
            self.index[entry.token] = entry
        return len(delta.entries)


@dataclass
class _PsaDelta:
    """One record's synchronization message, as it goes on the wire."""

    cid: str
    domain: str
    entries: Tuple[Any, ...]
    retired: Tuple[bytes, ...]
    auth_state: bytes
    payload: bytes

    @property
    def size_bytes(self) -> int:
        return len(self.payload)



VARIANT_DIAS = "dias"
VARIANT_INCREMENTAL_ALL = "incremental_all"
VARIANT_FULL_STATE = "full_state"
PSA_EXP6_VARIANTS: Tuple[str, ...] = (
    VARIANT_DIAS, VARIANT_INCREMENTAL_ALL, VARIANT_FULL_STATE
)

#: "the fraction of policies affected ... increases from 10% to 100%".
AFFECTED_RATIOS: Tuple[float, ...] = (0.1, 0.25, 0.5, 0.75, 1.0)


@dataclass
class PsaExp6AffectedRatio:
    """Manuscript Exp. 6: DIAS as the affected-policy ratio goes 10% -> 100%.

    The implemented Exp. 6 sweeps an UPDATE COUNT (10^2..10^5), so its banked
    data cannot be plotted on this axis at all — that is divergence D8. Here the
    ratio is dialled directly, by stating which policies the mutated authority
    governs (``PolicyGovernance.with_overrides``), and the three arms are the
    ones §VI names:

    ``dias``            evolve only dependent policies and deliver only to FSNs
                        holding an affected shard.
    ``incremental_all`` evolve only dependent policies, deliver to every FSN.
    ``full_state``      re-evolve every policy and deliver to every FSN.

    The prediction the figure is meant to test is in §VI: the DIAS advantage
    "narrows" as the ratio approaches 100%, because at 100% every policy is
    dependency-relevant and the first two arms coincide.
    """

    config: scheme_config.Configuration
    #: Required. Supplies the policies, the records under them, and the
    #: vocabulary -- see `policy_population`.
    source: Any = None
    CORPUS_BACKED: ClassVar[bool] = True
    name: str = "exp6_authorization_sync"
    number: int = 6
    variable: str = "affected_policy_ratio"
    values: Tuple[Any, ...] = AFFECTED_RATIOS
    variant: str = VARIANT_DIAS
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        # RECORDS, not policies: `evolved` increments once per record in
        # the loop below. The two were indistinguishable while this arm
        # synthesised one record per policy -- both read 40 -- so the
        # mislabel was invisible. On real corpus records they differ by the
        # records-per-policy factor (811 vs 4 at ratio 0.1), and a reader
        # would have taken 811 as a policy count.
        MetricSpec("records_evolved", COUNT),
        MetricSpec("entries_retokenized", COUNT),
        MetricSpec("delivered_kb", KB),
        MetricSpec("fsns_touched", COUNT),
    )
    #: The policy population the ratio is taken over, and it is now READ FROM
    #: THE CORPUS rather than stipulated.
    #:
    #: What had to be separated to get here. Two things were conflated:
    #:
    #: 1. **Which** policies the moved authority governs. That is the
    #:    independent variable -- `with_overrides` below sets it so exactly
    #:    `ratio` of the population depends on `moved`. It is stated by
    #:    construction in any honest version of this experiment, because the
    #:    ratio is what the x-axis IS.
    #: 2. **How many** policies exist, and **which records, shards and FSNs**
    #:    sit under them. That is not the variable, and it was being invented
    #:    along with (1): one synthetic record per policy, so
    #:    `entries_retokenized` was `affected_count * keywords_per_record` --
    #:    linear in the ratio by construction rather than by measurement.
    #:
    #: Only (1) needs stipulating. (2) comes from the corpus:
    #: `BucketedPolicyAssignment` hashes the patient pseudonym, so a patient's
    #: records are governed together -- which is what an access policy over
    #: clinical data means -- and `R_k^aff` becomes the real records under the
    #: affected policies, with the real skew in how many records each policy
    #: carries. The chain `AA_k -> P_k^aff -> R_k^aff -> S_k^aff -> F_k^aff` is
    #: then real from `P` onward.
    #:
    #: **Why the resolution is 40 and not the campaign's 8.** The corpus admits
    #: any policy count; the campaign default of `policies_per_domain=2` yields
    #: 8 at §VI's d=4, and §VI sweeps 10%..100%. 10% of 8 is 0.8 -- not
    #: representable, and that single fact is why this arm used to be
    #: stipulated. `AFFECTED_RATIOS` needs a population divisible by 20, so 40
    #: policies (10 per domain at d=4) makes every step exact: 4, 10, 20, 30,
    #: 40. The policy count is a benchmark decision either way (open decision
    #: 3); choosing the resolution that makes the manuscript's own sweep exact
    #: is the defensible one, and `DEFAULT_POLICIES_PER_DOMAIN` is untouched so
    #: no other experiment moves.
    #:
    #: Consequence: this arm IS `CORPUS_BACKED`, inherits the corpus SHA and
    #: `corpus_type: synthea`, and can therefore be reportable.
    policy_population: int = 40
    keywords_per_record: int = 6
    fog_search_nodes: int = 4
    #: Records drawn to populate the policies. Must be large enough that every
    #: one of `policy_population` buckets is actually hit -- an empty policy
    #: would silently shrink the population the ratio is taken over.
    #: 8000 over 40 policies is ~200 records each, deliberately NOT capped to an
    #: equal count per policy: an equal cap would make the records under the
    #: affected policies exactly `affected_count x cap`, which is the same
    #: linear-by-construction artefact as one record per policy, just scaled.
    sample_records: int = 8000

    def __post_init__(self) -> None:
        if self.variant not in PSA_EXP6_VARIANTS:
            raise ValueError(
                f"unknown PSA Exp. 6 variant {self.variant!r}; "
                f"valid: {', '.join(PSA_EXP6_VARIANTS)}"
            )

    def prepare(self, value: Any) -> Any:
        ratio = float(value)
        if self.source is None:
            raise ValueError(
                "Exp. 6 reads its policies, records and vocabulary from the "
                "corpus; pass the same source build_deployment is given"
            )
        domain_count = int(self.config.defaults.domains)
        # The resolution that makes every AFFECTED_RATIOS step a whole number of
        # policies -- see `policy_population`. Ceil so a smaller d still reaches
        # the population rather than silently under-filling it.
        per_domain = -(-self.policy_population // max(1, domain_count))
        world, vocabulary, by_policy = corpus_world(
            self.source,
            records=self.sample_records,
            domains=domain_count,
            policies_per_domain=per_domain,
            collect=True,
        )
        policies = list(world.policies)
        # An unhit bucket would shrink the population the ratio is taken over,
        # making "10%" mean 10% of something smaller than the figure claims.
        expected = per_domain * domain_count
        if len(policies) != expected:
            raise RuntimeError(
                f"Exp. 6 drew {self.sample_records} corpus records and saw "
                f"{len(policies)} of {expected} policies "
                f"({per_domain}/domain x d={domain_count}). The affected-policy "
                f"ratio is a fraction of the population, so a missing policy "
                f"would silently redefine every point on the x-axis. Raise "
                f"`sample_records`."
            )
        roster = sorted(world.authorities.values())
        moved, other = roster[0], roster[1]

        # State the governing sets so exactly `ratio` of the population depends
        # on `moved`. Every policy keeps two governors, so the arms differ only
        # in propagation scope and not in per-policy work.
        affected_count = max(1, round(ratio * len(policies)))
        overrides = {
            policy: ((moved, other) if index < affected_count else (other, roster[-1]))
            for index, policy in enumerate(policies)
        }
        world.governance = world.governance.with_overrides(overrides)

        scheme = _keyed_scheme()
        records = []
        # R_k^aff -- the REAL records under each policy, with the corpus's own
        # keyword sets and its own skew in how many records a policy carries.
        # One synthetic record per policy used to make `entries_retokenized`
        # exactly `affected_count * keywords_per_record`, i.e. linear in the
        # ratio by construction; the retokenization cost is now a function of
        # what the affected policies actually govern.
        #
        # Policies are taken in sorted order, so which policies land in the
        # affected set is deterministic and reproducible across runs and hosts.
        for policy in policies:
            domain = policy.split("/", 1)[0]
            pv = world.pv(policy)
            for record in by_policy[policy]:
                cid = f"bafyPSA{record.record_id:08d}"
                keywords = list(dict.fromkeys(record.keywords))[
                    : self.keywords_per_record
                ]
                records.append(
                    dict(
                        cid=cid, policy=policy, domain=domain,
                        keywords=keywords, pv=pv,
                        entries=[
                            psa_records.PolicyStateIndexEntry(
                                token=scheme.index_token(
                                    w, policy_id=policy, pv=pv, domain=domain
                                ),
                                cid=cid, policy_id=policy, pv=pv,
                            )
                            for w in keywords
                        ],
                    )
                )
        # F^aff -- the FSN layer the dependency chain ends at. One shard per
        # node, domains assigned round-robin the way `assign_domains_to_fsns`
        # does, so at d = m = 4 each node holds exactly one domain. Without a
        # node layer there is nothing for "propagates the deltas only to FSNs
        # maintaining affected shards" to be true OF, and the three arms could
        # differ only in a counter.
        nodes = [
            _PsaShard(node_id=f"FSN{i}", domains=set())
            for i in range(self.fog_search_nodes)
        ]
        for index, domain in enumerate(world.domains):
            nodes[index % len(nodes)].domains.add(domain)
        for record in records:
            for node in nodes:
                if record["domain"] in node.domains:
                    for entry in record["entries"]:
                        node.index[entry.token] = entry
        return dict(
            world=world, scheme=scheme, records=records, moved=moved,
            affected_count=affected_count, nodes=nodes,
        )

    def measure(self, prepared: Any) -> Sample:
        world = prepared["world"]
        scheme = prepared["scheme"]
        moved = prepared["moved"]
        bumped = {**world.versions, moved: world.versions[moved] + 1}
        full_state = self.variant == VARIANT_FULL_STATE
        selective = self.variant == VARIANT_DIAS

        nodes = prepared["nodes"]
        others = tuple(a for a in sorted(world.authorities.values()) if a != moved)

        # AUTHORIZATION-STATE REDISTRIBUTION, the other half of what §VI calls
        # Full-State: "reconstructs and propagates the relevant
        # authorization/index state to all FSNs". The index half is the policy
        # loop below; this is the authorization half, and without it this arm
        # measured only part of what it is named after -- so `FS/DIAS` came out
        # a lower bound and the two Exp. 6 figures defined `full_state`
        # differently.
        #
        # Sized BEFORE the timer for the reason `experiments.py` gives at the
        # same point: the republished payload does not change length while the
        # loop runs, so one encoding is the size of every republish. Doing it
        # per update would put an encode() on the timed path and charge
        # Full-State for measurement work the other two arms do not do.
        rebuild_bytes_per_authority = 0
        if full_state:
            rebuild_bytes_per_authority = len(
                psa_state.PolicyAuthorityState.build(
                    world.commitments, [others[0]]
                ).encode()
            ) * len(nodes)

        evolved = 0
        retokenized = 0
        delivered_bytes = 0
        reached: set = set()

        with gc_quiesced():
            started = time.perf_counter_ns()
            for record in prepared["records"]:
                governing = world.governance.governing(record["policy"])
                dependent = moved in governing
                # full_state re-evolves everything; the other two respect the
                # dependency closure of DIAS Step 1.
                if not dependent and not full_state:
                    continue
                pv2 = psa_state.PolicyVersionState.build(bumped, governing).digest()
                fresh = [
                    psa_records.PolicyStateIndexEntry(
                        token=scheme.index_token(
                            w, policy_id=record["policy"], pv=pv2,
                            domain=record["domain"],
                        ),
                        cid=record["cid"], policy_id=record["policy"], pv=pv2,
                    )
                    for w in record["keywords"]
                ]
                commitment = psa_commit.commit_record(
                    record_id=0, cid=record["cid"], entries=fresh,
                    policy_id=record["policy"], pv=pv2,
                    auth_state=psa_state.PolicyAuthorityState.build(
                        world.commitments, governing
                    ).digest(),
                )
                evolved += 1
                retokenized += len(fresh)

                # The delta as it goes on the wire: the new entries plus the
                # authenticated metadata, from the REAL encodings.
                delta = _PsaDelta(
                    cid=record["cid"], domain=record["domain"],
                    entries=tuple(fresh),
                    retired=tuple(e.token for e in record["entries"]),
                    auth_state=commitment.meta.auth_state,
                    payload=b"".join(
                        [e.encode() for e in fresh] + [commitment.meta.encode()]
                    ),
                )
                record["entries"] = fresh

                # PROPAGATION -- the half of the claim the arms actually ablate.
                # DIAS delivers only to FSNs maintaining an affected shard;
                # Incremental-All and Full-State deliver to every FSN. Each
                # recipient really ingests the message (`_PsaShard.apply`), so
                # the extra fan-out is work done rather than a counter
                # incremented. `delivered_bytes` accumulates per DELIVERY from
                # the message's own length -- never `payload x fan_out`, the
                # derivation `experiments.py` records as wrong on 2026-09-04.
                targets = (
                    [n for n in nodes if delta.domain in n.domains]
                    if selective else nodes
                )
                for node in targets:
                    node.apply(delta)
                    delivered_bytes += delta.size_bytes
                    reached.add(node.node_id)

            if full_state:
                # Every OTHER authority recomputes C_k^auth and the AIM
                # republishes it to every FSN. Built from `world.commitments`
                # each time rather than read back from a cache, so this is the
                # real recomputation -- the same standard `experiments.py`
                # holds `Authority.commitment()` to.
                for authority in others:
                    republished = psa_state.PolicyAuthorityState.build(
                        world.commitments, [authority]
                    ).digest()
                    for node in nodes:
                        node.auth_view = hashes.sha256(
                            node.auth_view, republished,
                            domain=b"psa-fsn-auth-view/v1",
                        )
                        reached.add(node.node_id)
                    delivered_bytes += rebuild_bytes_per_authority
            elapsed = time.perf_counter_ns() - started

        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "records_evolved": float(evolved),
                "entries_retokenized": float(retokenized),
                "delivered_kb": delivered_bytes / 1024.0,
                # DISTINCT nodes, which is what `F_k^aff` is and what Option D's
                # metric of the same name means. Accumulating fan-out per record
                # instead reported 160 "FSNs touched" on a 4-node deployment.
                "fsns_touched": float(len(reached)),
            },
        )


# ===========================================================================
# Exp. 2 — the online search path under the policy-bound token
# ===========================================================================
@dataclass
class PsaExp2SearchLatency:
    """Search latency when the token names a (policy, domain, policy-state).

    Same boundary as ``Exp2SearchLatency``: AIM check, shard selection, shard
    search, response assembly, with index construction offline. ``N`` is sized
    the way Option D sizes it -- in RECORDS -- so the axis means the same thing
    in both, and the same thing the four baselines and SVI mean by it. Both
    constructions were changed together on 2026-09-07; before that both divided
    by ``keywords_per_record`` and drew a corpus 32x smaller than the baselines
    at the same x.

    **What this is expected to show, and why it is a cost not a bug.** A query
    under ``T = H(w ‖ PID ‖ PV ‖ Dom)`` cannot be one trapdoor per keyword: it
    needs one per (keyword, authorized policy), so it issues ``q·|P_U|`` tokens
    and performs that many posting-list lookups where Option D performs ``q``.
    The same binding also stops two records under different policies from
    sharing a posting list for the same keyword, so the index fragments. Both
    follow from D1 and both belong in §VI.

    Corpus-backed: it reads the source ``build_deployment`` reads, so a
    difference between the two curves is a difference between constructions
    rather than between fixtures.
    """

    config: scheme_config.Configuration
    source: Any
    name: str = "exp2_search_latency"
    number: int = 2
    variable: str = "index_size"
    values: Tuple[Any, ...] = ()
    #: This experiment reads the corpus, so it may inherit its provenance.
    CORPUS_BACKED: ClassVar[bool] = True
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("n_eff", COUNT),
        MetricSpec("entries_traversed", COUNT),
        MetricSpec("tokens_issued", COUNT),
        MetricSpec("entries_per_token", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp2").values)

    def prepare(self, value: Any) -> Any:
        record_count = max(1, int(value))
        deployment = psa_build_deployment(
            config=self.config, source=self.source, records=record_count
        )
        world = deployment.world
        # The user's authorized policies -- |P_U| of them, the quantity D7
        # sweeps. Drawn from the policies the corpus actually produced.
        scope = min(self.config.defaults.keywords_per_query, len(world.policies))
        scopes = [world.scope(p) for p in world.policies[:scope]]
        # A NEW keyword per run, at the baselines' own selectivity bounds. The
        # 2026-09-03 defect was querying keywords[0] of the first record for
        # every run of every point, which measured the repeatability of one
        # query rather than search latency.
        pool = [r["keywords"] for r in deployment.records]
        # Phase III enrolment, so the AIM check §VI puts inside the search path
        # can actually run. Untimed: session establishment is not per query.
        profile, authority_ids, attributes, resolver = psa_enrol(
            deployment, "DU-1", deployment.world.domains
        )
        return dict(
            deployment=deployment, scopes=scopes, pool=pool, cursor=[0],
            profile=profile, authority_ids=authority_ids,
            attributes=attributes, resolver=resolver,
        )

    def measure(self, prepared: Any) -> Sample:
        deployment = prepared["deployment"]
        pool, cursor = prepared["pool"], prepared["cursor"]
        keywords = pool[cursor[0] % len(pool)]
        cursor[0] += 1
        q = min(self.config.defaults.keywords_per_query, len(keywords))
        query = list(dict.fromkeys(keywords))[:q]

        traversed = 0
        hits = 0
        issued = 0
        with gc_quiesced():
            started = time.perf_counter_ns()
            # THE FOUR STAGES §VI NAMES, in its order. This timed only token
            # derivation and the posting-list walk, so Figs. 2 and 3 excluded
            # both of the paper's named contributions — the AIM's VAP
            # validation and AASS's shard assignment — while Option D's Exp. 2
            # timed all four and Exp. 7-8 timed the AIM check in BOTH tracks.
            all_tokens = tuple(
                t for scope in prepared["scopes"]
                for t in psa_tokens.generate_query_tokens(
                    deployment.scheme, query, [scope]
                )
            )
            decision = authz_mod.verify_search_request(
                deployment.aim,
                psa_search_token(prepared["profile"], all_tokens),
                prepared["profile"],
                authority_ids=prepared["authority_ids"],
                attributes=prepared["attributes"],
                resolver=prepared["resolver"],
            )
            if not decision.accepted:
                raise RuntimeError(f"authorization rejected: {decision.reason}")
            aass_mod.Scheduler(aass_mod.VARIANT_AASS).select(
                deployment.nodes,
                aass_mod.SearchRequest(
                    tokens=all_tokens,
                    authorized=decision.authorized_shards,
                    vid_u=prepared["profile"].vid,
                    query_versions=decision.query_versions,
                ),
            )
            # ONE CONJUNCTIVE LOOKUP PER AUTHORIZED POLICY, unioned.
            #
            # A PSA query is a disjunction ACROSS policies of a conjunction
            # OVER keywords: the user holds |P_U| policies and a record matches
            # if it carries all q keywords under ANY one of them. Handing the
            # flat q*|P_U| token set to a single conjunctive lookup asks one
            # record to satisfy tokens bound to five different policies, which
            # no record can -- it returned n_eff = 0 at every sweep point even
            # after the per-record intersection fix, because the defect is in
            # how the query is POSED, not how it is matched.
            #
            # |T_Q| = q*|P_U| is unchanged, and so is the work: the same tokens
            # are derived and the same posting lists walked. Only the grouping
            # differs, and the grouping is what makes an answer possible.
            for scope in prepared["scopes"]:
                scope_tokens = psa_tokens.generate_query_tokens(
                    deployment.scheme, query, [scope]
                )
                issued += len(scope_tokens)
                for node in deployment.nodes:
                    if scope.domain not in node.domains:
                        continue
                    found, stats = node.index.lookup(
                        scope_tokens, [(scope.domain, scope.policy_id)]
                    )
                    hits += len(found)
                    traversed += stats.entries_traversed
            elapsed = time.perf_counter_ns() - started

        entries = deployment.entry_count
        distinct = sum(node.index.token_count for node in deployment.nodes)
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "n_eff": float(hits),
                "entries_traversed": float(traversed),
                "tokens_issued": float(issued),
                # Entries per DISTINCT token -- a sharing ratio, so HIGHER is
                # more sharing. Named that way round deliberately: the first
                # draft called it `index_fragmentation`, which reads as the
                # opposite of what it counts, and this project has shipped
                # three defects where the number was fine and the label was
                # not. Option D shares one posting list across every record
                # carrying the keyword; PSA shares only within a
                # (policy, domain, PV), so this is the measured cost of D1's
                # binding on index structure.
                "entries_per_token": entries / max(distinct, 1),
            },
        )


# ===========================================================================
# D3 — Exp. 4 under the policy-state-aware commitment
# ===========================================================================
def _psa_batched_chain_checker(ledger, cids: Sequence[str]):
    """Phase VIII Step 3 for a whole response, against a REAL ledger.

    Reads through ``verify/ledger.py::lookup_anchors``, so whatever
    ``ABCD_LEDGER`` selected is what gets queried: ``memory`` walks the
    in-process chain, ``fabric`` talks to the running Hyperledger network. The
    experiment therefore prices the chain step the paper describes rather than
    a dictionary, and ``ledger_faithful`` in run_meta.json describes the object
    that was actually called.

    Batched for the reason ``batched_chain_checker`` documents: a per-record
    namespace walk made Option D's Step 3 O(r^2) and 99.6% of the step's cost.
    The fetch is LAZY -- it happens on the first bundle checked, inside
    whatever region the caller is timing -- so the harness cannot make the cost
    vanish by resolving anchors in an untimed ``prepare``. Its whole cost lands
    on the first record, which is right: a client pays it once per response.
    """
    resolved: Dict[str, Any] = {}
    missing: set = set()
    done = [False]

    def check(bundle) -> psa_verify.StepResult:
        if not done[0]:
            anchors, absent = vledger_mod.lookup_anchors(ledger, cids)
            resolved.update(anchors)
            missing.update(absent)
            done[0] = True
        found = resolved.get(bundle.cid)
        if found is None:
            return psa_verify.StepResult(
                "chain", False, f"no anchor on the ledger for {bundle.cid}"
            )
        ok = hashes.constant_time_equal(found.anchor.commit, bundle.meta.commit)
        return psa_verify.StepResult(
            "chain", ok,
            "" if ok else "Commit_i is not the one anchored on the ledger",
        )

    return check


@dataclass(frozen=True)
class _PsaAnchoredCommitment:
    """What ``anchor_initial_commitment`` reads: ``.commit`` and ``.root``.

    A PSA commitment is not a ``RecordCommitment`` -- it binds CID and
    AuthState where that one binds AuthRoot_DO -- but the ANCHOR is the same
    two fields, so the ledger write path is shared rather than duplicated.
    """

    commit: bytes
    root: bytes


@dataclass
class PsaExp4Verification:
    """Phase VIII Steps 1-3 per returned RECORD, under ``Commit_i`` of D3.

    The Option D counterpart verifies ``H(Root ‖ PID ‖ VID ‖ AuthRoot_DO)``;
    this verifies ``H(CID ‖ Root ‖ PID ‖ PV ‖ AuthState)``. Both time the same
    boundary -- Merkle proof, commitment recomputation, chain consistency, with
    IPFS fetch and decryption excluded -- so the two curves are comparable at
    the same ``r``.

    ``r`` COUNTS RECORDS. ``psa/verify.py::build_response`` emits one bundle per
    index ENTRY, so this takes ``[0]`` per record. Taking them all is defect
    ``d1cdf9c``, which has already forced two re-runs and then survived into
    Exp. 9; at ``keywords_per_record = 6`` it would inflate the sweep 6x and
    compare 6r entries against baselines returning r records.
    """

    #: Phase VIII Step 3 now runs against whatever ``ABCD_LEDGER`` selects, the
    #: same switch ``build_deployment`` reads -- so with ``ABCD_LEDGER=fabric``
    #: this measures the same chain the banked Option D Exp. 4 measured
    #: (`5ee7c16`, "like-for-like axis against real Fabric") and the two curves
    #: share an axis. It previously used an in-process anchor MAP, which is why
    #: 16.86 ms sat against Option D's 1675.34 ms at r=1000: that ~99x was the
    #: backend, not the construction.

    config: scheme_config.Configuration
    source: Any
    name: str = "exp4_verification_overhead"
    number: int = 4
    variable: str = "returned_results"
    values: Tuple[Any, ...] = ()
    #: Reads the corpus for its policies and keywords.
    CORPUS_BACKED: ClassVar[bool] = True
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("proof_size", KB),
        MetricSpec("path_length", COUNT),
        MetricSpec("records_verified", COUNT),
    )
    #: WAS a hardcoded 6. The frozen corpus's mean |W_i| is **31.70**, and this
    #: sets the Merkle tree's leaf count — so the constant understated the tree
    #: height Exp. 4's proof paths are measured against. Read from the source.
    @property
    def keywords_per_record(self) -> int:
        return max(1, int(getattr(self.source, "keywords_per_record", 6)))

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp4").values)

    def prepare(self, value: Any) -> Any:
        wanted = int(value)
        # Policies and keywords from the corpus, so the hashed inputs and the
        # governing sets behind every `PV_i` are the corpus's own.
        world, vocabulary = corpus_world(
            self.source, records=EXP1_SAMPLE_RECORDS,
            domains=int(self.config.defaults.domains),
        )
        scheme = _keyed_scheme()
        # ABCD_LEDGER decides, exactly as build_deployment decides it. `fabric`
        # refuses to fall back, so a run stamped Fabric-backed was Fabric-backed.
        ledger = chain_select.make_ledger()
        bundles = []
        for rid in range(wanted):
            policy = world.policies[rid % len(world.policies)]
            domain = policy.split("/", 1)[0]
            pv = world.pv(policy)
            cid = f"bafyPSA{rid:08d}"
            entries = [
                psa_records.PolicyStateIndexEntry(
                    token=scheme.index_token(
                        vocabulary[
                            (rid * self.keywords_per_record + k) % len(vocabulary)
                        ],
                        policy_id=policy, pv=pv, domain=domain,
                    ),
                    cid=cid, policy_id=policy, pv=pv,
                )
                for k in range(self.keywords_per_record)
            ]
            commitment = psa_commit.commit_record(
                record_id=rid, cid=cid, entries=entries, policy_id=policy,
                pv=pv, auth_state=world.auth_state(policy),
            )
            # ONE bundle per returned ciphertext.
            bundles.append(psa_verify.build_response(commitment, entries)[0])
            # Phase V Step 3: anchor BC_i. The PSA commitment carries the policy
            # state inside Commit_i, so there is no scalar VID to key on and the
            # anchor sits at version 0 -- the same key scheme Phase VII Step 5
            # would extend if this record were later evolved.
            out_mod.anchor_initial_commitment(
                ledger, cid=cid,
                commitment=_PsaAnchoredCommitment(
                    commit=commitment.commit, root=commitment.root
                ),
                vid=0,
            )
        return dict(
            bundles=tuple(bundles), ledger=ledger,
            cids=[b.cid for b in bundles],
        )

    def measure(self, prepared: Any) -> Sample:
        bundles = prepared["bundles"]
        checker = _psa_batched_chain_checker(prepared["ledger"], prepared["cids"])
        with gc_quiesced():
            started = time.perf_counter_ns()
            results = [
                psa_verify.verify_bundle(bundle, chain_check=checker)
                for bundle in bundles
            ]
            elapsed = time.perf_counter_ns() - started
        rejected = [r for r in results if not r.accepted]
        if rejected:
            raise RuntimeError(
                f"{len(rejected)} of {len(results)} bundles failed verification "
                f"(first at step {rejected[0].failed_step})"
            )
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "proof_size": sum(r.proof_size_bytes for r in results) / 1024.0,
                "path_length": (
                    sum(r.proof_path_length for r in results) / len(results)
                ),
                "records_verified": float(len(results)),
            },
        )



def _flip_token_byte(bundle):
    """Corrupt one byte of the bundle's index-entry token.

    ``cid`` is left intact so the bundle stays well-formed and Phase VIII Step 1
    rejects it as a DETECTED tamper rather than a parse failure.
    """
    entry = bundle.entry
    raw = bytearray(entry.token)
    raw[0] ^= 0x01
    return replace(bundle, entry=replace(entry, token=bytes(raw)))



# ---------------------------------------------------------------------------
# Exp. 4, arm `granularity` — SVI Fig. 4(b)
# ---------------------------------------------------------------------------
@dataclass
class PsaExp4Granularity:
    """What per-entry verification BUYS, where the default arm measures its COST.

    Panel (b) of SVI's Fig. 4. There is no Experiment 9 in the manuscript; this
    is the second arm of Experiment 4 and shares its figure.

    The result-set size is PINNED and the number of tampered records is swept.
    The question is not how fast a scheme verifies but what it can do once
    verification fails.

    **Why this is a fair comparison and not a strawman.** Scheme 35's Alg. 4
    checks a single XOR-accumulated tag over the COMPLETE result set, and
    Scheme 30's prooflist entry commits to every file added at that level in
    that batch. In both, a subset does not balance -- verifying a truncated
    subset is *supposed* to fail, because the XOR would not cancel. So neither
    construction can bisect its way to the bad record without the server issuing
    fresh proofs per sub-batch, which neither paper defines. The all-or-nothing
    outcome is a property of the published designs, not of this implementation.

    **The tamper.** One byte of an index entry's token, leaving ``cid`` intact
    so the bundle stays well-formed. The leaf covers every field, so Phase VIII
    Step 1 rejects it as a detected tamper rather than a malformed bundle --
    different code paths, and timing the wrong one would measure parse failure.

    **Not swept at t = 0.** The figure is log-log and the untampered case is the
    default arm.

    **The unit is a RECORD, not an index entry**, the same rule the default arm
    adopted: both are panels of one figure, so a mismatch would put panel (a) in
    records and panel (b) in entries under a single caption.
    """

    config: scheme_config.Configuration
    source: Any
    name: str = "exp4_verification_overhead"
    number: int = 4
    variable: str = "tampered_records"
    values: Tuple[Any, ...] = ()
    CORPUS_BACKED: ClassVar[bool] = True
    primary: MetricSpec = MetricSpec("records_discarded", COUNT)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("usable_recovered", COUNT),
        MetricSpec("tampered_localised", COUNT),
        MetricSpec("latency", MS, is_timing=True),
    )

    @property
    def keywords_per_record(self) -> int:
        return max(1, int(getattr(self.source, "keywords_per_record", 6)))

    @property
    def result_set_size(self) -> int:
        """``r``, pinned. Swept quantity is ``t``, so ``r`` must not move."""
        held = self.config.experiment("exp4").held_constant or {}
        return int(held.get("returned_results", 20000))

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp4").tamper_values)

    def prepare(self, value: Any) -> Any:
        tampered = int(value)
        total = self.result_set_size
        world, vocabulary = corpus_world(
            self.source, records=EXP1_SAMPLE_RECORDS,
            domains=int(self.config.defaults.domains),
        )
        scheme = _keyed_scheme()
        ledger = chain_select.make_ledger()
        bundles = []
        for rid in range(total):
            policy = world.policies[rid % len(world.policies)]
            domain = policy.split("/", 1)[0]
            pv = world.pv(policy)
            cid = f"bafyPSA{rid:08d}"
            entries = [
                psa_records.PolicyStateIndexEntry(
                    token=scheme.index_token(
                        vocabulary[
                            (rid * self.keywords_per_record + k) % len(vocabulary)
                        ],
                        policy_id=policy, pv=pv, domain=domain,
                    ),
                    cid=cid, policy_id=policy, pv=pv,
                )
                for k in range(self.keywords_per_record)
            ]
            commitment = psa_commit.commit_record(
                record_id=rid, cid=cid, entries=entries, policy_id=policy,
                pv=pv, auth_state=world.auth_state(policy),
            )
            bundles.append(psa_verify.build_response(commitment, entries)[0])
            out_mod.anchor_initial_commitment(
                ledger, cid=cid,
                commitment=_PsaAnchoredCommitment(
                    commit=commitment.commit, root=commitment.root
                ),
                vid=0,
            )

        # Tamper OUTSIDE the timed region: forging a response is the adversary's
        # work, not the verifier's. Deterministic in t so a re-run tampers with
        # the same records.
        rng = random.Random(20260912 + tampered)
        marked = rng.sample(range(len(bundles)), min(tampered, len(bundles)))
        for i in marked:
            bundles[i] = _flip_token_byte(bundles[i])

        return dict(
            bundles=tuple(bundles), ledger=ledger,
            cids=[b.cid for b in bundles], tampered=len(marked),
        )

    def measure(self, prepared: Any) -> Sample:
        checker = _psa_batched_chain_checker(prepared["ledger"], prepared["cids"])
        with gc_quiesced():
            started = time.perf_counter_ns()
            results = [
                psa_verify.verify_bundle(bundle, chain_check=checker)
                for bundle in prepared["bundles"]
            ]
            elapsed = time.perf_counter_ns() - started

        rejected = [r for r in results if not r.accepted]
        discarded = len(rejected)
        expected = prepared["tampered"]
        # A mismatch either way is a real failure, not a metric: fewer means a
        # tamper went undetected (soundness), more means an intact record was
        # thrown away (completeness). Both invalidate the figure, so neither is
        # silently averaged into it.
        if discarded != expected:
            raise RuntimeError(
                f"{discarded} records rejected but {expected} were tampered; "
                f"verification is neither sound nor complete under this build"
            )
        return Sample(
            primary=float(discarded),
            secondaries={
                "usable_recovered": float(len(results) - discarded),
                "tampered_localised": float(discarded),
                "latency": elapsed / 1e6,
            },
        )


# ===========================================================================
# Exp. 7-8 — the scheduler ablation under the policy-bound token
# ===========================================================================
@dataclass(frozen=True)
class _PsaTrapdoor:
    """What the replay reads off a trapdoor: ``.tokens``, ``.vid_u``, ``.groups``.

    The forked replay in ``SchedulerAblation._replay_multiprocess`` touches a
    trapdoor through exactly those two attributes, so the PSA arm supplies
    them and the replay, the scheduler and the FSN pool are left untouched.
    Nothing about the measured path is re-implemented here.
    """

    tokens: Tuple[bytes, ...]
    vid_u: int
    #: ``[(tokens_for_one_policy, [(domain, policy)])]``. The query is a
    #: disjunction ACROSS policies of a conjunction OVER keywords, so the shard
    #: must evaluate one group per authorized policy and union the results.
    #: Without it the flat ``q*|P_U|`` set asks one record to satisfy tokens
    #: bound to several policies, which no record can, and every request
    #: returns nothing.
    groups: Tuple = ()


class PsaSchedulerAblation(experiments_mod.SchedulerAblation):
    """Exp. 7-8 with PSA entries in the shards and PSA tokens in the trace.

    **Only ``prepare`` is overridden.** The scheduler, the replay, the FSN pool
    and the utilization sampling are Option D's, unchanged -- they are
    construction-independent, and re-implementing them would mean two copies of
    the measured path drifting apart. Three things had to be true for that to
    work, and each was checked before this class was written:

    * ``FogSearchNode`` holds a ``PolicyStateIndexEntry`` without modification,
      because ``DynamicSearchIndex`` keys on token/cid/policy_id and stores the
      entry opaquely.
    * ``C_j^sync`` still resolves. It is the count of query-relevant authorities
      the node lags (``|{(ID_k,v_k) in V_Q : v_{j,k} < v_k}|``), and ``V_Q``
      comes from the AIM decision the trace already carries, so the four terms of
      eq:search-cost are unaffected by the construction swap.
    * Entries and a loaded index both pickle, so the fork boundary is safe.
      Pinned by ``test_psa_exp2_survives_the_multiprocess_replay_boundary``.

    **What it should show.** A request under ``T = H(w ‖ PID ‖ PV ‖ Dom)``
    carries ``q·|P_U|`` tokens where Option D's carries ``q``, so each unit of
    work is heavier and throughput must fall. That is the cost of D1 on the
    online path, and Exp. 8 shows whether it also changes how the load spreads.
    """

    def prepare(self, value: Any) -> Any:
        concurrency = int(value)
        record_count = max(
            1, int(self.config.defaults.index_size) // self.source.keywords_per_record
        )
        # Option D's deployment supplies the INFRASTRUCTURE -- authorities, AIM,
        # ledger, FSN set, and the record population `_population` reads. Only
        # the indexed entries and the trace's tokens are swapped below.
        deployment = experiments_mod.build_deployment(
            config=self.config, source=self.source, records=record_count
        )

        authorities = _authorities(deployment.domains)
        roster = sorted(authorities.values())
        world = _World(
            domains=tuple(deployment.domains),
            authorities=authorities,
            governance=psa_gov.PolicyGovernance.from_domains(authorities),
            versions={a: 1 for a in roster},
            commitments={a: bytes([i + 1]) * 32 for i, a in enumerate(roster)},
            policies=tuple(sorted({
                r["record"].policy_id for r in deployment.records
            })),
        )
        scheme = _keyed_scheme()

        # REPLACE the shard contents. The nodes keep their identity, domains,
        # queues and authorization state -- what changes is the construction
        # whose entries they serve.
        for node in deployment.nodes:
            node.index = dsi_mod.DynamicSearchIndex.from_config(
                sorted(node.domains), self.config
            )
        for entry in deployment.records:
            record = entry["record"]
            pv = world.pv(record.policy_id)
            psa_entries = [
                psa_records.PolicyStateIndexEntry(
                    token=scheme.index_token(
                        kw, policy_id=record.policy_id, pv=pv, domain=record.domain
                    ),
                    cid=entry["cid"], policy_id=record.policy_id, pv=pv,
                )
                for kw in record.keywords
            ]
            entry["psa_entries"] = psa_entries
            for node in deployment.nodes:
                if node.serves_domain(record.domain):
                    node.index.insert_record(psa_entries, domain=record.domain)

        population = self._population(deployment)
        by_domain: Dict[str, List[Any]] = {d: [] for d in deployment.domains}
        for entry in deployment.records:
            by_domain[entry["record"].domain].append(entry)

        requests = []
        for index in range(concurrency):
            profile, authority_ids, attributes, resolver, subset = (
                population[index % len(population)]
            )
            domain = subset[index % len(subset)]
            pool_for_domain = by_domain[domain]
            if not pool_for_domain:
                continue
            record = pool_for_domain[index % len(pool_for_domain)]
            option_d_token = token_mod.generate_search_token(
                deployment.scheme, profile, [record["record"].keywords[0]]
            )
            decision = authz_mod.verify_search_request(
                deployment.aim, option_d_token, profile,
                authority_ids=authority_ids, attributes=attributes,
                resolver=resolver,
            )
            if not decision.accepted:
                continue
            # q * |P_U|: one token per (keyword, authorized policy). |P_U| is
            # the authorized shard set the AIM just resolved, so the count is
            # the user's real authorization scope rather than a chosen number.
            scopes = [
                psa_tokens.PolicyScopedQuery(
                    policy_id=policy, domain=dom, pv=world.pv(policy)
                )
                for dom, policy in decision.authorized_shards
            ]
            # THE SAME KEYWORD SET Option D's trace uses, so the only
            # difference between the two arms is the construction. Both are now
            # q per global.yaml; when that was q=5 here and 1 there, the resulting
            # "PSA is 1.38x faster" was the workload mismatch, not a result.
            keywords = list(dict.fromkeys(record["record"].keywords))[
                : self.config.defaults.keywords_per_query
            ]
            psa_query = psa_tokens.generate_query_tokens(scheme, keywords, scopes)
            grouped = tuple(
                (
                    psa_tokens.generate_query_tokens(scheme, keywords, [scope]),
                    ((scope.domain, scope.policy_id),),
                )
                for scope in scopes
            )
            requests.append((
                _PsaTrapdoor(
                    tokens=psa_query, vid_u=option_d_token.vid_u, groups=grouped
                ),
                decision,
            ))
        requests = tuple(requests)
        self._ramp(deployment, requests, concurrency)
        return dict(
            deployment=deployment, requests=requests, concurrency=concurrency
        )


@dataclass
class PsaExp7Throughput(PsaSchedulerAblation, experiments_mod.Exp7Throughput):
    """Exp. 7 under the PSA construction."""

    name: str = "exp7_search_throughput"
    number: int = 7
    CORPUS_BACKED: ClassVar[bool] = True


@dataclass
class PsaExp8LoadBalance(PsaSchedulerAblation, experiments_mod.Exp8LoadBalance):
    """Exp. 8 under the PSA construction."""

    name: str = "exp8_load_balance"
    number: int = 8
    CORPUS_BACKED: ClassVar[bool] = True


#: Registry, mirroring ``experiments.py``'s numbering so a PSA run and an
#: Option D run of the same experiment number are directly comparable.
#: Experiment 4's second arm. Section VI has no Experiment 9; its
#: localization/retention measurement is Fig. 4(b), so it lives here as an
#: arm of Exp. 4 rather than as an experiment the paper does not define.
PSA_EXP4_VARIANTS: Tuple[str, ...] = ("granularity",)

PSA_EXPERIMENTS = {
    1: PsaExp1TokenGeneration,
    2: PsaExp2SearchLatency,
    # 3 is SVI's Fig. 3, which measures LATENCY. The token-count experiment is
    # the D9 companion and moves to 9, mirroring how the Option D track parks
    # the Exp. 4 companion (Exp9VerificationGranularity) at 9 rather than
    # letting a companion occupy a manuscript figure's slot.
    3: PsaExp3CrossDomainLatency,
    4: PsaExp4Verification,
    5: PsaExp5ReTokenization,
    6: PsaExp6AffectedRatio,
    7: PsaExp7Throughput,
    8: PsaExp8LoadBalance,
    # 10, NOT 9: in the Option D track 9 is Exp9VerificationGranularity, and
    # giving the same number two different meanings across constructions would
    # make `--experiment 9` mean one thing and `--experiment 9 --construction
}


def build(
    number: int, config: scheme_config.Configuration, *, variant: str = "",
    source=None,
):
    """Instantiate the PSA experiment for ``number``."""
    if number not in PSA_EXPERIMENTS:
        raise KeyError(
            f"no policy-state-aware experiment {number}; D6-D9 cover "
            f"{sorted(PSA_EXPERIMENTS)} — see the divergence notes and the "
            f"scope note in this module's docstring"
        )
    cls = PSA_EXPERIMENTS[number]
    if getattr(cls, "CORPUS_BACKED", False):
        if source is None:
            raise ValueError(
                f"psa experiment {number} reads the corpus and needs a record "
                f"source; pass the same one build_deployment is given"
            )
        # Exp. 1 is corpus-backed AND has an arm: |P_U| is the variant. This
        # branch used to drop `variant` on the floor, so every arm would have
        # been built at the default |P_U| = 1 and four identical curves written
        # to four directories.
        if number == 1 and variant:
            return cls(
                config=config, source=source,
                policy_scope=policy_scope_of(variant),
            )
        # Exp. 4's two arms: the default r sweep is Fig. 4(a), the
        # `granularity` t sweep is Fig. 4(b). One experiment, one figure.
        if number == 4 and variant == "granularity":
            return PsaExp4Granularity(config=config, source=source)
        # Exp. 7-8's arm IS the scheduler. Same defect as Exp. 1's above, and it
        # survived the fix there because 7 and 8 are CORPUS_BACKED and fell
        # through to the variant-less return: `--variant all` built four
        # experiments that were all `aass`, ran the same scheduler four times,
        # and wrote the four results to no_lb/round_robin/least_loaded/aass
        # directories. Measured 2026-09-12 on the campaign host, that produced
        # four throughput curves agreeing inside their CIs and
        # `cross_node_forwards = 0` in every arm -- the signature of AASS, whose
        # eligibility guard never misplaces a shard, reported as if it were the
        # oblivious arms' behaviour too. Fig. 8(c) was therefore measuring one
        # scheduler against itself.
        if number in (7, 8) and variant:
            return cls(config=config, source=source, variant=variant)
        # Exp. 6 became CORPUS_BACKED on 2026-09-12, which moved it into THIS
        # branch. Its DIAS propagation arm must still be carried through, or the
        # move would have reintroduced the 7-8 defect on a third experiment:
        # three arms built at the default, written to three directories.
        if number == 6 and variant:
            return cls(config=config, source=source, variant=variant)
        return cls(config=config, source=source)
    if number == 1 and variant:
        return cls(config=config, policy_scope=policy_scope_of(variant))
    if number == 6:
        # Exp. 6 is the one arm that takes a source WITHOUT being CORPUS_BACKED:
        # it uses the corpus vocabulary but stipulates its policy topology, so
        # it must not inherit corpus provenance. See `policy_population`.
        if variant:
            return cls(config=config, variant=variant, source=source)
        return cls(config=config, source=source)
    return cls(config=config)


__all__ = [
    "AFFECTED_RATIOS",
    "PSA_EXP1_VARIANTS",
    "policy_scope_of",
    "POLICY_SCOPES",
    "PSA_EXP6_VARIANTS",
    "PSA_EXPERIMENTS",
    "PsaExp1TokenGeneration",
    "PsaExp2SearchLatency",
    "PsaExp3CrossDomainLatency",
    "PsaExp4Granularity",
    "PSA_EXP4_VARIANTS",
    "PsaExp4Verification",
    "PsaExp5ReTokenization",
    "PsaExp6AffectedRatio",
    "VARIANT_DIAS",
    "VARIANT_FULL_STATE",
    "VARIANT_INCREMENTAL_ALL",
    "build",
    "build_world",
    "corpus_world",
    "EXP1_SAMPLE_RECORDS",
    "psa_build_deployment",
    "PsaDeployment",
]
