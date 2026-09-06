"""D6-D9 — the experiments the manuscript's construction calls for.

``MANUSCRIPT_DIVERGENCE.md`` D7-D9 are experiment-design divergences and D6 is a
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
deciding whether to adopt D1-D5, not for quoting in §V.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import merkle  # noqa: E402
from Common.timing import gc_quiesced  # noqa: E402

from .. import config as scheme_config  # noqa: E402
from ..psa import commit as psa_commit  # noqa: E402
from ..psa import governance as psa_gov  # noqa: E402
from ..psa import records as psa_records  # noqa: E402
from ..psa import state as psa_state  # noqa: E402
from ..psa import tokens as psa_tokens  # noqa: E402
from .runner import MetricSpec, Sample  # noqa: E402

MS = "ms"
COUNT = "count"
KB = "KB"
BYTES = "B"

#: Domains, matching ``global.yaml: defaults.domains``. One AA each, as
#: ``authority_to_domain: one_to_one`` requires.
DOMAIN_NAMES = ("emergency", "hospital", "laboratory", "research")

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
# D7 — Exp. 1 over q AND |P_U|
# ===========================================================================
#: ``|P_U| ∈ {1,2,4,8}`` — the manuscript's Exp. 1 authorization scope.
POLICY_SCOPES: Tuple[int, ...] = (1, 2, 4, 8)


@dataclass
class PsaExp1TokenGeneration:
    """"the number of generated tokens is ``|T_Q| = q|P_U|``" — manuscript Exp. 1.

    The manuscript sweeps two variables; the runner takes one. So the sweep
    value is an INDEX into :attr:`pairs`, the ``(q, |P_U|)`` combinations in
    ascending ``q·|P_U|``, and the quantities that matter are reported as
    secondaries: ``tokens`` is ``|T_Q|``, alongside ``keywords`` (``q``) and
    ``policies`` (``|P_U|``). :meth:`label` renders a point as ``q=…, |P_U|=…``.

    ``|T_Q|`` is deliberately NOT the sweep value even though it is the quantity
    ``tab:cost``'s ``O(|T_Q|)T_H`` is about, because it is not injective:
    ``|T_Q| = 20`` is ``q=20,|P_U|=1`` and ``q=10,|P_U|=2`` and ``q=5,|P_U|=4``.
    Collapsing those onto one x would average across three different queries and
    destroy the only thing this experiment can actually settle — whether the
    cost depends on the PRODUCT alone, as the manuscript's identity asserts, or
    on how the product is factored. Keeping them as separate points is what lets
    the figure show that they coincide (or that they do not).
    """

    config: scheme_config.Configuration
    name: str = "psa_exp1_token_generation"
    number: int = 1
    variable: str = "scope_index"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("tokens", COUNT),
        MetricSpec("keywords", COUNT),
        MetricSpec("policies", COUNT),
        MetricSpec("token_bytes", BYTES),
    )
    #: ``(q, |P_U|)`` pairs, in ascending ``q·|P_U|``.
    pairs: Tuple[Tuple[int, int], ...] = ()

    def __post_init__(self) -> None:
        if not self.pairs:
            keyword_counts = tuple(self.config.experiment("exp1").values)
            self.pairs = tuple(
                sorted(
                    ((q, p) for q in keyword_counts for p in POLICY_SCOPES),
                    key=lambda qp: (qp[0] * qp[1], qp[0]),
                )
            )
        if not self.values:
            self.values = tuple(range(len(self.pairs)))

    def prepare(self, value: Any) -> Any:
        q, policy_count = self.pairs[int(value)]
        # Enough domains and policies to supply |P_U| distinct authorized
        # policies without repeating one -- repeating would collapse distinct
        # tokens and understate |T_Q|.
        per_domain = -(-policy_count // len(DOMAIN_NAMES)) or 1
        world = build_world(policies_per_domain=max(per_domain, 1))
        scopes = [world.scope(p) for p in world.policies[:policy_count]]
        if len(scopes) != policy_count:
            raise RuntimeError(
                f"needed {policy_count} distinct policies, built {len(scopes)}"
            )
        return dict(
            scheme=_keyed_scheme(),
            keywords=[f"kw:{i:05d}" for i in range(q)],
            scopes=scopes,
            q=q,
            policies=policy_count,
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

    def label(self, value: Any) -> str:
        q, p = self.pairs[int(value)]
        return f"q={q}, |P_U|={p}"


# ===========================================================================
# D9 — trapdoors a cross-domain query must issue
# ===========================================================================
@dataclass
class PsaExp3CrossDomainTokens:
    """What Exp. 3's ``trapdoors_issued`` becomes under this construction.

    ``Exp3CrossDomain`` reports a constant ``1.0``: Option D's token is
    ``H(w)``, so one trapdoor serves every domain. Under eq:policy-bound-token
    a token names its domain and policy state, so a query spanning ``d`` domains
    must issue a token per ``(keyword, authorized policy)`` — and the count
    grows with ``d`` instead of staying flat.

    This experiment reports that count directly. It is the measurement behind
    D9's claim that the single-trapdoor property does not survive the
    manuscript's token, and the reason the manuscript's own Exp. 3 no longer
    states it.
    """

    config: scheme_config.Configuration
    name: str = "psa_exp3_crossdomain_tokens"
    number: int = 3
    variable: str = "domains"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("tokens_issued", COUNT),
        MetricSpec("policies", COUNT),
        MetricSpec("option_d_tokens_issued", COUNT),
    )

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp3").values)

    def prepare(self, value: Any) -> Any:
        domain_count = int(value)
        world = build_world(domains=domain_count, policies_per_domain=1)
        keywords = [f"kw:{i:05d}" for i in range(self.config.defaults.keywords_per_query)]
        return dict(
            scheme=_keyed_scheme(),
            keywords=keywords,
            scopes=[world.scope(p) for p in world.policies],
            domains=domain_count,
        )

    def measure(self, prepared: Any) -> Sample:
        with gc_quiesced():
            started = time.perf_counter_ns()
            produced = psa_tokens.generate_query_tokens(
                prepared["scheme"], prepared["keywords"], prepared["scopes"]
            )
            elapsed = time.perf_counter_ns() - started
        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "tokens_issued": float(len(produced)),
                "policies": float(len(prepared["scopes"])),
                # The comparison the panel exists to make: Option D issues one
                # trapdoor whatever d is (Exp3CrossDomain's headline secondary).
                "option_d_tokens_issued": 1.0,
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
    ``PHASE_IV_PLAN.md`` §1.3's ~9.0M-entry estimate is the thing they settle.
    """

    config: scheme_config.Configuration
    name: str = "psa_exp5_retokenization"
    number: int = 5
    variable: str = "keyword_document_pairs"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("entries_retokenized", COUNT),
        MetricSpec("merkle_nodes_recomputed", COUNT),
        MetricSpec("commitments_rebuilt", COUNT),
    )
    #: Keywords per record, matching the frozen corpus's mean |W_i|.
    keywords_per_record: int = 6

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp5").values)

    def prepare(self, value: Any) -> Any:
        pairs = int(value)
        world = build_world()
        record_count = max(1, -(-pairs // self.keywords_per_record))
        scheme = _keyed_scheme()
        records: List[Dict[str, Any]] = []
        for rid in range(record_count):
            policy = world.policies[rid % len(world.policies)]
            domain = policy.split("/", 1)[0]
            pv = world.pv(policy)
            cid = f"bafyPSA{rid:08d}"
            keywords = [
                f"kw:{(rid * self.keywords_per_record + k) % 2006:05d}"
                for k in range(self.keywords_per_record)
            ]
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
    ones §V names:

    ``dias``            evolve only dependent policies and deliver only to FSNs
                        holding an affected shard.
    ``incremental_all`` evolve only dependent policies, deliver to every FSN.
    ``full_state``      re-evolve every policy and deliver to every FSN.

    The prediction the figure is meant to test is in §V: the DIAS advantage
    "narrows" as the ratio approaches 100%, because at 100% every policy is
    dependency-relevant and the first two arms coincide.
    """

    config: scheme_config.Configuration
    name: str = "psa_exp6_affected_ratio"
    number: int = 6
    variable: str = "affected_policy_ratio"
    values: Tuple[Any, ...] = AFFECTED_RATIOS
    variant: str = VARIANT_DIAS
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("policies_evolved", COUNT),
        MetricSpec("entries_retokenized", COUNT),
        MetricSpec("delivered_kb", KB),
        MetricSpec("fsns_touched", COUNT),
    )
    #: Policy population. Large enough that a 10% step is a whole number.
    policy_population: int = 40
    keywords_per_record: int = 6
    fog_search_nodes: int = 4

    def __post_init__(self) -> None:
        if self.variant not in PSA_EXP6_VARIANTS:
            raise ValueError(
                f"unknown PSA Exp. 6 variant {self.variant!r}; "
                f"valid: {', '.join(PSA_EXP6_VARIANTS)}"
            )

    def prepare(self, value: Any) -> Any:
        ratio = float(value)
        per_domain = self.policy_population // len(DOMAIN_NAMES)
        world = build_world(policies_per_domain=per_domain)
        policies = list(world.policies)
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
        for rid, policy in enumerate(policies):
            domain = policy.split("/", 1)[0]
            pv = world.pv(policy)
            cid = f"bafyPSA{rid:08d}"
            keywords = [f"kw:{rid:04d}:{k}" for k in range(self.keywords_per_record)]
            records.append(
                dict(
                    cid=cid, policy=policy, domain=domain, keywords=keywords,
                    pv=pv,
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
        return dict(
            world=world, scheme=scheme, records=records, moved=moved,
            affected_count=affected_count,
        )

    def measure(self, prepared: Any) -> Sample:
        world = prepared["world"]
        scheme = prepared["scheme"]
        moved = prepared["moved"]
        bumped = {**world.versions, moved: world.versions[moved] + 1}
        full_state = self.variant == VARIANT_FULL_STATE
        selective = self.variant == VARIANT_DIAS

        evolved = 0
        retokenized = 0
        delivered_bytes = 0
        touched = 0

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

                # The delta actually put on the wire: the new entries plus the
                # authenticated metadata. Measured from the real encodings, not
                # derived as size x fan-out -- the mistake `experiments.py`
                # documents for the Option D Exp. 6.
                payload = sum(len(e.encode()) for e in fresh)
                payload += len(commitment.meta.encode())
                # Selective delivery reaches the one FSN holding the domain's
                # shard; the other two arms reach every node.
                fan_out = 1 if selective else self.fog_search_nodes
                delivered_bytes += payload * fan_out
                touched += fan_out
            elapsed = time.perf_counter_ns() - started

        return Sample(
            primary=elapsed / 1e6,
            secondaries={
                "policies_evolved": float(evolved),
                "entries_retokenized": float(retokenized),
                "delivered_kb": delivered_bytes / 1024.0,
                "fsns_touched": float(touched),
            },
        )


#: Registry, mirroring ``experiments.py``'s numbering so a PSA run and an
#: Option D run of the same experiment number are directly comparable.
PSA_EXPERIMENTS = {
    1: PsaExp1TokenGeneration,
    3: PsaExp3CrossDomainTokens,
    5: PsaExp5ReTokenization,
    6: PsaExp6AffectedRatio,
}


def build(number: int, config: scheme_config.Configuration, *, variant: str = ""):
    """Instantiate the PSA experiment for ``number``."""
    if number not in PSA_EXPERIMENTS:
        raise KeyError(
            f"no policy-state-aware experiment {number}; D6-D9 cover "
            f"{sorted(PSA_EXPERIMENTS)} — see MANUSCRIPT_DIVERGENCE.md and the "
            f"scope note in this module's docstring"
        )
    cls = PSA_EXPERIMENTS[number]
    if number == 6 and variant:
        return cls(config=config, variant=variant)
    return cls(config=config)


__all__ = [
    "AFFECTED_RATIOS",
    "POLICY_SCOPES",
    "PSA_EXP6_VARIANTS",
    "PSA_EXPERIMENTS",
    "PsaExp1TokenGeneration",
    "PsaExp3CrossDomainTokens",
    "PsaExp5ReTokenization",
    "PsaExp6AffectedRatio",
    "VARIANT_DIAS",
    "VARIANT_FULL_STATE",
    "VARIANT_INCREMENTAL_ALL",
    "build",
    "build_world",
]
