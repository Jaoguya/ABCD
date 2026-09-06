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
from typing import Any, ClassVar, Dict, List, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from Common.crypto import hashes, merkle  # noqa: E402
from Common.timing import gc_quiesced  # noqa: E402

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


#: One arm per ``|P_U|``, so the figure renders §V's two-variable sweep the way
#: §V states it: "q is varied as {1,5,10,15,20}, WHILE |P_U| is varied as
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

    §V varies ``q ∈ {1,5,10,15,20}`` while varying ``|P_U| ∈ {1,2,4,8}``. The
    runner sweeps one variable, so ``q`` is the sweep and ``|P_U|`` is the ARM:
    one run per scope, written to ``psa_exp1_token_generation__pu<N>/``, drawn
    as one curve each. ``|T_Q| = q·|P_U|`` is checked on every sample rather
    than assumed, and reported as the ``tokens`` secondary.

    WHY THIS CANNOT LIVE ON THE IMPLEMENTED SCHEME
    ----------------------------------------------
    ``index/tokens.py``'s ``generate_trapdoor(scheme, keywords)`` takes no
    policy argument at all: Option D's token is ``H(w)``, so ``|T_Q| = q``
    whatever ``|P_U|`` is and the second dimension is structurally inert. §V's
    Exp. 1 is a measurement OF the policy-bound token (D1), which is why it is
    here and not in ``experiments.py``. That is divergence D7.
    """

    config: scheme_config.Configuration
    name: str = "psa_exp1_token_generation"
    number: int = 1
    variable: str = "keywords"
    values: Tuple[Any, ...] = ()
    #: ``|P_U|`` — how many authorized policies this arm derives tokens under.
    policy_scope: int = 1
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
        if not self.values:
            self.values = tuple(self.config.experiment("exp1").values)

    def prepare(self, value: Any) -> Any:
        q = int(value)
        # Enough domains and policies to supply |P_U| DISTINCT authorized
        # policies. Repeating one would collapse distinct tokens and understate
        # |T_Q| -- the identity this experiment exists to check.
        per_domain = max(1, -(-self.policy_scope // len(DOMAIN_NAMES)))
        world = build_world(policies_per_domain=per_domain)
        scopes = [world.scope(p) for p in world.policies[: self.policy_scope]]
        if len(scopes) != self.policy_scope:
            raise RuntimeError(
                f"needed {self.policy_scope} distinct policies, "
                f"built {len(scopes)}"
            )
        return dict(
            scheme=_keyed_scheme(),
            keywords=[f"kw:{i:05d}" for i in range(q)],
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
        scheme = _keyed_scheme()
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
            if moved in world.governance.governing(policy):
                affected_entries += self.keywords_per_record
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

        # AUTHORIZATION-STATE REDISTRIBUTION, the other half of what §V calls
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
                "policies_evolved": float(evolved),
                "entries_retokenized": float(retokenized),
                "delivered_kb": delivered_bytes / 1024.0,
                # DISTINCT nodes, which is what `F_k^aff` is and what Option D's
                # metric of the same name means. Accumulating fan-out per record
                # instead reported 160 "FSNs touched" on a 4-node deployment.
                "fsns_touched": float(len(reached)),
            },
        )


# ===========================================================================
# D3 — Exp. 4 under the policy-state-aware commitment
# ===========================================================================
def _psa_batched_chain_checker(anchors: Dict[str, bytes], cids: Sequence[str]):
    """Phase VIII Step 3 for a whole response, anchors fetched ONCE.

    Same shape as ``verify/ledger.py::batched_chain_checker`` and for the same
    reason: a per-record namespace walk made Option D's Step 3 O(r^2) and 99.6%
    of the step's cost. The fetch is LAZY -- it happens on the first bundle
    checked, inside whatever region the caller is timing -- so the harness
    cannot make the cost vanish by resolving anchors in an untimed ``prepare``.
    Its whole cost is charged to the first record, which is right: a client
    pays it once per response.
    """
    resolved: Dict[str, bytes] = {}
    done = [False]

    def check(bundle) -> psa_verify.StepResult:
        if not done[0]:
            resolved.update({cid: anchors[cid] for cid in cids if cid in anchors})
            done[0] = True
        anchored = resolved.get(bundle.cid)
        if anchored is None:
            return psa_verify.StepResult(
                "chain", False, f"no anchor for {bundle.cid}"
            )
        return psa_verify.StepResult(
            "chain",
            hashes.constant_time_equal(anchored, bundle.meta.commit),
            "" if anchored == bundle.meta.commit else "Commit_i is not the anchored one",
        )

    return check


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

    #: Phase VIII Step 3 runs against an IN-PROCESS anchor map, not a chain.
    #: The banked Option D Exp. 4 ran against real Hyperledger Fabric
    #: (`5ee7c16`, "like-for-like axis against real Fabric"), so the two
    #: numbers are NOT comparable: at r=1000 Option D measures 1675.34 ms and
    #: this measures 16.86 ms, and essentially all of that ~99x is the ledger
    #: backend rather than the construction. Stamped into `run_meta.json` so a
    #: reader cannot put the two curves on one axis by accident.
    LEDGER_BACKEND: ClassVar[str] = "in_process_anchor_map"

    config: scheme_config.Configuration
    name: str = "psa_exp4_verification_overhead"
    number: int = 4
    variable: str = "returned_results"
    values: Tuple[Any, ...] = ()
    primary: MetricSpec = MetricSpec("latency", MS, is_timing=True)
    secondaries: Tuple[MetricSpec, ...] = (
        MetricSpec("proof_size", KB),
        MetricSpec("path_length", COUNT),
        MetricSpec("records_verified", COUNT),
    )
    keywords_per_record: int = 6

    def __post_init__(self) -> None:
        if not self.values:
            self.values = tuple(self.config.experiment("exp4").values)

    def prepare(self, value: Any) -> Any:
        wanted = int(value)
        world = build_world()
        scheme = _keyed_scheme()
        bundles = []
        anchors: Dict[str, bytes] = {}
        for rid in range(wanted):
            policy = world.policies[rid % len(world.policies)]
            domain = policy.split("/", 1)[0]
            pv = world.pv(policy)
            cid = f"bafyPSA{rid:08d}"
            entries = [
                psa_records.PolicyStateIndexEntry(
                    token=scheme.index_token(
                        f"kw:{rid:05d}:{k}", policy_id=policy, pv=pv, domain=domain
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
            anchors[cid] = commitment.commit
        return dict(
            bundles=tuple(bundles), anchors=anchors,
            cids=[b.cid for b in bundles],
        )

    def measure(self, prepared: Any) -> Sample:
        bundles = prepared["bundles"]
        checker = _psa_batched_chain_checker(prepared["anchors"], prepared["cids"])
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


#: Registry, mirroring ``experiments.py``'s numbering so a PSA run and an
#: Option D run of the same experiment number are directly comparable.
PSA_EXPERIMENTS = {
    1: PsaExp1TokenGeneration,
    3: PsaExp3CrossDomainTokens,
    4: PsaExp4Verification,
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
    if number == 1 and variant:
        return cls(config=config, policy_scope=policy_scope_of(variant))
    if number == 6 and variant:
        return cls(config=config, variant=variant)
    return cls(config=config)


__all__ = [
    "AFFECTED_RATIOS",
    "PSA_EXP1_VARIANTS",
    "policy_scope_of",
    "POLICY_SCOPES",
    "PSA_EXP6_VARIANTS",
    "PSA_EXPERIMENTS",
    "PsaExp1TokenGeneration",
    "PsaExp3CrossDomainTokens",
    "PsaExp4Verification",
    "PsaExp5ReTokenization",
    "PsaExp6AffectedRatio",
    "VARIANT_DIAS",
    "VARIANT_FULL_STATE",
    "VARIANT_INCREMENTAL_ALL",
    "build",
    "build_world",
]
