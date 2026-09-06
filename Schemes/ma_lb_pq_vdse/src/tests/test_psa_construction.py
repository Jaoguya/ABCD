"""D1-D5 — the manuscript's construction, pinned claim by claim.

Every test here names the divergence and the manuscript equation it enforces, so
that if `Overleaf/MA-LB-PQ-VDSE.tex` changes again the failure says which
published formula moved rather than merely that a digest differs.

The two theorems this file exists to make executable:

* **Policy-State Token Consistency** — the index token and the query token are
  equal exactly when keyword, policy, domain and policy state agree.
* **Policy-State Non-Interference** — ``AA_k ∉ AA(PID_i) ⟹ PV_i' = PV_i``
  (eq:unaffected-policy), and therefore the token and the entry are unchanged.

Both are proved in the paper over the *set* ``AA(PID_i)``. They are only
non-vacuous when that set is a proper, non-empty subset of the roster, which is
why ``PolicyGovernance`` defaults to 2-of-4 and why the fixtures below never use
a singleton — see ``psa/governance.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

import pytest  # noqa: E402

from Schemes.ma_lb_pq_vdse.src.psa import (  # noqa: E402
    commit as psa_commit,
    governance as psa_gov,
    records as psa_records,
    state as psa_state,
    tokens as psa_tokens,
)

DOMAINS = {"emergency": "AA1", "hospital": "AA2", "laboratory": "AA3", "research": "AA4"}
AUTHORITIES = tuple(sorted(DOMAINS.values()))
KEY = b"k" * 32


@pytest.fixture
def governance():
    return psa_gov.PolicyGovernance.from_domains(DOMAINS)


@pytest.fixture
def versions():
    return {a: 3 for a in AUTHORITIES}


@pytest.fixture
def commitments():
    return {a: bytes([i + 1]) * 32 for i, a in enumerate(AUTHORITIES)}


@pytest.fixture
def scheme():
    return psa_tokens.PolicyStateTokenScheme.keyed(KEY)


def _pv(versions, governance, policy_id):
    return psa_state.PolicyVersionState.build(
        versions, governance.governing(policy_id)
    ).digest()


# ===========================================================================
# Governance — AA(PID_i)
# ===========================================================================
def test_governing_set_is_a_proper_nonempty_subset(governance):
    """A singleton or the whole roster makes one half of the claim vacuous."""
    policies = [f"{d}/pol{i}" for d in DOMAINS for i in range(3)]
    for policy in policies:
        governing = governance.governing(policy)
        assert 0 < len(governing) < len(AUTHORITIES), (
            f"AA({policy}) = {governing}: with a singleton there is no unrelated "
            f"authority for non-interference to exclude, and with the full "
            f"roster there is no unaffected policy for DIAS to skip"
        )


def test_a_policy_is_always_governed_by_its_own_domain_authority(governance):
    for domain, authority in DOMAINS.items():
        assert authority in governance.governing(f"{domain}/pol0")


def test_governing_set_is_sorted_and_deterministic(governance):
    """PV_i is a hash over V_P, so an unstable order is an unstable digest."""
    for policy in (f"{d}/pol{i}" for d in DOMAINS for i in range(3)):
        first = governance.governing(policy)
        assert first == tuple(sorted(first))
        assert first == governance.governing(policy)
        # A fresh instance must agree: the AIM and an FSN build their own.
        assert first == psa_gov.PolicyGovernance.from_domains(DOMAINS).governing(policy)


def test_governing_set_has_exactly_the_requested_size(governance):
    for k in (1, 2, 3, 4):
        g = psa_gov.PolicyGovernance.from_domains(DOMAINS, authorities_per_policy=k)
        assert len(g.governing("hospital/pol0")) == k


def test_authorities_per_policy_beyond_the_roster_is_refused():
    with pytest.raises(psa_gov.GovernanceError, match="roster size"):
        psa_gov.PolicyGovernance.from_domains(DOMAINS, authorities_per_policy=5)


def test_overrides_state_the_set_outright(governance):
    """Exp. 6 dials the affected ratio; the hash draw cannot be asked for one."""
    policies = [f"hospital/pol{i}" for i in range(10)]
    stated = {p: ("AA1",) for p in policies[:3]}
    stated.update({p: ("AA2",) for p in policies[3:]})
    dialled = governance.with_overrides(stated)
    affected = dialled.affected_policies("AA1", policies)
    assert len(affected) / len(policies) == pytest.approx(0.3)


def test_an_empty_stated_governing_set_is_refused(governance):
    with pytest.raises(psa_gov.GovernanceError, match="empty"):
        governance.with_overrides({"hospital/pol0": ()}).governing("hospital/pol0")


# ===========================================================================
# D2 — V_P and PV  (eq:policy-version-state, eq:policy-version-digest)
# ===========================================================================
def test_policy_version_state_covers_only_the_governing_authorities(
    governance, versions
):
    policy = "hospital/pol0"
    governing = governance.governing(policy)
    state = psa_state.PolicyVersionState.build(versions, governing)
    assert state.authority_ids == governing
    assert len(state.versions) < len(AUTHORITIES), "V_P must exclude non-governors"


def test_pv_is_order_independent(governance, versions):
    """Two honest parties enumerating AA(PID) differently must agree on PV_i."""
    governing = governance.governing("hospital/pol0")
    forward = psa_state.PolicyVersionState.build(versions, governing)
    backward = psa_state.PolicyVersionState.build(versions, tuple(reversed(governing)))
    assert forward.digest() == backward.digest()


def test_unsorted_state_is_refused():
    with pytest.raises(psa_state.PolicyStateError, match="sorted"):
        psa_state.PolicyVersionState(versions=(("AA2", 1), ("AA1", 1)))


def test_a_missing_governing_version_is_refused_not_defaulted(governance):
    """A stale FSN must not be able to synthesise a matching PV_i."""
    governing = governance.governing("hospital/pol0")
    partial = {governing[0]: 3}
    with pytest.raises(psa_state.PolicyStateError, match="no version known"):
        psa_state.PolicyVersionState.build(partial, governing)


def test_empty_governing_set_is_refused():
    with pytest.raises(psa_state.PolicyStateError, match="at least one"):
        psa_state.PolicyVersionState(versions=())


# ===========================================================================
# D1 — the token  (eq:policy-bound-token, eq:query-token)
# ===========================================================================
def test_index_and_query_tokens_are_equal(scheme, governance, versions):
    """Theorem "Policy-State Token Consistency", as an equality not a claim."""
    policy, domain = "hospital/pol0", "hospital"
    pv = _pv(versions, governance, policy)
    assert scheme.index_token(
        "cond:af", policy_id=policy, pv=pv, domain=domain
    ) == scheme.query_token("cond:af", policy_id=policy, pv=pv, domain=domain)


@pytest.mark.parametrize("field", ["keyword", "policy_id", "pv", "domain"])
def test_every_token_input_changes_the_token(field, scheme, governance, versions):
    """All four inputs of eq:policy-bound-token must be live."""
    base = dict(
        keyword="cond:af", policy_id="hospital/pol0",
        pv=_pv(versions, governance, "hospital/pol0"), domain="hospital",
    )
    altered = dict(base)
    altered[field] = {
        "keyword": "cond:mi",
        "policy_id": "hospital/pol1",
        "pv": _pv({a: 4 for a in AUTHORITIES}, governance, "hospital/pol0"),
        "domain": "laboratory",
    }[field]
    token = scheme.token(base.pop("keyword"), **base)
    other = scheme.token(altered.pop("keyword"), **altered)
    assert token != other, f"{field} does not affect the token"


def test_token_is_not_domain_independent(scheme, governance, versions):
    """The Option D property that Exp. 3's single-trapdoor claim rested on (D9).

    Under this construction the same keyword under the same policy state yields
    a DIFFERENT token per domain, so one trapdoor cannot serve d domains.
    """
    policy = "hospital/pol0"
    pv = _pv(versions, governance, policy)
    tokens = {
        d: scheme.token("cond:af", policy_id=policy, pv=pv, domain=d)
        for d in DOMAINS
    }
    assert len(set(tokens.values())) == len(DOMAINS)


def test_psa_and_option_d_tokens_never_collide(scheme):
    """Both constructions can live in one process; their tags must separate them."""
    from Schemes.ma_lb_pq_vdse.src.index import tokens as option_d

    legacy = option_d.TokenScheme.keyed(KEY)
    assert legacy.index_token("cond:af") != scheme.token(
        "cond:af", policy_id="hospital/pol0", pv=b"\x01" * 32, domain="hospital"
    )


def test_duplicate_keyword_in_a_query_is_refused(scheme):
    scope = psa_tokens.PolicyScopedQuery(
        policy_id="hospital/pol0", domain="hospital", pv=b"\x01" * 32
    )
    with pytest.raises(psa_tokens.TokenError, match="duplicate keyword"):
        psa_tokens.generate_query_tokens(scheme, ["w", "w"], [scope])


def test_query_token_count_is_q_times_policies(scheme, governance, versions):
    """|T_Q| = q·|P_U| — the manuscript's Exp. 1 identity, and D7's sweep."""
    policies = [f"{d}/pol0" for d in sorted(DOMAINS)]
    scopes = [
        psa_tokens.PolicyScopedQuery(
            policy_id=p, domain=p.split("/")[0], pv=_pv(versions, governance, p)
        )
        for p in policies
    ]
    for q in (1, 5, 10):
        for policy_count in (1, 2, 4):
            produced = psa_tokens.generate_query_tokens(
                scheme, [f"kw:{i}" for i in range(q)], scopes[:policy_count]
            )
            assert len(produced) == q * policy_count
            assert len(set(produced)) == q * policy_count


# ===========================================================================
# Policy-State Non-Interference  (eq:unaffected-policy)
# ===========================================================================
def test_a_non_governing_authority_changes_nothing(scheme, governance, versions):
    policy, domain = "hospital/pol0", "hospital"
    governing = governance.governing(policy)
    outsider = next(a for a in AUTHORITIES if a not in governing)

    before = psa_state.PolicyVersionState.build(versions, governing)
    after = before.advanced(outsider)

    assert after.digest() == before.digest(), "eq:unaffected-policy: PV_i' = PV_i"

    token_before = scheme.token(
        "cond:af", policy_id=policy, pv=before.digest(), domain=domain
    )
    token_after = scheme.token(
        "cond:af", policy_id=policy, pv=after.digest(), domain=domain
    )
    assert token_before == token_after

    entry_before = psa_records.PolicyStateIndexEntry(
        token=token_before, cid="bafyREC1", policy_id=policy, pv=before.digest()
    )
    entry_after = psa_records.PolicyStateIndexEntry(
        token=token_after, cid="bafyREC1", policy_id=policy, pv=after.digest()
    )
    assert entry_before == entry_after, "no index delta for an unrelated update"


def test_a_governing_authority_moves_pv_token_and_entry(scheme, governance, versions):
    """The other half: an update that SHOULD propagate does."""
    policy, domain = "hospital/pol0", "hospital"
    governing = governance.governing(policy)

    before = psa_state.PolicyVersionState.build(versions, governing)
    after = before.advanced(governing[0])

    assert after.digest() != before.digest()
    assert scheme.token(
        "cond:af", policy_id=policy, pv=before.digest(), domain=domain
    ) != scheme.token("cond:af", policy_id=policy, pv=after.digest(), domain=domain)


# ===========================================================================
# D4/D3 — the entry, the root and the commitment
# ===========================================================================
def _record(scheme, governance, versions, commitments,
            policy="hospital/pol0", cid="bafyREC1"):
    domain = policy.split("/")[0]
    governing = governance.governing(policy)
    pv = psa_state.PolicyVersionState.build(versions, governing).digest()
    auth_state = psa_state.PolicyAuthorityState.build(commitments, governing).digest()
    entries = [
        psa_records.PolicyStateIndexEntry(
            token=scheme.token(w, policy_id=policy, pv=pv, domain=domain),
            cid=cid, policy_id=policy, pv=pv,
        )
        for w in ("cond:af", "cond:mi", "obs:ecg", "obs:hr")
    ]
    return psa_commit.commit_record(
        record_id=1, cid=cid, entries=entries,
        policy_id=policy, pv=pv, auth_state=auth_state,
    ), entries


def test_commitment_verifies_and_binds_every_field(
    scheme, governance, versions, commitments
):
    commitment, _ = _record(scheme, governance, versions, commitments)
    assert commitment.meta.verify(), "Commit_i* == Commit_i (Phase VIII Step 2)"

    meta = commitment.meta
    for field, replacement in (
        ("cid", "bafyOTHER"),
        ("policy_id", "hospital/pol1"),
        ("pv", b"\x09" * 32),
        ("root", b"\x08" * 32),
        ("auth_state", b"\x07" * 32),
    ):
        tampered = psa_commit.AuthenticatedMetadata(
            **{**meta.__dict__, field: replacement}
        )
        assert not tampered.verify(), f"substituting {field} was not detected"


def test_merkle_proof_authenticates_each_entry(
    scheme, governance, versions, commitments
):
    from Common.crypto import merkle

    commitment, entries = _record(scheme, governance, versions, commitments)
    for index, entry in enumerate(entries):
        proof = commitment.prove(index)
        # MerkleTree hashes the items it is given, so leaf_hash is
        # hash_leaf(entry.leaf()) -- the same convention index/commit.py uses.
        assert proof.leaf_hash == merkle.hash_leaf(entry.leaf())
        assert merkle.MerkleTree.verify_leaf(entry.leaf(), proof, commitment.root)

    # A proof from one entry must not authenticate another's leaf.
    stolen = commitment.prove(0)
    forged = merkle.MerkleProof(
        leaf_index=stolen.leaf_index, leaf_hash=entries[1].leaf(), path=stolen.path
    )
    assert not merkle.MerkleTree.verify(forged, commitment.root)


def test_an_entry_disagreeing_with_the_record_is_refused(
    scheme, governance, versions, commitments
):
    commitment, entries = _record(scheme, governance, versions, commitments)
    foreign = psa_records.PolicyStateIndexEntry(
        token=entries[0].token, cid="bafyOTHER",
        policy_id=entries[0].policy_id, pv=entries[0].pv,
    )
    with pytest.raises(psa_commit.CommitmentError, match="disagree"):
        psa_commit.commit_record(
            record_id=1, cid=entries[0].cid, entries=[foreign],
            policy_id=entries[0].policy_id, pv=entries[0].pv,
            auth_state=b"\x01" * 32,
        )


def test_commitment_moves_when_a_governing_authority_moves(
    scheme, governance, versions, commitments
):
    """The cost of D3: authority evolution now rewrites Commit_i."""
    before, _ = _record(scheme, governance, versions, commitments)
    governing = governance.governing("hospital/pol0")
    moved = {**commitments, governing[0]: b"\xfe" * 32}
    after, _ = _record(scheme, governance, versions, moved)
    assert after.commit != before.commit


# ===========================================================================
# D5 — the VAP
# ===========================================================================
def test_profile_pairs_versions_with_authorities(versions, commitments):
    profile = psa_records.build_profile(
        uid="DU-1", domains=sorted(DOMAINS), attributes=["AA1:doc"],
        versions=versions, commitments=commitments,
    )
    assert profile.authority_ids == AUTHORITIES
    assert profile.version_of("AA1") == 3
    assert profile.covers(("AA1", "AA2"))


def test_profile_halves_must_cover_the_same_authorities(versions, commitments):
    """Phase VI Step 2 consults both V_U and C_U; disagreement is unresolvable."""
    version_state = psa_state.PolicyVersionState.build(versions, AUTHORITIES)
    short = psa_state.PolicyAuthorityState.build(commitments, AUTHORITIES[:2])
    with pytest.raises(psa_records.RecordError, match="V_U covers"):
        psa_records.PolicyStateProfile(
            uid="DU-1", domains=("hospital",),
            versions=version_state, commitments=short, auth_root=b"\x01" * 32,
        )


def test_auth_root_changes_with_every_component(versions, commitments):
    base = psa_records.build_profile(
        uid="DU-1", domains=sorted(DOMAINS), attributes=["AA1:doc"],
        versions=versions, commitments=commitments,
    )
    variants = {
        "uid": dict(uid="DU-2"),
        "attributes": dict(attributes=["AA1:nurse"]),
        "versions": dict(versions={**versions, "AA1": 4}),
        "commitments": dict(commitments={**commitments, "AA1": b"\xaa" * 32}),
    }
    for name, override in variants.items():
        kwargs = dict(
            uid="DU-1", domains=sorted(DOMAINS), attributes=["AA1:doc"],
            versions=versions, commitments=commitments,
        )
        kwargs.update(override)
        assert psa_records.build_profile(**kwargs).auth_root != base.auth_root, name


def test_attribute_set_order_does_not_change_auth_root(versions, commitments):
    forward = psa_records.build_profile(
        uid="DU-1", domains=sorted(DOMAINS), attributes=["AA1:doc", "AA2:nurse"],
        versions=versions, commitments=commitments,
    )
    reverse = psa_records.build_profile(
        uid="DU-1", domains=sorted(DOMAINS), attributes=["AA2:nurse", "AA1:doc"],
        versions=versions, commitments=commitments,
    )
    assert forward.auth_root == reverse.auth_root
