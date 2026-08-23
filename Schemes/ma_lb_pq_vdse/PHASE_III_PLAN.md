# MA-LB-PQ-VDSE — Phase III Implementation Plan

**Scope:** Phase III — User Registration and Version-Bound Authorization Profile
(VAP) Generation — implemented under `Schemes/ma_lb_pq_vdse/src/`.

**Manuscript source:** `Overleaf/PQ-AVDSE-OJCOMS` — Phase III at `:489`, Step 1
`:493`, Step 2 `:502`, Step 3 `:526`, Step 4 `:549`. Equation text quoted below is
from the pandoc export `PQ-AVDSE-OJCOMS.md:530-651`, which matches the LaTeX for
this phase.

**Timing status:** setup, **not timed** (README §2). Phase III emits no
`raw_runs.csv` / `results.csv`. It contributes exactly one number to the paper —
the ML-KEM session-establishment cost from Step 3 — which the Exp. 1 measurement
rule requires be reported separately, outside the per-query trapdoor curve.

---

## Scope note: this is not the phase the request described

The request described Phase III as "Data Owner Key Generation, Record Sharding,
and Index Shard Generation". The manuscript's Phase III is *User Registration and
Version-Bound Authorization Profile Generation*, and README §2 agrees
("III | User Registration & Version-Bound Authorization Profile"). One of the
three named topics belongs here; the other two are later phases:

| Requested topic | Where it actually is |
|---|---|
| **Data Owner key generation** | **Phase III Steps 2-3** — covered by this plan. The manuscript enrols *both* roles: "each Data Owner (DO) and Data User (DU) enrolls with one or more Attribute Authorities" (`:491`). DO and DU differ in the attributes they receive, not in the key-issuance path. |
| Record sharding | **Phase V Step 4**, Search Infrastructure Synchronization (`:737` ff.) — `Sync_i = (I_i, PID_i, VID_i, CID_i)` "is propagated to the authorized Fog Search Nodes", against the domain-keyed shard assignment in `index.yaml → sharding` (already built in `fsn/fsn.py`). |
| Index shard generation | **Phase IV**, Policy-Bound Dynamic Search Index Construction (`:603` ff.) — keyword extraction, policy-bound token encoding `T_j`, DSI entry construction, batch Merkle commitment, `Commit_i`. |

This plan covers Phase III as published. A `PHASE_IV_V_PLAN.md` covering the other
two topics is the natural next document — say so and it gets written.

---

## 0. Target layout

Additions to the existing tree (`SCHEME.md` maps Phase III to `src/user/`):

```
src/
├── abe/ma_cpabe.py       # + KeyGen(MSK_i, S_{U,i})        Step 2  (Setup already planned)
├── user/
│   ├── __init__.py
│   ├── user.py           # Req_U, KEM keypair, key reception, SK_U assembly
│   └── credentials.py    # Cred validation predicate per authority   Step 1
├── authority/authority.py  # + issue_attribute_key(), deliver_key()  Steps 2-3
├── aim/aim.py            # + VAP construction and storage            Step 4
└── types.py              # + UserRequest, AttributeKeyShare, EncryptedKeyDelivery,
                          #   VersionBoundAuthorizationProfile
```

Everything already established carries over: parameters from
`Experiment Configuration/*.yaml` through `src/config.py`; primitives from
`Common/crypto`; records as frozen dataclasses over `types.canonical`; tests
appended to `src/tests/` in the standalone `ok/SKIP/FAIL` harness.

**Test file split.** `test_phase1_2.py` is at 155 tests. Phase III tests go in a
new `src/tests/test_phase3.py` with the same harness, importing the shared
fixtures rather than duplicating them (the stub group provider and
`phase_i_ii_federation()` are both needed here). One file per phase group keeps a
failure's blast radius readable.

---

## Phase III — step by step

### Step III.1 — User Registration (`:493`)

```
Req_U = (UID, Dom, Role, Cred)
```

"Each participating Attribute Authority independently validates the submitted
credentials according to its local policy."

**Modules:** `user/user.py` (build `Req_U`), `user/credentials.py` +
`authority/authority.py` (validate).

**Decisions.** The manuscript specifies no credential format and no policy
language — only that validation is local and independent. Proposal: `Cred` is an
opaque byte blob plus a role claim, and each authority holds a
`CredentialPolicy` callable mapping `(Role, Dom)` to the attribute subset it is
willing to issue. Default policy: issue the attributes whose role prefix matches
`Role`, refuse otherwise. Marked `benchmark`; it affects no reported number,
because Phase III is untimed and no experiment exercises enrolment.

*Independent* validation is the part worth enforcing in code: each authority must
reach its own verdict from its own policy, with no shared validator object, or
the multi-authority property degenerates into a single trusted gatekeeper — the
thing §III's system model exists to remove.

**Tests** (`test_phase3.py`):

- `Req_U` binds all four fields — changing `UID`, `Dom`, `Role`, or `Cred`
  changes the record's digest.
- Two authorities with different policies reach *different* verdicts on one
  `Req_U`, and neither consults the other.
- An authority refuses a `Role` its policy does not cover, and issues nothing.
- A user's `Dom` must be one of the four corpus domains (`Dataset` / `dataset.yaml`).
- Registration with an unregistered authority (no `Reg_i` on chain) is refused.

### Step III.2 — Multi-Authority Attribute Key Generation (`:502`)

```
S_{U,i} ⊆ A_i
SK_{U,i} ← KeyGen(MSK_i, S_{U,i})
SK_U = ∪_{i=1..N_U} SK_{U,i}
```

**Modules:** `abe/ma_cpabe.py` (`KeyGen`), `authority/authority.py`
(`issue_attribute_key`), `user/user.py` (assemble `SK_U`).

**BLOCKED — the manuscript gives `KeyGen` as an interface only.** It fixes
`MSK_i = (α_i, β_i)` and `PK_i = (g_1, g_2, e(g_1,g_2)^{α_i}, g_1^{β_i})`
(Phase I Step 2) but never defines the structure of `SK_{U,i}` — no key
components, no randomisation, no attribute embedding. AGENT_RULES §2 forbids
guessing a construction, so this needs a decision before the module is written.

The published `(MSK_i, PK_i)` shape is the Rouselakis-Waters (RW15) decentralised
CP-ABE shape, which is the standard Type-III multi-authority instantiation and
the obvious candidate — but "obvious candidate" is not "published", and the
choice determines what `SK_{U,i}` and decryption actually compute.

**What limits the risk:** the ABE layer sits on *no measured path*. Exp. 1 times
trapdoor generation, which is Phase VI Step 1 — `T_Q = {H(w_i ‖ VID_U)}`, pure
hashing, no pairing. Exp. 4 explicitly excludes decryption. Phases III and V are
untimed. So `KeyGen`'s internals affect **no reported number** in §V. They do
affect whether the implemented system is the published scheme, and the security
argument, so the decision still has to be made — it just does not have to be made
before any figure can be produced.

Also blocked on the same missing Type-III pairing backend as Phase I Step 2
(`crypto.yaml`: `backend_implemented: false`). The same injected-seam discipline
applies: no working stub in `src/`, and any key from an unfaithful group inherits
`faithful=False`.

**Tests:**

- `S_{U,i} ⊆ A_i` is enforced — an authority refuses to issue an attribute
  outside its own namespace, which is the Phase II Step 2 disjointness property
  seen from the issuance side.
- `SK_U` is the union over `N_U` authorities, and its share count equals `N_U`.
- Two authorities issuing to one user produce independent shares (distinct
  randomisation).
- The same authority issuing the same attribute set twice produces *different*
  shares — key randomisation is what stops two users colluding by comparing keys.
- `MSK_i` never appears in `SK_{U,i}`, asserted on encoded bytes.
- `KeyGen` with no group operations raises, as Phase I Step 2 does.

### Step III.3 — Post-Quantum Secure Key Delivery (`:526`)

```
(ct_i, ss_i) ← ML-KEM.Encaps(pk_U^KEM)
K_i = HKDF(ss_i)
EncKey_i = AES-256-GCM.Enc(K_i, SK_{U,i})
```

**Modules:** `authority/authority.py` (`deliver_key`), `user/user.py`
(`receive_key`). **Fully implementable today** — `Common/crypto/kem.py` (liboqs
0.16.0), `hashes.hkdf_sha256`, and `symmetric.encrypt` are all verified, and this
step needs no pairing.

**Decisions.**

- The paper writes `HKDF(ss_i)` with no salt or info. Proposal: `info` is the
  length-prefixed `(UID ‖ ID_i ‖ VID_i)` under `crypto.yaml`'s
  `kdf.info_prefix`, so a key derived for one user and authority cannot be
  reused for another. `benchmark` provenance, zero measurable cost, and it
  removes a real ambiguity rather than changing the construction.
- `associated_data` for AES-256-GCM binds `(UID, ID_i, VID_i)`, so an
  `EncKey_i` cannot be replayed to a different user or across a version change.
  Same rationale.
- `pk_U^KEM` is generated by the user in Step 1 and carried in `Req_U`; the
  manuscript introduces it in Step 3 without saying who generates it, and the
  user is the only party that can hold the decapsulation key.

**Observation for the authors — the forward-secrecy claim does not hold.**
`:547` states this mechanism "provides confidentiality, forward secrecy, and
resistance against quantum adversaries". Encapsulating to a *static* user KEM
public key gives no forward secrecy: an adversary who records `ct_i` and later
compromises the user's decapsulation key recovers `ss_i`, hence `K_i`, hence
`SK_{U,i}`. Forward secrecy would need an ephemeral KEM keypair per delivery.
Following the Ref[41] precedent (implement as published, report the observation),
the plan implements the published static-key delivery and records this here
rather than silently substituting an ephemeral variant — which would be
strengthening our own scheme beyond what it claims.

**Tests:**

- Round trip: the user recovers `SK_{U,i}` byte-for-byte from `(ct_i, EncKey_i)`.
- FIPS 203 sizes on `ct_i` (1088 B) and `ss_i` (32 B), from `kem.py`'s constants.
- A wrong decapsulation key fails to recover the key (AEAD tag rejects).
- Tampering with `EncKey_i` is detected — the AEAD is doing its job.
- `EncKey_i` issued for `UID_A` fails to decrypt under `UID_B`'s derived key
  (the `info` binding).
- The same `SK_{U,i}` delivered twice yields different `ct_i` and different
  ciphertext (fresh encapsulation and nonce each time).
- `SK_{U,i}` plaintext bytes never appear in `EncKey_i`.
- The ML-KEM setup cost is reported through
  `initializer.measure_kem_setup_cost` with its `backend` tag, and a `kyber_py`
  backend is refused for a reportable figure. SKIPs when no backend is live.

### Step III.4 — Version-Bound Authorization Profile Generation (`:549`)

```
S_U = ∪_{i=1..N_U} S_{U,i}
C_U = {C_1^auth, ..., C_{N_U}^auth}
AuthRoot_U = H(UID ‖ H(S_U) ‖ VID_U ‖ H(C_U))
VAP_U = (UID, D_U, AuthRoot_U, VID_U, C_U)
```

**Module:** `aim/aim.py`. The AIM already returns `C_U` in sorted authority-ID
order (`AuthorizationIndexManager.commitments`), which was built for this step;
what is added is `AuthRoot_U`, the `VAP_U` record, and VAP storage
("maintained by the Authorization Index Manager").

**Decisions.**

- `H(S_U)` and `H(C_U)` are unspecified, exactly as `H(A_i)` was in Phase II
  Step 2. Use the same rule already implemented there: SHA-256 over the canonical
  encoding of the **sorted** collection under a per-use domain tag. Order
  independence is required, not cosmetic — the AIM enumerates authorities in no
  guaranteed order, and Phase VIII Step 2 must recompute `AuthRoot_U` from the
  same inputs.
- **`VID_U` aggregation — one decision, shared with `VID_j`.** The manuscript
  says only "the AIM assigns the current authorization version identifier
  `VID_U`", while `C_U` spans `N_U` authorities each with its own `VID_i`.
  Phase VI Step 3 then computes `C_j^sync = |VID_U − VID_j|`, so `VID_U` and
  `VID_j` **must share a scale and an aggregation rule** or their difference is
  meaningless. `fsn/fsn.py` already takes the minimum across synchronised
  authorities; `VID_U` therefore takes the minimum across the user's
  participating authorities. `benchmark` provenance, already flagged for
  `VID_j`, and this makes it one decision rather than two.
- `D_U` is the set of authorised administrative domains, derived as
  `{Dom_i : AA_i ∈ participating}`, and must be a subset of the four corpus
  domains.

**Cross-phase consumers** — the reason this step is load-bearing:

| Consumer | Uses |
|---|---|
| Phase IV Step 5 (`Commit_i`) | `AuthRoot_DO` — the Data Owner's VAP, which is why DO enrolment cannot be deferred |
| Phase VI Step 1 (`ST`) | `AuthRoot_U`, `VID_U` |
| Phase VI Step 2 (AIM check) | `(AuthRoot_U, VID_U, C_U)` consistency against current authority state |
| Phase VI Step 3 (`C_j^sync`) | `VID_U` |
| Phase VII Step 4 (`Commit_i'`) | `AuthRoot_DO` |
| Phase VIII Step 2 | recomputation of `AuthRoot_U` |

**Tests:**

- `AuthRoot_U` binds all four inputs — four separate assertions (`UID`,
  `H(S_U)`, `VID_U`, `H(C_U)`), the same shape as the `C_i^auth` sensitivity test.
- `AuthRoot_U` is order-independent over both `S_U` and `C_U`.
- A single authority incrementing its `VID` changes `AuthRoot_U` — the
  version-*bound* property the profile is named for.
- `VID_U` equals the minimum over participating authorities, and a stale
  authority pulls it down.
- `D_U ⊆` corpus domains; a VAP naming an unknown domain is refused.
- The VAP is recomputable by a verifier from `(UID, S_U, VID_U, C_U)` alone —
  the Phase VIII Step 2 precondition.
- `SK_U` and `MSK_i` bytes never appear in the encoded `VAP_U`: the profile is
  authorization metadata, and the AIM is not trusted with key material.
- A VAP built from `C_U` that disagrees with the ledger is detected
  (reuses `verify_against_ledger`).
- End-to-end: the Phase I-II federation plus one DO and one DU, both enrolled
  across 2 of 4 authorities, ending with two VAPs and a chain that still verifies.

---

## Ordering

1. `types.py` records (`UserRequest`, `AttributeKeyShare`, `EncryptedKeyDelivery`,
   `VersionBoundAuthorizationProfile`) — everything downstream hashes through them.
2. **Step III.3 first, out of protocol order.** It is the only step with no
   blocked dependency, and it is the one that produces a reported figure. Written
   against a placeholder `SK_{U,i}` blob, it needs no change once Step 2's
   construction is settled — delivery is agnostic to what it delivers.
3. Step III.1 (registration and credential policy).
4. Step III.4 (VAP) — depends on Step 1 for `S_U`/`D_U` and on Phase II's
   commitments, both available; **not** blocked by Step 2, since `AuthRoot_U`
   hashes the attribute *set*, never the key.
5. Step III.2 last, once the `KeyGen` construction is signed off and the
   Type-III backend exists.

This ordering means Phase III can reach "everything but the ABE key structure"
without waiting on either open decision, and Phase IV can start — it consumes
`AuthRoot_DO`, which Step 4 produces.

## Open decisions

| # | Decision | Blocks | Affects a reported number? |
|---|---|---|---|
| 1 | **`KeyGen(MSK_i, S_{U,i})` construction.** Interface only in the manuscript; the published `(MSK_i, PK_i)` shape matches Rouselakis-Waters. Confirm RW15, or supply the intended construction. | Step III.2 | **No** — the ABE layer is on no measured path (Exp. 1 is pure hashing, Exp. 4 excludes decryption, Phases III/V untimed) |
| 2 | **Type-III charm backend** absent from `Common/crypto/pairing.py`. Carried over from Phase I Step 2. | Steps III.2 (and I.2) | Not until a reportable run |
| 3 | **`VID_U` / `VID_j` aggregation = minimum.** Unspecified in the manuscript; the two must share a rule for `C_j^sync` to mean anything. | Step III.4 | **Yes** — feeds the AASS score, hence Exp. 7-8 |
| 4 | **Credential policy and `Cred` format.** Unspecified. Proposed role-prefix policy above. | Step III.1 | No |
| 5 | **HKDF `info` and AEAD associated data** bindings. Unspecified; proposed `(UID ‖ ID_i ‖ VID_i)`. | Step III.3 | No |

## Observations for the manuscript

Not implementation choices — things a reviewer may raise, recorded here so they
are decided deliberately.

1. **Step 3's forward-secrecy claim (`:547`) does not hold** for encapsulation to
   a static user KEM key. Detailed above. Implemented as published.
2. **The Phase IV / Phase VI token mismatch remains unresolved** (already
   flagged): Phase IV Step 2 binds index tokens as
   `H(w_j ‖ PID_i ‖ VID_i ‖ Dom_i)` while Phase VI Step 1 builds
   `T_Q = {H(w_i ‖ VID_U)}`. As published, a search token cannot match an index
   entry. This blocks Phase IV/VI, not Phase III, but Phase III Step 4 is where
   `VID_U` — the version the search token carries — is defined, so the two need
   settling together.
3. **`N_U` is not specified.** §V fixes `d = 4`, `m = 4`, `q = 5`, and
   `N_AA = 4` was settled at `benchmark` provenance on 2026-08-08. The number of
   authorities a *user* enrols with is a separate quantity; the plan's tests use
   2 of 4 to exercise the multi-authority path without assuming full enrolment.
   Worth stating in §V alongside `N_AA`.
