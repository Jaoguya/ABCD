# MA-LB-PQ-VDSE — Phase I & II Implementation Plan

**Scope:** Phase I (System Initialization) and Phase II (Multi-Authority Registration and
Authorization-State Commitment), implemented under `Schemes/ma_lb_pq_vdse/src/`.

**Manuscript source:** `Overleaf/PQ-AVDSE-OJCOMS` — Phase I at `:362`, Phase II at `:432`.
Equation references below cite the pandoc export `PQ-AVDSE-OJCOMS.md` (§Phase I `:370–449`,
§Phase II `:451–528`), which matches the LaTeX for these two phases.

**Timing status:** both phases are **setup, not timed** (README §2). Neither emits
`raw_runs.csv`/`results.csv`. The one number they contribute to the paper is the ML-KEM
session-establishment cost, reported separately per the Exp. 1 measurement rule.

---

## 0. Target layout

```
src/
├── __init__.py
├── config.py             # loads global.yaml + crypto.yaml; no literal parameters in code
├── types.py              # frozen dataclasses + canonical byte encodings
├── abe/ma_cpabe.py       # Phase I Step 2: Setup(1^λ) → (MSK_i, PK_i)
├── authority/
│   ├── initializer.py    # Phase I Steps 1 & 3: global crypto init, PP assembly + publication
│   ├── authority.py      # AA_i: Phase I Step 2, Phase II Steps 1–3
│   └── revocation.py     # RevRoot_i over the revocation list
├── aim/aim.py            # Phase II Step 4: Meta_i registry, VID table, FSN propagation
├── fsn/fsn.py            # Phase I Step 4: FSN_j shard state, VID_j, queue
├── chain/ledger.py       # blockchain adapter (registrations, states, roots, audit log)
├── main.py               # CLI: --experiment / --config / --dataset / --runs
└── tests/test_phase1_2.py
```

Conventions inherited from the repo: parameters come from `Experiment Configuration/*.yaml`
via `Common.crypto.config` and are never hardcoded; primitives come from `Common/crypto/`
(README §8 — anything the paper *cites* is shared, anything it *contributes* is ours);
tests are standalone scripts in the `test_primitives.py` style (no framework required, skip
rather than fail on an absent optional backend).

---

## Phase I — System Initialization

### Step I.1 — Global cryptographic initialization (`authority/initializer.py`)

Builds the primitive set `P = {H, SHA-256, AES-256-GCM, HKDF, ML-KEM}` (`.md:387–399`) by
*binding* to `Common/crypto`, not reimplementing it:

| Manuscript symbol | Binding |
|---|---|
| `H` (searchable-index generation) | `hashes.sha256` with a per-use domain tag |
| SHA-256 (Merkle commitments) | `merkle.hash_leaf` / `hash_node` (already prefix-separated) |
| AES-256-GCM | `symmetric.encrypt` / `decrypt` |
| HKDF | `hashes.hkdf_sha256` |
| ML-KEM | `kem.MLKEM768` (liboqs 0.16.0 backend, verified) |

Also resolves the bilinear group `e : G₁ × G₂ → G_T` of prime order `p` with generators
`g₁ ∈ G₁`, `g₂ ∈ G₂` (`.md:382–385`) through `pairing.get_backend()`.

**Blocked — open decision 1.** The manuscript writes `e : G₁ × G₂ → G_T` (Type-III, matching
README §1 "Type-III for our MA-CP-ABE"), but `crypto.yaml` has **no `ma_lb_pq_vdse` section**,
so no curve or backend is configured for our scheme, and no pairing backend builds on the
macOS dev host. Nothing in Step I.2 can be written faithfully until a curve is fixed.

Deliverable: `GlobalParams` — an immutable record of the resolved primitive set, curve, and
backend names, hashable so its digest can enter `run_meta.json`.

**Verify:** primitive set round-trips (encrypt→decrypt, HKDF determinism, KEM self-test);
`GlobalParams` digest is stable across processes; requesting a Type-I curve for our scheme
raises rather than silently using the wrong group.

### Step I.2 — Multi-authority initialization (`abe/ma_cpabe.py`, `authority/authority.py`)

Per authority, `Setup(1^λ)` (`.md:404–418`):

```
α_i, β_i ←$ Z_p                MSK_i = (α_i, β_i)
PK_i = ( g₁, g₂, e(g₁,g₂)^{α_i}, g₁^{β_i} )
```

- `e(g₁,g₂)` is computed **once** in Step I.1 and reused; each authority pays one G_T
  exponentiation plus one G₁ exponentiation. This is the honest reading of the equation and
  keeps `N_AA` setup cost linear rather than paying `N_AA` pairings.
- Disjoint attribute universes are asserted, not assumed (`.md:418–420`, "each Attribute
  Authority independently manages a disjoint attribute universe") — overlapping namespaces
  across two AAs must raise.
- `α_i, β_i` are drawn from a config-selectable source: `rng.SecureRandom` by default, or
  `rng.DeterministicRNG(setup_seed)` so a reviewer can reproduce the exact `PP`. Phase I is
  untimed, so this cannot influence a reported latency; the choice is recorded in
  `run_meta.json`.

**Verify:** `PK_i` has the published four-tuple shape; `MSK_i` never appears in `PP` or in any
serialized/ledger record (assert on the encoded bytes, not by inspection); two authorities
produce independent keys; a duplicate attribute across authorities is rejected.

### Step I.3 — Public parameter publication (`authority/initializer.py`, `chain/ledger.py`)

`PP = (G₁,G₂,G_T,e,g₁,g₂,{PK_i}_{i=1..N_AA}, P)` (`.md:424–430`), then each authority
publishes `(ID_i, PK_i)` to the ledger.

Canonical encoding matters here: `PP` is hashed into provenance and, in Phase III, into
`AuthRoot_U`. All encodings go through one `types.py` helper using length-prefixed fields
(the framing-collision property `Common/crypto/hashes.py::_join` already provides and
`test_primitives.py` already covers), with authorities serialized in sorted `ID_i` order so
the digest does not depend on registration order.

**Verify:** encoding is deterministic across processes and insensitive to insertion order;
`PP` digest changes if any `PK_i` changes; ledger read-back is byte-identical.

### Step I.4 — Infrastructure initialization (`fsn/fsn.py`, `aim/aim.py`, `chain/ledger.py`)

Instantiates AIM, LBC, and `F = {FSN₁ … FSN_m}` with `m = 4` from config (`.md:436–449`;
§V "Four Fog Search Nodes and one cloud server"). Each FSN starts with an empty index shard,
`VID_j = 0`, an empty request queue, and the counters Phase VI's `SC_j` will read
(`N_j` entries, `T_j^queue`, synced `VID_j`) — created here so Exp. 7–8 never has to
retrofit them. The ledger's metadata repository namespaces are initialized: authority
registrations, authorization states, Merkle roots, version identifiers, revocation records,
audit logs.

**Staging note:** README §1 requires each FSN to be an **independent process**. Phases I–II
need only in-process objects, so `FSN` is written as a class with process ownership added
when Phase VI lands. The class must therefore hold no references to shared mutable state, or
the process split later will silently change measured behaviour.

**Verify:** `m` comes from config (not a literal); a fresh FSN reports `VID_j = 0` and zero
entries; two FSNs share no mutable state (mutating one leaves the other unchanged); all six
ledger namespaces exist and are empty.

---

## Phase II — Multi-Authority Registration and Authorization-State Commitment

### Step II.1 — Authority registration (`authority/authority.py`, `chain/ledger.py`)

`Reg_i = (ID_i, Dom_i, PK_i)` anchored on the ledger (`.md:467–476`). `Dom_i` is drawn from
the frozen corpus's four domains via `Dataset.corpus`, so authority domains and index domains
are the same objects rather than two parallel notions of "domain".

**Blocked — open decision 2.** `N_AA` is not stated anywhere in §V (which fixes only
`d = 4` domains, `m = 4` FSNs, `q = 5`), and neither is `|A_i|`. The AA↔domain mapping is
therefore undetermined.

**Verify:** re-registering an `ID_i` is rejected; every `Dom_i` is a real corpus domain; the
anchored record verifies against `PP`.

### Step II.2 — Attribute namespace initialization (`authority/authority.py`)

`A_i = {a_{i,1} … a_{i,n_i}}`, every attribute owned by exactly one authority
(`.md:481–487`). `H(A_i)` is the "digest of the authority's attribute namespace" — the paper
does not fix its construction, so: SHA-256 over the length-prefixed, lexicographically
sorted attribute encodings under a dedicated domain tag. Sorting makes the digest
order-independent; the choice is documented in code since it feeds `C_i^auth`.

**Verify:** `H(A_i)` is order-independent but membership-sensitive; global disjointness holds
across all authorities; an empty namespace is rejected rather than digested to a constant.

### Step II.3 — Authorization-state commitment (`authority/revocation.py`, `authority/authority.py`)

```
C_i^auth = H( ID_i ‖ Dom_i ‖ H(A_i) ‖ VID_i ‖ RevRoot_i )        (.md:494–507)
```

- `RevRoot_i` is an **authenticated** revocation root, so a `MerkleTree` over the sorted
  revoked-identifier leaves — not a flat hash. `Common/crypto/merkle.py` rejects an empty
  leaf set, so the empty revocation list needs an explicit domain-tagged sentinel root, and
  that sentinel must be distinguishable from a one-element tree.
- `VID_i` is initialized to `0` and only ever incremented (Phase VII Step 3 defines
  `VID_k' = VID_k + 1`, `.md:1090–1091`). Phase VI's `C_j^sync = |VID_U − VID_j|` and Phase
  VII's `ΔVID = VID' − VID` require a plain integer counter, not an opaque identifier.
- `‖` is realized with the length-prefixed join, so `C_i^auth` cannot collide across
  different field splits. This changes no cost and closes a real ambiguity in the notation.

**Verify:** `C_i^auth` changes when *any* of the five inputs changes (five separate
assertions — this is the commitment's defining property); recomputation from the published
`State_i` reproduces it bit-for-bit; a revoked-identifier insertion changes `RevRoot_i` and
hence `C_i^auth`; incrementing `VID_i` alone changes the commitment.

### Step II.4 — Blockchain commitment and AIM synchronization (`chain/ledger.py`, `aim/aim.py`)

`State_i = (ID_i, PK_i, C_i^auth, VID_i)` to the ledger; `Meta_i = (Dom_i, VID_i, C_i^auth)`
synchronized by the AIM across all FSNs (`.md:515–528`).

The AIM registry is the structure the rest of the scheme reads, so it is built once here
with the accessors later phases need: by-authority lookup (Phase III `C_U`), by-domain
lookup (Phase VI shard authorization), and a version table (Phase VI `C_j^sync`, Phase VII
selective propagation). Phase II is the **initial** sync and legitimately touches every FSN;
Phase VII's selectivity is the measured claim (Exp. 6) and must not be pre-empted by wiring
a broadcast that later phases inherit — propagation therefore takes an explicit FSN set
even now, with Phase II passing all of them.

**Verify:** every FSN reports the same `(Dom_i, VID_i, C_i^auth)` after sync; the AIM's
`C_i^auth` equals the ledger's; propagating to a subset leaves the others' `VID_j` unchanged
(the property Exp. 6 depends on); an authority that has not run Step II.3 cannot be synced.

---

## Ordering

1. `config.py` + `types.py` (canonical encodings) — everything downstream hashes through them.
2. `chain/ledger.py` — Steps I.3, II.1, II.4 all publish; write the adapter before the callers.
3. Step I.1 → I.2 → I.3 → I.4.
4. Step II.1 → II.2 → II.3 → II.4.
5. `tests/test_phase1_2.py` grows with each step; `main.py` gains a `--phase setup` path that
   runs I+II end to end and prints the resolved `PP` digest and per-authority `C_i^auth`.
6. ML-KEM setup cost (`kem.measure_setup_cost`) is emitted from the Phase I path as a
   separately reported figure, keeping it out of the Exp. 1 per-query curve.

## Decisions taken 2026-08-08 (were blocking)

| # | Decision | Recorded in |
|---|---|---|
| 1 | **Type-III via charm-crypto, curve BN254** (`MNT224` only as a host fallback, to be confirmed and recorded, never selected silently). charm is already built and verified on the experiment host, so no new dependency. | `crypto.yaml → ma_lb_pq_vdse.pairing` |
| 2 | **`N_AA` = 4, one AA per administrative domain**, `\|A_i\|` = 10, marked `benchmark` not `published` (§V states neither). | `global.yaml → authorities` |
| 3 | **In-process ledger adapter now**, real Fabric v2.5 behind the same interface before Exp. 4 — the first experiment that measures a chain-consistency check. Phases I–II are untimed, so no reportable number depends on the adapter. | `src/chain/ledger.py` (this plan, Step I.3) |
| 4 | **All four missing config files created**: `global.yaml`, `index.yaml`, `scheduler.yaml`, `workload/`. | `Experiment Configuration/` |

### Still open — carried into the implementation

1. **A Type-III charm backend does not exist yet.** `Common/crypto/pairing.py` exposes only
   `CharmSS512Backend` (Type-I) and `PetrelicBN254Backend` (does not build). Decision 1 needs
   a `CharmType3Backend` added there and verified on the AWS host; it cannot be verified on
   the macOS dev machine, where all four pairing tests skip. `crypto.yaml` records this as
   `backend_implemented: false` so it cannot be mistaken for working.
2. **λ₁…λ₅ remain undetermined** (README §14 open issue #5). `scheduler.yaml` carries
   `weights.status: pending_sweep` with a uniform starting vector, a documented sweep
   procedure on a held-out trace, and `refuse_reportable_runs_while_pending: true`. Exp. 7–8
   stay blocked until the sweep runs — creating the file did not resolve the issue.
3. **The AASS cost terms need normalization that the paper does not specify.** The five
   published estimators span four orders of magnitude at the §6 defaults, so raw weights
   would be vacuous. `scheduler.yaml → normalization` fixes a scale-free rule
   (max over candidate FSNs); it is `benchmark` and belongs in §V if the weights are stated
   there.
4. **Token/trapdoor mismatch between Phase IV and Phase VI.** Phase IV Step 2 binds index
   tokens as `T_j = H(w_j ‖ PID_i ‖ VID_i ‖ Dom_i)`, but Phase VI Step 1 builds the search
   token as `T_Q = {H(w_i ‖ VID_U)}` — without `PID` or `Dom`. As published, a search token
   cannot match an index entry. This blocks Phase IV/VI, not Phase I/II, but it needs an
   author decision before Exp. 1–3 can be implemented.
5. **`README.md` needs two Change Log lines** for the config additions (§16), and §14 issues
   #5 and #7 need their status updated. The agent must not edit
   `README.md` — these are for the user to apply.
