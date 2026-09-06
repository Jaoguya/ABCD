# MA-LB-PQ-VDSE — Phase IV Implementation Plan

> **Note (2026-09-06).** Every `Overleaf/PQ-AVDSE-OJCOMS` line anchor below
> refers to the SUPERSEDED manuscript revision this decision was taken
> against. The live manuscript is `Overleaf/MA-LB-PQ-VDSE.tex`, whose phases
> were renumbered; the anchors are kept unchanged so the record still says
> what was read at the time. See `MANUSCRIPT_DIVERGENCE.md`.


**Scope:** Phase IV — Policy-Bound Dynamic Search Index (PDSI) Construction —
implemented under `Schemes/ma_lb_pq_vdse/src/index/`. Includes the Phase V Step 4
shard distribution requested alongside it, marked as the separate phase it is.

**Manuscript source:** `Overleaf/PQ-AVDSE-OJCOMS` — Phase IV at `:603`, Step 1
`:606`, Step 2 `:635`, Step 3 `:661`, Step 4 `:690`, Step 5 `:717`. Phase V at
`:737`, Step 4 `:797`, Step 5 `:813`. Cross-referenced against Phase VI Step 1
`:829`, Step 2 `:860`, Step 4 (matching) and §V `:1892`.

**Timing status:** Phase IV is **offline index construction and is excluded from
every measurement** (README §5, Exp. 2 rule: "Index construction is offline").
What it produces is the object Exp. 2, 3, 5 and 7-8 measure searching over, so its
correctness governs whether those numbers mean anything, while its own latency is
never reported.

---

## Naming and scope corrections

Three items in the request need restating before the plan makes sense:

| Requested | As published |
|---|---|
| PDSI = "Privacy-Preserving Distributed Searchable Index" | **Policy-Bound Dynamic Search Index** (`:603`, and README §2). Not a cosmetic difference: "policy-bound" names the property this phase is *about*, and it is precisely the property §1 below shows cannot hold as written. |
| Record sharding across FSNs | **Phase V Step 4** (`:797`) — `Sync_i = (I_i, PID_i, VID_i, CID_i)` "is propagated to the authorized Fog Search Nodes". Covered in §3 below since it was asked for, but it is Phase V and it depends on Phase V Steps 1-3 (IPFS outsourcing, metadata registration, blockchain commitment) which this plan does not cover. |
| Data owner registration | **Already implemented.** Phase III enrols DO and DU through one path (`:491`); `src/user/registration.py` and `src/user/profile.py` are committed. What Phase IV needs from it is `AuthRoot_DO`, which `profile.build_profile_from_aim()` produces. Nothing further to build. |

---

## 1. The index-matching discrepancy

This is the substantive blocker, and it is not a typo.

### 1.1 What the manuscript says

Three statements that cannot all hold together:

```
Phase IV Step 2  (:635)   T_j = H( w_j ‖ PID_i ‖ VID_i ‖ Dom_i )       index token
Phase VI Step 1  (:829)   T_Q = { H( w_i ‖ VID_U ) }                    query token
Phase VI Step 4           R = { (CID_i, PID_i, VID_i) | T_Q → I_i }     matching
```

The matching relation is written `T_Q → I_i` — **an arrow, never defined**. So the
paper does not actually claim `T_Q = T_j`; it leaves the predicate unspecified. The
discrepancy is therefore a *gap in the construction*, not an inconsistency to be
patched, and closing it is an author decision.

### 1.2 Why the obvious reading is impossible

Under exact-match semantics the client would have to reproduce
`H(w_j ‖ PID_i ‖ VID_i ‖ Dom_i)`, which requires knowing every record's policy
identifier, version, and domain. Enumerating them client-side means
`q × |PID_U| × |D_U|` tokens per query instead of `q`.

That is ruled out by the manuscript itself, at `:1892`:

> "the proposed framework generates **a single authorization-bound trapdoor** for
> each multi-domain query. **The same trapdoor can be reused across participating
> domains**, while each fog search node enforces domain-specific authorization
> locally. Moreover, authorization-aware bitmap filtering removes unauthorized
> ciphertexts before encrypted matching…"

A single trapdoor reused across domains **cannot contain `Dom_i`**. And since each
domain carries its own authorization version, it cannot contain a per-domain
version either. §V is not describing a token that binds policy and domain; it is
describing a token that binds neither, with both enforced *locally at the FSN by
bitmap filtering*. Exp. 3 measures exactly that claim, and `index.yaml`'s
`bitmap.granularity: domain_policy` was already built for it.

### 1.3 Two further consequences of a version-bearing token

- **Version skew becomes a correctness cliff.** Phase VI Step 3 defines
  `C_j^sync = |VID_U − VID_j|`, so the design *expects* versions to diverge. If the
  token embeds a version, any divergence yields **zero matches** rather than stale
  results — a silent empty answer, not a degraded one.
- **An authority version bump re-tokenizes its whole domain.** Phase VII Step 2
  (`:1020` ff.) recomputes `T_j' = H(w_j ‖ PID_i' ‖ VID_i' ‖ Dom_i)` for "affected"
  keywords. If `VID_i` tracks the authority's version, every keyword of every
  record in that domain is affected: 285,268 records × 31.7 keywords ≈ **9.0M
  entries per bump**. Exp. 6 sweeps δ to 10⁵ authorization updates, and `:1892`
  claims these operations "avoid global index reconstruction".

### 1.4 `VID` is overloaded across four distinct scopes

The root cause. One symbol denotes four different counters:

| Symbol | Scope | Defined |
|---|---|---|
| `VID_i` | a **record's** policy/authorization version | Phase IV Step 1 (`Meta_i`) |
| `VID_k` | an **authority's** authorization version | Phase II Step 3, Phase VII Step 3 |
| `VID_U` | a **user's** profile version | Phase III Step 4 |
| `VID_j` | an **FSN's** synchronized version | Phase VI Step 3 |

`H(w ‖ VID_i)` and `H(w ‖ VID_U)` can only match if the record and user counters
are the same namespace. Nothing in the manuscript says they are, and §V's
`C_j^sync` treats `VID_U` and `VID_j` as comparable while Phase IV treats `VID_i`
as a per-record field. **This needs disambiguating in §V regardless of which
matching option is chosen.**

### 1.5 Options

| # | Matching relation | Exp. 1 | Exp. 3 (one trapdoor) | Exp. 5/6 (incremental) | Policy-bound token | Leakage |
|---|---|---|---|---|---|---|
| A | Client enumerates `(PID, VID, Dom)`; exact match | **breaks** — `q×\|PID\|×\|D\|` | **breaks** | ok | yes | lowest |
| B | `T_j = H(w_j)`; policy/domain/version enforced by bitmap + entry payload | ok | ok | ok | **no** | keyword equality visible across domains |
| C | `T_j = H(w_j ‖ epoch)` with one global authorization epoch | ok | ok | **breaks** — re-tokenize per epoch | at epoch granularity | as B, per epoch |
| D | **B, plus an authenticated per-entry policy tag** `H(PID_i ‖ VID_i ‖ Dom_i)` | ok | ok | ok | binding retained as a *tag*, not a lookup key | as B |
| E | Server-side re-keying: FSN derives domain-keyed tokens from one client token | ok | ok | ok | yes | lowest |

**Recommendation: D.** It is the minimal change consistent with §V `:1892`,
satisfies every experiment's requirement, and keeps the integrity half of the
"policy-bound" claim: an entry cannot be moved between policies or versions
undetected, because the tag is bound into the Merkle leaf. What it gives up is
*confidentiality* of cross-domain keyword equality, which must be disclosed in the
leakage model (§Security) rather than left implicit.

**Option E deserves a look before D is settled.** It preserves policy-bound lookup
keys *and* the single client trapdoor, by having each FSN derive its own
domain-keyed tokens from the client's token. Its per-query cost is
`O(|P_Q|)` PRF evaluations at the node — and the AASS score already defines
`C_j^auth = |P_Q|`, "the number of authorization policies involved in the query",
which only makes sense if the server does per-policy work. That is suggestive
enough to be worth an author's judgement. It is also a **new construction**, so it
is not something this implementation should choose.

### 1.6 How the code isolates the decision

`index/tokens.py` exposes one function, `index_token(...)`, and one query-side
counterpart, `query_token(...)`. Every other module calls those and never
concatenates a token itself. Whichever option is chosen changes those two
functions and the tests that pin them; nothing else moves. This is the same seam
discipline used for the pairing backend and for `KeyGen` — the blocked decision
sits behind one named boundary instead of being spread across the phase.

Until the decision lands, `index_token` raises, exactly as `resolve_group` does.
Steps IV.1, IV.3 (structure), IV.4 and IV.5 do not depend on it and can be built
and tested in full.

---

## 2. Phase IV — step by step

### 0. Target layout

```
src/index/
├── __init__.py
├── tokens.py      # Step 2: index_token / query_token — THE BLOCKED SEAM
├── extract.py     # Step 1: W_i and Meta_i from a corpus record
├── dsi.py         # Step 3: index entries, the DSI, bitmap filters
├── commit.py      # Steps 4-5: per-record Merkle tree, Root_i, Commit_i
└── build.py       # drives Steps 1-5 over the corpus; Phase V Step 4 handoff
```

### Step IV.1 — Keyword and Metadata Extraction (`:606`)

```
W_i    = {w_1, ..., w_t}
Meta_i = (PID_i, VID_i, Dom_i, TS_i)
```

**Module:** `index/extract.py`. `W_i`, `Dom_i` and `TS_i` come straight from the
frozen corpus — `Dataset/corpus.py` already yields `W_i + (PID_i, VID_i, Dom_i,
TS_i)` per README §4, so extraction is a projection, not a re-derivation.

**Decision.** `PID_i` (the access-policy identifier) is *not* in the corpus: the
corpus carries a placeholder. The manuscript never says how many distinct policies
exist or how records map to them. Proposal: a policy per (domain, record-type)
pair, giving a small fixed `|PID|` per domain, recorded in `index.yaml` as
`benchmark`. This matters for Exp. 2 — `bitmap.granularity: domain_policy` sizes
the number of bitmaps as `|Dom| × |PID|`, so `|PID|` directly sets the pruning
structure whose effect `n_eff` reports.

**Tests:** extraction is a pure projection of a corpus record (no keyword invented
or dropped); `|W_i| ≥ 5` for every record, matching the corpus's
`min_keywords_per_record`; `Dom_i` is one of the four domains; `Meta_i` binds all
four fields in its digest; a record whose `|W_i|` is below the configured minimum
is rejected rather than silently indexed.

### Step IV.2 — Policy-Bound Keyword Encoding (`:635`)

**BLOCKED — see §1.** `index/tokens.py` holds the seam and raises until the
matching relation is decided.

**Tests once decided** (written now, skipped until then): the token is
deterministic; distinct keywords give distinct tokens; whichever fields the chosen
option binds are each shown to change the token (one assertion per field); a
single query token matches entries across all `d` domains, which is the Exp. 3
precondition and the property option A fails; token width equals
`index.yaml → dsi.token_bits` with no truncation.

### Step IV.3 — Dynamic Search Index Construction (`:661`)

```
I_j = (T_j, CID_i, PID_i, VID_i)
DSI = ∪ I_j
```

**Module:** `index/dsi.py`. The entry already carries `PID_i` and `VID_i` as
payload, which is what makes option B/D implementable without adding fields the
paper does not define.

"Each index entry remains independently updateable, allowing insertions,
deletions, and policy modifications **without rebuilding the entire searchable
index**" — this is the Exp. 5 property, so the structure must support per-entry
mutation. A token → postings map with stable entry ordinals, plus the
`domain_policy` bitmaps over those ordinals from `index.yaml`.

**Tests:** an insertion touches only its own postings list and the affected
bitmaps; a deletion likewise, with entry ordinals of *other* entries unchanged (an
ordinal shift would invalidate every bitmap — the failure mode this test exists to
catch); a policy change rewrites the entry payload without touching the token,
which under option D is the whole point; `N_j` equals the entries actually held;
bitmap intersection returns exactly the authorized candidate set, and `n_eff` is
that set's size measured rather than derived; a Bloom false positive costs one
wasted comparison and never a wrong result.

### Step IV.4 — Batch Integrity Commitment (`:690`)

```
L_j    = H(I_j)
Root_i = MerkleRoot({L_j})
```

**Module:** `index/commit.py`, over `Common/crypto/merkle.py`. Batch scope is
**per record** (`index.yaml → merkle.batch_scope: per_record`, matching `:690`
"batches all index entries associated with one IoMT record"). At the corpus's mean
`|W_i| = 31.7` that is a ~32-leaf tree of height 5 per record — which sets the
Exp. 4 proof size, ~5 × 33 bytes per record.

"Only the Merkle root is committed to the blockchain, while the authentication
paths are maintained by the cloud infrastructure" — so paths are held off-chain
and the ledger takes only `Root_i`.

**Tests:** every leaf's proof verifies against `Root_i`; a tampered entry fails;
`Root_i` is order-sensitive over leaves but stable for a fixed order; incremental
`update_leaf` matches a full rebuild's root (already proven in `Common`, re-checked
at this layer's boundary); proof size and path length are reported for Exp. 4;
odd-leaf promotion rather than duplication, so two distinct leaf sets cannot share
a root.

### Step IV.5 — Policy Commitment Generation (`:717`)

```
Commit_i = H( Root_i ‖ PID_i ‖ VID_i ‖ AuthRoot_DO )
```

**Module:** `index/commit.py`. `AuthRoot_DO` comes from the Data Owner's VAP —
`user/profile.py`, already implemented — which is the concrete reason Phase III had
to precede Phase IV.

Single definition, as with `C_i^auth` and `AuthRoot_U`: Phase VII Step 4 recomputes
`Commit_i'` and Phase VIII Step 1 verifies it, and both must call this function.

**Tests:** `Commit_i` binds all four inputs (four assertions); it changes when the
DO's authorization profile changes, which is the binding that ties data to its
owner's authorization state; recomputable by a verifier from
`(Root_i, PID_i, VID_i, AuthRoot_DO)` alone — the Phase VIII Step 1 precondition;
length-prefixed fields, so no two distinct commitments collide by reframing.

---

## 3. Phase V Step 4 — shard distribution (requested; separate phase)

```
Sync_i = (I_i, PID_i, VID_i, CID_i)   propagated to the authorized FSNs   (:797)
```

Most of this exists. `fsn/fsn.py` already provides `assign_domains_to_fsns()` with
`index.yaml`'s `pack_largest_first` policy, `build_fsn_set()`, and
`ShardState.add_entries()`; `aim/aim.py` already propagates to an explicit node set
and reports nodes touched. What Phase V Step 4 adds is routing an *index* delta
rather than an authorization delta: `Sync_i` goes to the nodes serving `Dom_i`,
found the same way `affected_fsns()` finds them.

**Tests:** a record's entries land only on nodes serving its domain; `N_j` rises by
exactly `|W_i|` on the receiving node and not at all elsewhere; with `d = m = 4`
each record touches exactly one node; with `d = 10 > m = 4` the packing holds and
no node is idle; the shard totals across nodes sum to the DSI size, so no entry is
dropped or double-counted.

Phase V Steps 1-3 (IPFS outsourcing, metadata registration, blockchain commitment)
are **not** in this plan; Step 4 needs `CID_i` from Step 1, so a placeholder CID is
used until then, isolated the same way `SK_{U,i}` was.

---

## 4. Prerequisite: the corpus cannot currently be read

Phase IV is the first phase that reads the corpus, and it cannot run yet.
`Dataset/dataset_manifest.json` in the tree is the **superseded v1** manifest
(`d991c695…`, 1,206,159 records) while `dataset.yaml` pins v2 (`fd4b7654…`,
1,141,072 records). `Dataset/corpus.py::verify_against_pin` correctly raises
`CorpusMismatchError`, so `load_verified_corpus()` refuses to load anything —
committed as `334c34c` on 2026-08-08.

**The v2 manifest must be committed from the experiment host before Step IV.1 can
be tested against real data.** Steps IV.2-IV.5 are testable on synthetic records
constructed in the test file, so the plan is not blocked on it end to end — but no
Exp. 2 number can be produced until it lands.

`src/config.py::verify_corpus_reference()` already cross-checks `index.yaml`'s
restated corpus facts against whatever manifest loads, so this class of drift fails
loudly rather than being read past.

---

## 5. Ordering

1. `index/extract.py` (Step IV.1) — pure projection, no blocked dependency.
2. `index/commit.py` (Steps IV.4-IV.5) — needs only `merkle` and `AuthRoot_DO`,
   both available. Delivers the single definition of `Commit_i` that Phases VII
   and VIII depend on.
3. `index/dsi.py` (Step IV.3) — structure, bitmaps, and per-entry mutation, built
   against an injected token function so it does not wait on §1.
4. `index/tokens.py` (Step IV.2) — **after the matching decision.** One function
   changes; the tests written in step 3 stop skipping.
5. `index/build.py` — drives Steps 1-5 over the corpus, once the v2 manifest is
   available.
6. Phase V Step 4 routing, with a placeholder `CID_i`.

This order means everything except the token function itself can be complete and
tested before the author decision arrives.

## 6. Open decisions

| # | Decision | Blocks | Affects a reported number? |
|---|---|---|---|
| 1 | **The index-matching relation** (§1.5). Recommend option D; option E worth an author's judgement. | Step IV.2, and Exp. 1-3, 5, 7-8 | **Yes — decisively.** It determines Exp. 1's trapdoor count, Exp. 3's single-trapdoor claim, and whether Exp. 5/6 are incremental |
| 2 | **`VID` disambiguation** across record / authority / user / FSN scopes (§1.4). | Step IV.2, and the §V text | Yes — via option 1 |
| 3 | **`\|PID\|` and the record-to-policy mapping** (Step IV.1). Not in the manuscript. | Steps IV.1, IV.3 | Yes — sizes the bitmap structure, hence `n_eff` in Exp. 2 |
| 4 | **v2 `dataset_manifest.json`** (§4). | Step IV.1 against real data; every Exp. 2 number | Yes |
| 5 | Type-III charm backend — carried over, unchanged. | Phase I Step 2, Phase III Step 2 | Not until a reportable run |

## 7. Observations for the manuscript

1. **`T_Q → I_i` is undefined** (Phase VI Step 4). Whichever option is chosen, the
   matching relation should be written explicitly.
2. **§V `:1892` and Phase IV Step 2 describe different constructions.** §V's
   single reusable trapdoor with local bitmap enforcement is the coherent one and
   the one the experiments measure; Phase IV Step 2's four-input token is not
   compatible with it. Phase IV Step 2 is the text that should change.
3. **`VID` is overloaded four ways** (§1.4).
4. **If option B or D is adopted, the leakage model needs updating**: identical
   keywords under different policies and domains produce identical tokens, so
   cross-domain keyword equality is visible to an honest-but-curious node. The
   current text claims the token "limit[s] cross-domain linkage" (`:635`), which
   would no longer hold.
5. Carried forward, unchanged: the Phase III Step 3 forward-secrecy claim
   (`:547`), and the RW15-vs-RW13 citation (this repo's `3893fd0`).
