# Where the implementation and the manuscript disagree

Recorded 2026-09-06, against `Overleaf/MA-LB-PQ-VDSE.tex` as synced that day.

The manuscript was rewritten into its eight-phase, policy-state-aware form. The
code was **re-anchored to it by name only**: module headers, phase/step numbers,
`IAS` → `DIAS`, and the Exp. 6 arm labels now follow the manuscript. Nothing
cryptographic was changed, so every banked `results.csv` remains valid and no
re-run was triggered.

That leaves real divergences. They are listed here rather than fixed silently,
because each one is either results-affecting (D1–D9) or a defect on the
manuscript's side (D10–D14). **A reader who trusts a docstring's phase citation
should read this file before trusting the formula next to it.**

Scope decision of 2026-09-06: *structure and naming only*. D1–D9 were costed and
deferred; adopting them **in place** invalidates every proposed-scheme result and
requires a full campaign re-run.

## Update, 2026-09-06 — D1–D9 are implemented as a parallel track

Rather than mutate the scheme, the manuscript's construction now exists
**alongside** it, so the two can be measured against each other and the banked
Option D results stay valid:

| Divergence | Implemented in | Runnable as |
|---|---|---|
| D1 token `H(w‖PID‖PV‖Dom)` | `src/psa/tokens.py` | — |
| D2 `V_P` vector, `PV` digest | `src/psa/state.py` | — |
| D3 `AuthState`, new `Commit_i` | `src/psa/state.py`, `src/psa/commit.py` | — |
| D4 `I = (T, CID, PID, PV)` | `src/psa/records.py` | — |
| D5 `VAP = (UID, D_U, V_U, C_U, AuthRoot_U)` | `src/psa/records.py` | — |
| D6 current `tab:cost` rows | `tests/test_cost_table_agreement.py::PSA_CLAIMS` | `pytest` |
| D7 Exp. 1 over `q` **and** `\|P_U\|` | `harness/psa_experiments.py` | `--construction psa --experiment 1` |
| D8 Exp. 6 over affected-policy ratio | `harness/psa_experiments.py` | `--construction psa --experiment 6 --variant all` |
| D9 trapdoors issued vs `d` | `harness/psa_experiments.py` | `--construction psa --experiment 3` |

`AA(PID_i)` had to be modelled to do any of this: policy ids are `<domain>/polN`
and there is one AA per domain, so read literally the governing set is a
**singleton** and both halves of the manuscript's central claim are vacuous.
`src/psa/governance.py` therefore makes the set size a `benchmark` parameter
defaulting to 2-of-4, with the reasoning recorded there.

**What the track does not cover.** Exp. 2 (search latency), Exp. 4
(verification) and Exp. 7–8 (scheduling) have no PSA form, because
`index/dsi.py`, `fsn/` and `verify/` are all written against `types.IndexEntry`
and its scalar `vid`. Forking those is a larger change than D1–D9 describe, so
`--construction psa` refuses those experiment numbers rather than quietly
measuring something else. The manuscript's Search and Verification `tab:cost`
rows are correspondingly absent from `PSA_CLAIMS`.

**Reportability.** Every PSA run is built on in-process synthetic data with no
corpus behind it, so `provenance.reportability()` refuses it — by construction,
not by discipline. These numbers decide whether to adopt D1–D5; they are not
§V material. A comparison against the banked Option D numbers is only valid on
the same host, since those were measured on AWS.

---

## Results-affecting: the code implements the previous construction

### D1 — Token construction (Option D)

| | |
|---|---|
| Manuscript | `T_{i,j} = H(w ‖ PID_i ‖ PV_i ‖ Dom_i)` (eq:policy-bound-token), and the query token `T^Q_{r,ℓ}` identically (eq:query-token). Theorem "Policy-State Token Consistency" asserts they match. |
| Code | `T = H(w)` alone, with policy/version/domain moved onto a separate `PolicyTag` and the FSN's `(domain, policy)` bitmap. See `src/index/tokens.py`. |

Option D was chosen on 2026-08-10 because the *previous* manuscript wrote the
index token with `PID‖VID‖Dom` and the query token with `VID_U` only, which
cannot both hold. The new manuscript resolves that same contradiction in the
opposite direction. Adopting it changes every token in every index.

Knock-on effects, all currently true of the code and false of the manuscript:

* `Trapdoor.is_domain_independent` is `True`. Under the manuscript's form it is
  `False` — a token names a domain.
* A policy or authority-version change re-tokenizes every affected entry
  (manuscript Phase VII Step 2). Under Option D it touches no token at all,
  which is what makes Exp. 5 an incremental-update measurement.
  `PHASE_IV_PLAN.md` §1.3 sized the re-tokenization at ~9.0M entries per
  authority version bump.

### D2 — Version state is a scalar, not a policy-relevant vector

Manuscript: `V_{P_i} = {(ID_k, v_k) : AA_k ∈ AA(PID_i)}` (eq:policy-version-state)
digested to `PV_i = H(Encode(V_{P_i}))` (eq:policy-version-digest).
Code: a single integer `vid` throughout (~980 references in `src/`).

The manuscript's Policy-State Non-Interference theorem is a property of the
*vector*: an unrelated `AA_k` advancing leaves `V_{P_i}` untouched. A scalar
cannot express it.

### D3 — Record commitment binds a different authority state

Manuscript: `Commit_i = H(CID_i ‖ Root_i ‖ PID_i ‖ PV_i ‖ AuthState_i)`
(eq:record-commitment), with `AuthState_i` a digest over the commitments of the
policy-governing AAs only (eq:policy-auth-state).
Code: `commit_record(..., auth_root_do=...)` binds the Data Owner's `AuthRoot`.

### D4 — Index entry shape

Manuscript `I_{i,j} = (T_{i,j}, CID_i, PID_i, PV_i)` (eq:index-entry);
code `types.IndexEntry(token, cid, policy_id, vid)`. Follows from D2.

### D5 — VAP shape

Manuscript `VAP_U = (UID, D_U, V_U, C_U, AuthRoot_U)`, where `V_U` and `C_U` are
per-authority sets refreshed entry-by-entry. Code carries a scalar version.

### D6 — Every `tab:cost` row changed

`src/tests/test_cost_table_agreement.py::CLAIMS` pins the previous table. Current
manuscript rows for the proposed scheme:

| Cell | Manuscript now | Pinned in the test |
|---|---|---|
| Token generation | `O(\|T_Q\|)T_H` | `O(q)T_H` |
| Search | `O(\|T_Q\|)T_L` | `O(dT_H)+O(n_eff)(T_F+T_H)` |
| Dynamic update | `O(k log t)T_H` | `O(k)T_H+O(log n)T_MT` |
| Verification | `O(r log t)T_H + O(r)T_BC` | `O(r)T_MT+O(r)T_H` |
| Auth. synchronization | `O(a + k log t)T_H` | `O(δ)T_H+O(log d)T_MT` |

The test still passes: it checks the *shape* of the measured curve (linear in the
swept variable), and both tables claim linear growth. It is nonetheless asserting
cells that no longer appear in the paper.

### D7 — Exp. 1 has a second sweep dimension

Manuscript: `q ∈ {1,5,10,15,20}` **and** `|P_U| ∈ {1,2,4,8}`, with
`|T_Q| = q·|P_U|`. Code (`Exp1TrapdoorGeneration`) sweeps `q` only and enrols the
user in a single domain, so `|P_U|` is always 1 and `|T_Q| = q`.

### D8 — Exp. 6 sweeps a different variable

Manuscript: the *fraction of policies affected*, 10% → 100%.
Code and `global.yaml`: `authorization_updates`, 10² → 10⁵.

The three arms do correspond (see the mapping in
`src/harness/experiments.py`), but the x-axis does not. The banked Exp. 6 data
cannot be plotted against the manuscript's stated axis.

### D9 — Exp. 3's single-trapdoor claim is gone from the manuscript

`Exp3CrossDomain` reports `trapdoors_issued: 1.0` as its headline secondary. The
manuscript's Exp. 3 no longer makes that claim, and under D1's token form it
would be false. The metric is still measured and still correct *for the
implemented scheme*.

---

## Manuscript-side defects found while re-anchoring

### D10 — Phase V shard propagation and the catalog were deleted

The previous Phase V had Step 4 `Sync_i = (I_i, PID_i, VID_i, CID_i)` and Step 5
`Catalog ← Catalog ∪ (CID_i, PID_i, VID_i)`. Neither appears in the current
manuscript; Phase V now ends at the handoff to index construction, and
propagation to FSNs exists only as Phase VII Step 4 (`DIAS_i` → `F^aff_i`).

`src/shard/propagation.py`, `types.SyncPayload` and `types.CatalogEntry`
implement steps the paper no longer defines. The code is re-anchored to Phase VII
Step 4, but the *record shapes* have no equation behind them any more.

### D11 — Phase VIII Step 6 (retrieval audit logging) was deleted

Phase VIII went from six steps to four. `src/chain/ledger.py`'s
`NS_AUDIT_LOGS` namespace is the only survivor and is left in place; it is
harmless, but nothing in the paper calls for it.

### D12 — Exp. 7's stated range is narrower than the data

Manuscript Exp. 7: "from 100 to 5000". `global.yaml` sweeps
`[100, 500, 1000, 2500, 5000, 10000]`, and Exp. 8 — which shares the same runs —
is correctly stated as reaching 10,000. Either Exp. 7's sentence should say
10,000 too, or the point should be dropped from the figure.

### D13 — Exp. 4's text understates the measured cost

The current text says the framework "incurs a moderate per-result verification
cost" and names Schemes [30], [35] and [54] as the comparison. The previous
revision said, and the measurements support, that it is the **highest** of the
four per returned record, that Fig. 4(a) is on a log axis for that reason, and
that Scheme [54] is *omitted* from panel (b) because its verification is already
per-record rather than aggregated.

Dropping those three statements makes the claim weaker to defend, not stronger:
a reviewer who reads the figure will see the highest curve described as moderate.
Restoring them costs nothing — the trade-off argument that follows is unchanged.

### D14 — Smaller manuscript issues

* The **Conclusion** still lists "Policy-Driven Searchable Indexes (PDSIs)" and
  "Incremental Authorization Synchronization (IAS)" while the body defines DIAS
  and a policy-state-aware index throughout.
* `\cite{refSynthea}` (§V, the dataset) has **no `\bibitem`** — it renders as `[?]`.
* `tab:cost` uses `T_Mul`, `T_Sig`, `T_BF`, `N` and `n_cand`, none of which are
  defined in `tab:cost-notation`.
* `ref34`, `ref44`, `ref49`, `ref56` are in the bibliography but never cited.
* `tab:notation` defines two symbols the protocol never uses: `VID_i`
  ("Version identifier"), which appears nowhere outside that table now that
  `PV_i` and `V_{P_i}` carry version state (27 uses of `PV_i`, 0 of `VID_i`);
  and `Score_j`, where the scheduler's actual symbol is `SC_j` (7 uses, itself
  undefined in the table).
