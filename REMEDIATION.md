# REMEDIATION — MA-LB-PQ-VDSE audit

**THIS FILE IS TEMPORARY. DELETE IT WHEN EVERY TASK BELOW IS DONE.**

## Rules for this file (read before editing anything else)

1. **Tick a task the moment it is done**, with the evidence — the command run,
   the number that moved, or the test that now passes. A tick with no evidence
   is not a tick.
2. **When every task is `[x]`, delete this file.** That is the completion
   condition, not a suggestion.
3. **Nothing in the repo may cite this file.** No docstring, comment, config
   key or commit message may reference `REMEDIATION.md`.

Rule 3 is why this file is allowed to exist at all. `CLAUDE.md` says *"Two prose
files, and no more … Do not create a third. Every document retired from this
repo has left dangling citations behind — 338 of them when `README.md` went."*
That cost is live right now, and it is far larger than the rule implies —
**97 citations across the repo point at five documents that no longer exist**:

| deleted document | citations still pointing at it |
|---|---|
| `SCHEME.md` | 39 |
| `README.md` | 21 |
| `MANUSCRIPT_DIVERGENCE.md` | 15 |
| `PHASE_IV_PLAN.md` | 13 |
| `PHASE_III_PLAN.md` | 9 |

**This file is named `REMEDIATION.md`, not `TASKS.md`, for that reason.** A
`TASKS.md` existed and was deleted in the 2026-09-08 purge, and
`.claude/skills/bug-sweep/DECISIONS.md` still cites it six times by task ID
(`DECIDE-1`, `BUILD-1`, `BUILD-2b`, `FIX-4`). Recreating that filename would be
worse than the dangling citations it inherited: a reader following one would
find a file that exists and contradicts what they were sent to read.
`REMEDIATION.md` has never existed in this repo's history, so no stale citation
can resolve to it.

Durable findings do **not** belong here — they go to `SystemConfiguration.md`
§10 *Known gaps* (task D2). This file is only the to-do list.

---

## A. Decided, not yet done

> **DECIDED 2026-09-10 — migrate to PSA and retire `option_d`.** The twin
> structure is a defect generator, not a safety net. Five defects this session
> trace to it: the `collect()` bug (two folders per experiment number), a fix
> that "never reached this twin" (`psa_experiments.py:559`), a cold-vs-warm
> comparison across two different measurement boundaries, `parse_experiments`
> diverging on 9 vs 10, and finding 1.A itself — Fig. 1 from PSA against
> Figs. 2-8 from Option D.
>
> **Order matters: `option_d` currently produces seven of the eight manuscript
> figures.** Deleting it before PSA covers all eight leaves the paper with no
> figures. Sequence: **A2** (ports) -> **A7** (repoint) -> **B2** (campaign) ->
> then delete `option_d` as A10.

- [ ] **A10 Delete `option_d` once PSA covers all eight figures and B2 has
      run.** Not before: it is the only track that works end to end today.


- [ ] **A3 Re-source Fig. 6 from `psa_exp6_affected_ratio`.** §VI's Exp. 6 text
      and caption describe an affected-policy-ratio sweep (10–100%); the
      included figure is the δ = 10²–10⁵ sweep.
- [ ] **A4 Baselines ×4 — Exp. 3 per-domain sizing.**
      `guo/src/exp3_crossdomain.py:46`, `perera/.../runner.py:59`,
      `yue_ge/.../runner.py:79`, `thingom/src/experiments.py:673` all fix
      *total* at 100,000 and shard by `d`. §VI fixes **per-domain**; value
      decided at 10,000.
      *Results-affecting for four published baselines — disclose.*
- [ ] **A5 Exp. 7/8 index sizing** — still `index_size // keywords_per_record`
      ≈ 3,125 where Exp. 2 uses records directly.
- [ ] **A6 `C_j^sync` → the published vector count.** `scheduler.yaml:55` has
      `|VID_U - VID_j|` (a scalar) labelled *published*; eq:search-cost defines
      `|{(ID_k,v_k) ∈ V_Q : v_{j,k} < v_k}|`.
- [ ] **A7 Repoint the figure set to PSA.** `--construction` still defaults to
      `option_d` in `main.py` and `generate_plots.py`.
- [ ] **A8 Retire `test_exp3_trapdoor_count_does_not_scale_with_domains`** at
      the PSA switch — it asserts an Option-D property PSA contradicts by design.
- [ ] **A9 Exp. 4** — §V gains the `check_chain_integrity` disclosure sentence.
      *(`require_version_match` is a §VI item now: the AIM's freshness check is
      `VID_i == VID_U`, a SCALAR, and PSA's policy state is a vector digest.
      §VI Phase VI/VIII specify comparing `V_U` components. Recorded as a
      manuscript+code item rather than silently enabling a check that compares
      the wrong thing.)*

## B. Runs (in order, after A)

- [ ] **B1 λ re-sweep** over the four-term cost on
      `workload/exp78_sweep_holdout.yaml`; commit the output and fill
      `determined_on` / `determined_by`.
- [ ] **B2 One campaign** — re-measure Figs. 2–8 under PSA.
      **NEEDS AWS SPEND APPROVAL.** Never launch Ref[41] Exp. 2 above N=10⁴.
- [ ] **B3 Regenerate all figures**; the Step 1 guards must pass unaided.

## C. Manuscript (after B)

- [ ] **C1 Table I — `ref54` row, two wrong cells.** Blockchain ✗→✓ (p1, p3:
      Merkle proofs "anchored on a blockchain"); Multi-Keyword ✗→✓ (p3: "the
      first lattice-based ABSE framework that supports multikeyword, Boolean,
      fuzzy, and numeric range queries").
- [ ] **C2 Drop `ref41` from the lattice/PQ prose lists** at tex:139 and
      tex:332. The table's ✗ is correct (its security rests on DBDH, which Shor
      breaks); the prose contradicts it twice.
- [ ] **C3 Add a `ref30` row to Table I.** Peony++ is a baseline in Exps. 1–5
      and has no row.
- [ ] **C4 Verify the ten Table I rows whose PDFs are absent** from
      `References/`. Two errors were found in the one row audited closely.
- [ ] **C5 §VI query arity.** "the same q=5 conjunctive query used throughout
      this section" (tex:2544) is unachievable — [30] and [41] are
      single-keyword *by construction*. State the query shape per scheme.
- [ ] **C6 §VI Exp. 2 selectivity.** No baseline records a match count, so the
      "selectivity is kept constant" claim is unfalsifiable. Add a
      `matched_records` secondary to all five, or drop the sentence.
- [ ] **C7 §V Exp. 6, two corrections.** The selective advantage is in **bytes,
      not time** (DIAS vs Incremental-All latency differs by ~2%, noise). And
      the narrowing at a full ratio is **not total**: work converges (10×→1×)
      but delivery does not (40×→4×).
- [ ] **C8 §VI environment.** Host is unpinned (`pin_configured: false`), BLAS
      was never pinned in any banked run, and §VI claims one `m6i.xlarge`.
- [ ] **C9 §V Exp. 4** — re-derive the "within 2% at every r" sentence from
      `raw_runs.csv`; two datasets disagree.

## D. Hygiene

- [ ] **D3 Fix 97 dangling citations to five deleted documents** — `SCHEME.md`
      (39), `README.md` (21), `MANUSCRIPT_DIVERGENCE.md` (15),
      `PHASE_IV_PLAN.md` (13), `PHASE_III_PLAN.md` (9). Every one sends a
      reader to a file that does not exist. `DECISIONS.md`'s six `TASKS.md`
      citations are excluded: it is a closed archive per `CLAUDE.md`.

## E. Blocked / pending someone else

- [ ] **E1 ⏰ DECISION PARKED (user, 2026-09-10) — cross-node forwards.**
      `aass.py:635` increments `forwards` only in the non-AASS branch, so AASS
      scores 0 *by construction* and the others >0 *by construction*.
      Fig. 8(c) measures the arm definitions, not scheduler quality. Either
      give all four arms the same eligibility filter and report the honest
      difference, or drop the metric and §V's sentence.
- [ ] **E2 Exp. 5 `entries_rewritten == 0`** — three causes eliminated (stale
      code, topology, message construction); isolated to the corpus path.
      **Needs the AWS host**: `Dataset/derived/corpus.jsonl` is gitignored and
      exists only on the AMI.

---

## Baseline

**`python -m pytest -q` → 900 passed, 5 skipped, 0 failed** (2026-09-10).

This is the first run that is *meaningfully* green. Earlier "green" runs were
899 + a coin-flip: two timing-ratio tests in `test_psa_units.py` failed ~15% and
~7% of the time, so a red run carried no information and a green one carried
little. Both now assert exact quantities. Treat any failure from here as real.

## Done (kept as the evidence trail until this file is deleted)

- [x] **Step 4 — AIM and AASS wired into `PsaExp2` and `PsaExp3`.** §VI names a
      four-stage path (*"the AIM validates the current VAP and derives … AASS
      then assigns each required shard"*); the PSA track timed only token
      derivation and a posting-list walk, while Option D timed all four and
      Exps. 7-8 timed the AIM check in BOTH tracks — so the PSA track was
      inconsistent with §VI *and* with itself.
      `psa_build_deployment` now reuses Option D's Phase I-III scaffolding via
      `build_deployment(records=0)`, so both constructions share one AIM, one
      authority set and real `FogSearchNode`s instead of bare 3-tuples.
      Measured after wiring: PsaExp2 6.51 ms; PsaExp3 78.45 ms at d=2 and
      123.39 ms at d=4, tokens still `q*d`.
      Regression **900 passed / 5 skipped / 0 failed**.

- [x] **Cross-node forwards, per §VI's definition, applied to ALL FOUR arms.**
      The counter sat inside the non-AASS branch, so AASS scored 0 *by
      construction*. Moved out; §VI's definition is scheduler-agnostic.
      Measured after: **aass 0, no_lb 288, round_robin 168, least_loaded 288.**
      AASS still reads 0 — but now because its eligibility guard never
      misplaces a shard, which is a measurement rather than a tautology.
- [x] **`matched_records` added to all five schemes' Exp. 2.** §VI claims
      "query selectivity is kept constant" and nothing recorded the quantity
      that claim is about: `n_eff` means matched entries for the proposed
      scheme, `entries_traversed + forward_evals` for [35], tree nodes for [30],
      candidates examined for [54], and [41] had none. All five now emit the
      match count under one name, so selectivity is comparable across Fig. 2's
      shared axis for the first time.
      [41] needed its `Measurement`/`Run` widened to a third secondary and its
      hardcoded CSV header extended. Verified in `results.csv`.
      Regression **900 passed / 5 skipped / 0 failed**.

- [x] **A2 the four PSA corpus ports.** `PsaExp3CrossDomainTokens`, `PsaExp4`
      and `PsaExp5` are now `CORPUS_BACKED`, drawing policies and keywords from
      the corpus instead of inventing `hospital/pol0` and `kw:00042`.
      Verified: Exp. 3 tokens `q*d` (10 at d=2, 20 at d=4) with Option D flat at
      q=5; Exp. 5 retokenizes 102 at k=100 and 1002 at k=1000, unchanged from
      banked, so the port preserved behaviour.
      Two hardcoded `keywords_per_record = 6` constants replaced by the source's
      own figure — the frozen corpus's mean |W_i| is **31.70**, so both were
      wrong by ~5x, and in Exp. 4 that constant sets the Merkle leaf count the
      proof paths are measured against.
      **`PsaExp6` is deliberately NOT `CORPUS_BACKED`** — it takes the corpus
      vocabulary but must stipulate its policy topology, because it sets the
      governing sets itself to make the affected ratio exact, and because
      `extract` yields **8** policies at four domains where §VI's 10% step needs
      at least ten. Documented in `policy_population`; §VI must say the arm's
      policy dimension is constructed.
      Regression **900 passed / 5 skipped / 0 failed**.

- [x] **D1 Committed** as `3114495` — named columns, fingerprint, `domains: 4`,
      the UTF-8 crash, `parse_experiments`, `collect()` folder precedence and
      both de-flaked tests, with evidence and results-affecting flags in the
      message. Tree clean.
- [x] **D2 Findings migrated to `SystemConfiguration.md` §10.** Eight new
      entries (Table I errors, the unachievable q=5 conjunctive claim, the
      unfalsifiable selectivity claim, the PSA track's missing AIM check, two
      §V Exp. 6 corrections, Exp. 5's zero, 97 dangling citations, the parked
      cross-node-forward decision) and two corrected
      (`secondary_metrics`; the construction question, now decided: PSA).
      `test_document_config_agreement` green.

- [x] **A1 `domains: 4`** — `build_deployment`, `psa_build_deployment` and
      `PsaExp1`'s `corpus_world` call now default to
      `config.defaults.domains` instead of `len(source.domains)`.
      Proven on a **10-domain** source (the corpus case): both builders return
      **4** domains and 4 AAs, while an explicit `domains=10` still returns 10
      so Exp. 3's `d = 2…10` sweep is untouched.
      Regression **900 passed / 5 skipped / 0 failed**.
      *Results-affecting for Exps. 2, 4, 5, 7, 8 — those banked runs used ten
      domains and ten AAs.*

- [x] Step 1 instrumentation — `construction`, `ledger_backend`, host-caveat
      note, corpus/construction homogeneity guard, strict panel gate.
- [x] Exp. 3 `q=1→5` and per-domain sizing — `trapdoors_issued` 1→**5**;
      latency 0.076→**25.75 ms** at d=2 (index was 8 records, now 20,000).
- [x] `PsaExp3CrossDomainLatency` — §VI Fig. 3 had no PSA source. Issues `q·d`
      tokens (10 at d=2, 20 at d=4).
- [x] `psa_exp3` `option_d_tokens_issued` literal `1.0` → `len(keywords)`; it
      compared trapdoors against tokens, understating Option D by q.
- [x] **Named columns** — `cross_node_forwards_mean`, not `secondary_2_mean`.
      Proven on a deliberately reordered file: position→1.0 (wrong),
      name→0.0 (correct).
- [x] **Measurement fingerprint** — detects a changed `measure()` when names and
      shape are identical (the `exp5` case). Five properties verified.
- [x] Two flaky exp6 timing tests rewritten to assert exact quantities —
      20/20 and 15/15, from 8/10 and 14/15.
- [x] `generate_plots.py` UTF-8 crash — 1 figure → **8/8** on a cp874 console.
- [x] `parse_experiments` was construction-blind — a PSA campaign silently
      skipped experiment 10 and errored on 9.
- [x] `collect()` drew a different experiment's data under the new spec's label
      — the Fig. 8(c) defect by another route.
