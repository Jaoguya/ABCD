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
That cost was live when this file was written, and larger than either figure.
Two families, counted separately because they were found separately:

| family | live references | files | fixed by |
|---|---|---|---|
| **by filename** — `SCHEME.md`, `MANUSCRIPT_DIVERGENCE.md`, `PHASE_III_PLAN.md`, `PHASE_IV_PLAN.md`, `README.md`, `infra/fabric/README.md` | **79** (of 130 matches; the other 51 are history or banked `run_meta.json`) | 48 | D3 |
| **by section of `README.md`** — `§N`, `section N`, and the mojibake `S N` | **333** | 87 | D4 |

**412 in all, and all closed as of 2026-09-10.** The per-document split of the
79 was never measured, so it is not stated here; the 130 raw matches were
`SCHEME.md` 44, `MANUSCRIPT_DIVERGENCE.md` 35, `README.md` 23,
`PHASE_IV_PLAN.md` 16, `PHASE_III_PLAN.md` 12.

Two tests now hold the line: `test_no_source_file_cites_a_deleted_document` and
`test_no_source_file_cites_a_section_of_the_deleted_readme`. What still matches
those names in the tree is history — accounts of the deletion, not pointers.

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

- [ ] **A10 Retire the `option_d` EXPERIMENT TRACK — classes Exp1-Exp6 and
      Exp9 plus their `EXPERIMENTS` registry entries — after B2.**
      *(Scope and timing DECIDED by the user 2026-09-10.)* Not a deletion of
      `option_d`: step 4 wired PSA onto its `build_deployment`,
      `SchedulerAblation`, `Exp7/8` and `index/dsi.py`, so the shared Phase I-V
      scaffolding stays. Retiring after the campaign keeps a working fallback
      and a comparison baseline while PSA produces its first numbers. Until
      then the twin-drift hazard is contained by the `construction` field and
      the homogeneity guard, which refuse to draw both on one axis.


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
- [ ] **B2a PROBE FIRST — one point per experiment on the pinned host.**
      *(DECIDED by the user 2026-09-10.)* **The campaign cannot be priced from
      this repo.** `runtime_estimates.csv` holds exactly ONE measured row for
      the proposed scheme (`exp7_8`, 2026-08-29) and a TOTAL row that guesses
      *"exp1-6 ~0.25h"* with no basis; experiments 1-6 have no estimate at all.
      That row predates A5 (`Exp7.prepare` 2 s -> 58.3 s), Exp. 3's per-domain
      sizing (40 records -> 10,000 x d) and the PSA port. The four baselines
      ARE measured: 47.8 h for a full re-measure, 17.9 h of it Exp. 3 alone.
      The probe also exercises the PSA path on real corpus data for the first
      time, and **closes E2**, which needs exactly this host and corpus.
- [ ] **B2 One campaign** — re-measure Figs. 2–8 under PSA, priced from B2a.
      **NEEDS AWS SPEND APPROVAL.** Never launch Ref[41] Exp. 2 above N=10⁴.
      Run one point through `--require-reportable` first; the guards now
      hard-fail rather than drawing an unverified panel.
- [ ] **B3 Regenerate all figures**; the Step 1 guards must pass unaided.

## C. Manuscript (after B)

- [ ] **C5 §VI query arity — DECIDED (a), user 2026-09-10: name the exception
      at tex:2179; leave tex:2544 alone.** Two sites carry the claim, and
      tex:2179 is the one that covers every scheme: *"Unless otherwise
      specified, each query contains five keywords."* Schemes [30] and [41] are
      single-keyword **by construction** — Ge et al. p7 defines queries as
      `q = (w, alpha(u))`, "single keyword queries", and calls conjunctive
      Boolean "an interesting open problem"; Thingom's Search phase takes "the
      keyword w_w" and builds one `CS_w` per file. The harness is faithful in
      all four cases, so only the prose changes. Agreed wording:
      *"...each query contains five keywords; Schemes~\cite{ref30} and
      ~\cite{ref41} are single-keyword constructions and are evaluated at
      $q=1$."* tex:2544 needs no change: Exps. 7-8 are a proposed-scheme-only
      ablation, where $q=5$ is true.

- [ ] **C6 §VI Exp. 2 selectivity — DEFERRED TO THE DATA (user, 2026-09-10).**
      `matched_records` now exists in all five schemes, so "query selectivity
      is kept constant" is checkable for the first time — but only once B2 has
      run. The user will edit §VI to match the measured result rather than
      deciding the sentence in advance.

- [ ] **C8 §VI environment.** Host is unpinned (`pin_configured: false`), BLAS
      was never pinned in any banked run, and §VI claims one `m6i.xlarge`.
- [ ] **C9 §V Exp. 4 — the "within 2% at every $r$" sentence (tex:2419) is not
      supported. RE-DERIVED 2026-09-10; the wording is yours.**
      Two independent failures, from banked `raw_runs.csv`, n=10 per point:

      **1. The tolerance is exceeded at three of five points, and the gaps are
      real, not noise.** Per-result cost (primary / r), psa vs option_d:
      r=10 +1.67% (p=0.05, CIs overlap) · **r=50 −3.09%** (p=4e-06, DISJOINT) ·
      **r=100 −2.30%** (p=5e-05, DISJOINT) · **r=500 −2.28%** (p=1e-31,
      DISJOINT) · r=1000 −0.40% (p=0.45, overlap). Note the sign: PSA is
      *faster*, which the sentence's reasoning does not predict either.

      **2. The two runs are not comparable, which is why.**
      `exp4_verification_overhead` is `reportable: true` on the frozen corpus;
      `psa_exp4_verification_overhead` is **`reportable: false`** —
      `corpus_type='psa_in_process'`, no corpus SHA-256 — and was taken at a
      different commit (`4ebbcb6` vs `74472f1`). The giveaway is in the data:
      PSA's `path_length` is **exactly 3.000, ci95 0, at every r**, while
      option_d's moves 5.60 → 4.78. A Merkle path constant across a 100x change
      in `r` means the fixture rebuilt the same 8-leaf tree every time;
      option_d verified against ~27 leaves. Its proof is 1.87x larger at every
      point (153.9 KB vs 96.7 KB at r=1000). **So the −2 to −3% is tree size,
      not the commitment fields**, and §V's stated mechanism ("dominated by the
      per-record ledger lookup") is not what the numbers measure.

      **B2 settles it.** Once both constructions run on the frozen corpus under
      one commit the comparison becomes valid and the sentence can be written
      to the result — same treatment as C6. Until then it should not ship.

## D. Hygiene

*(empty — D3 and D4 both done, see below)*

## E. Blocked / pending someone else

- [x] **E1 RESOLVED — keep the cross-node-forward metric and §V's reading.**
      *(DECIDED by the user 2026-09-10.)* The counter was moved out of the
      non-AASS branch, so §VI's scheduler-agnostic definition now applies to
      all four arms: **aass 0, no_lb 288, round_robin 168, least_loaded 288.**
      AASS still reads 0, but because its eligibility guard never misplaces a
      shard — a measurement rather than a tautology. No manuscript change.

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

- [x] **C7 CLOSED — no change (user, 2026-09-10). Exp. 6's design is correct;
      the concern was overstated here.** Two claims in the earlier entry were
      wrong and are withdrawn:
      1. *"The policy topology is stipulated, so Exp. 6 does not price the
         corpus."* The **keywords are the corpus's** (`psa_experiments.py`:
         *"REAL keywords, so the hashed inputs are the corpus's own lengths"*),
         so the timed cryptographic work uses real input sizes.
      2. *"Constructing the governance is a defect."* It is the **swept
         variable**: `affected_count = round(ratio * len(policies))` and the
         overrides set exactly that many policies to depend on the moved
         authority. An affected ratio cannot be read off a corpus; it has to be
         set. The code also controls the obvious confound — "every policy keeps
         two governors, so the arms differ only in propagation scope and not in
         per-policy work."
      The 10%-vs-12.5% arithmetic is real but harmless: with 40 policies the
      figure shows exactly the 10%->100% sweep §VI describes, so **text and
      figure agree**. What remains is a gate misfiring — `corpus_type != synthea`
      marks the run non-reportable, but that gate exists to stop *cross-scheme*
      comparisons mixing corpora, and Exp. 6 compares three arms of one scheme.
      **It does not gate B2.** That was true only of the option being argued
      against (raising `policies_per_domain`, which would have reshaped the
      index for Exps. 2, 4 and 5).
      The two §V corrections stand independently, for whenever §V is next
      touched: the selective advantage is in **bytes, not time** (the
      DIAS-vs-Incremental-All latency gap is ~2%, noise in both directions),
      and the narrowing at a full ratio is **not total** — work converges
      10x->1x but delivery only 40x->4x.

- [x] **C1 + C3 + C4 — Table I rebuilt and applied to the manuscript by the
      user, 2026-09-10.** All thirteen rows re-verified against the papers, a
      `ref30` row added, and a third symbol `$	riangle$` introduced for partial
      support. **10 of 13 rows changed, 20 cells** — 15 upgrades, 5 downgrades.
      Every prediction made from the paper titles held: `ref54` Blockchain and
      Multi-Keyword ✗→✓ (C1, both), `ref52` Multi-Authority and Multi-Keyword
      ✗→✓, `ref53` Multi-Authority ✗→✓. `ref35` was unchanged, matching the
      independent 7/7 PDF check.
      The `ref30` row is the one cell-set taken from this side:
      `✓ ✓ ✗ ✓ ✗ ✗ ✗`, Blockchain resting on Ref[55].pdf p5 *"In this work, we
      design a new verification algorithm based on the Ethereum smart
      contract"*. `$	riangle$` needs no new package — `amssymb` is already
      loaded.
      *Verified mechanically against the user's grid:* 14 rows in citation
      order, 7 cells each, 0 unrecognised, environments balanced, no baseline
      row full even counting partials — so §II's "first to unify" claim at
      tex:332 still holds (closest: `ref54` 4.5/7, `ref48` 4.0/7).
- [x] **C2 RESOLVED by the new table — keep `ref41` in the lattice/PQ prose.**
      The recommendation to drop it from tex:139 and tex:332 rested on Table I
      marking it ✗ for Lattice/PQ. The verified table marks it **partial**, so
      the prose listing it among post-quantum approaches is defensible and the
      `$	riangle$` carries the qualification. No manuscript change.

- [x] **Rule 3 restored — the D4 guard had come to cite this file.** Two lines
      of `test_document_config_agreement.py` named `REMEDIATION.md`: an entry in
      the exclusion list and a comment explaining it. Both would have become
      dangling references the moment this file is deleted, which is the exact
      failure this file exists to clean up. **Caught by asking whether the
      tracker could be deleted yet, not by any test** — a guard cannot see a
      violation written into its own exclusions.
      Fixed by scanning no repo-root prose at all: the two surviving prose
      documents are already covered by
      `test_documents_cite_only_paths_that_exist`, and a document whose
      *subject* is the deletion has to be free to name what was deleted.
      *Verified:* nothing in the repo cites this file; coverage unchanged at
      421 files; every remaining exclusion is reachable, so none is decoration;
      both guards still fire on an injected violation and revert clean.

- [x] **D4 — every citation to a section of the deleted `README.md` is gone.**
      **333 live references across 87 files**, in four spellings: `README §5`,
      `README's §7`, `README section 5`, and the mojibake `README S6` a
      non-UTF-8 write left behind. Two were invisible to a `§` search.
      **Verified against the recovered file, not guessed.** README.md was
      recovered from `e503655^` (998 lines, 17 sections). §1 Environment,
      §4 Dataset, §6 Default Parameters, §7 Measurement Methodology and
      §9 Output Format all matched their citations exactly — **drift was
      confined to §14**, whose ~20 citations split between the Ground Rules
      (§13 in the recovered file) and the numbered Open Issues (§14). A fifth
      of them pointed at the wrong section *before* the file was deleted.
      **Executed as the hybrid, in three passes:**
      *82 deleted* — parentheticals whose whole content was the citation, where
      the sentence already states the fact ("mean ± 95% CI (README §7)").
      *241 repointed* — facts a config file owns now cite that file
      (`global.yaml` for defaults, methodology and units; `dataset.yaml` for the
      corpus), which is SHORTER than what it replaced and follows the repo's own
      rule that a number is read from the file that owns it. Everything else
      cites `SystemConfiguration.md` **with no section number**: the number is
      the part that rotted, and a bare filename cannot develop that fault.
      *10 by hand* — the `§14 issue #N` sites, whose issue numbers exist nowhere
      now, repointed at `scheduler.yaml` (the λ sweep) or reduced to the fact.
      **Reflow cost measured before choosing:** repointing by section NAME would
      have pushed 297 lines past 88 chars and, worse, put bare `"` inside
      f-strings — a syntax error. The config-file form cost **one** line over
      100 chars, and that line was already long.
      *Verified:* 0 live references remain (10 survivors are all history or the
      resolver table); every edited `.py` compiles, every `.yaml` parses, every
      `.sh` passes `bash -n`; the 131 changed code lines are argparse help,
      messages and comments, and no test asserts on any of them.
- [x] **Guard for D4** —
      `test_no_source_file_cites_a_section_of_the_deleted_readme`. Proven
      non-vacuous: an injected line carrying all three spellings fails it, each
      named in the message; reverted clean.
- [x] **Two stale `--runs 30` claims corrected**, both contradicting
      `global.yaml`'s 10 and found while rewriting the lines around them:
      `main.py`'s module docstring printed a `--runs 30` command, and
      `harness/runner.py`'s docstring said a failed run is re-run "to restore
      n = 30" seven lines after stating "10 runs after 5 discarded warm-ups".
      `test_repetition_count_agreement.py` exists to catch exactly this and
      scans only `SystemConfiguration.md` and `CLAUDE.md`, so it could not see
      either.

- [x] **Structural guard for D3** —
      `test_no_source_file_cites_a_deleted_document` scans **419** source files
      for the four deleted design documents. Proven non-vacuous: injecting
      `PHASE_IV_PLAN.md` into `index/extract.py` fails it by name, and the
      injection was reverted. The prose half was already covered by
      `test_documents_cite_only_paths_that_exist`; nothing covered source
      comments, which is where 79 of the 79 lived.
- [x] **`README` section 10 (figure conventions) rescued** into
      `SystemConfiguration.md` "Figure conventions". `generate_plots.py` cites
      it as "followed exactly" — vector PDF, 3.5 in single column, 8 pt
      minimum, 95% CI on every point, log x for Exps. 2/5/6, marker *and* line
      style so figures survive grayscale — and it existed nowhere in the tree.
      (`README` section 3's native-mode rule needed no rescue: it is already in
      section 5's measurement boundaries.)
- [x] **Corrected a claim the PSA port had made false.**
      `SystemConfiguration.md` section 5 said "All `psa_*` runs are built on
      in-process synthetic data and are `reportable: false` by construction".
      `psa_exp1/2/7/8` are corpus-backed, and every manuscript figure now
      draws from `psa`.

- [x] **D3 — every dangling citation to the five deleted documents is gone.**
      The recorded figure of 97 was low: **130 hits**, of which **79 were live
      pointers** and the rest history. All 79 rewritten across 48 files.
      Two forms: a pointer whose target survives goes to the surviving section
      (`README §5` → `SystemConfiguration.md` section 5, `README §9` → section 7,
      `infra/fabric/README.md` → section 13); a pointer to a *decision* keeps
      the identifier and loses the path (`` ``PHASE_IV_PLAN.md`` §1.3`` →
      `Phase IV §1.3`, `` ``MANUSCRIPT_DIVERGENCE.md`` D1`` → `divergence D1`).
      `SystemConfiguration.md` section 8 gains a resolver table — the six
      documents, what each held, where its substance went — so a bare
      "Phase IV decision 6" has exactly one place that explains it, in a file
      that exists.
      **Deliberately not touched, and why:** 18 hits in banked `run_meta.json`
      (machine-written records of what the code said at run time — editing them
      would falsify provenance; the string's source in `main.py` is fixed, so
      future runs carry the new wording), and 12 history statements in
      `CLAUDE.md`, `.claude/`, three test comments and this file, which
      describe the deletion rather than point at it.
      *Verified:* `grep -rE` over the tree returns only those two classes plus
      the new resolver table; 48 edited files compile / parse as YAML;
      `test_document_config_agreement` + `test_repetition_count_agreement` +
      `test_cost_table_agreement` + `test_phase1_2` → **188 passed**.
      *Found while there, and fixed:* `main.py`'s module docstring printed
      `--runs 30` against a config of 10 — the exact defect
      `test_repetition_count_agreement.py` exists to catch, in a file that
      test does not scan (its list is `SystemConfiguration.md` and `CLAUDE.md`).

- [x] **A7 + A3 — the manuscript figure set now sources PSA.** All eight
      `fig_exp<N>_*.pdf` specs point at `psa_*` folders, Fig. 6 included (which
      also closes A3: §VI's Exp. 6 describes the affected-policy-ratio sweep,
      which is `psa_exp6`, not the δ sweep that was being drawn).
      **A latent bug surfaced doing it:** `proposed_prefix` only took effect
      through `collect_mixed`, which runs only when `proposed_variants` is also
      set — so specs naming a `psa_` folder still globbed `exp<N>_*` and drew
      **Option D**. Verified: Fig. 3's proposed series came back as
      0.076/0.106/0.123 ms, the pre-fix Option D numbers. Fixed; Fig. 2 now
      draws 0.340 (psa_exp2) where it drew 0.486 (option_d).
- [x] **A5 Exp. 7/8 index sizing** — `index_size` in RECORDS, matching Exp. 2.
      Was `// keywords_per_record`, i.e. ~3,125 records against Exp. 2's
      100,000 at the same configured value.
      Cost: `Exp7.prepare` went from ~2 s to **58.3 s**, so the test suite now
      uses a 2,000-record index for Exps. 7-8 only (`_TEST_INDEX_SIZE`) —
      production keeps the value §VI describes.
- [x] **A6 `C_j^sync`** — the CODE was always right (`aass.sync_lag` computes
      the published set cardinality). `scheduler.yaml` described it as
      `|VID_U - VID_j|`, a scalar, and labelled that *published*. Config
      corrected to eq:search-cost.
- [x] **A8** — the Exp. 3 d-independence test is narrowed to Option D and
      renamed `test_exp3_trapdoor_count_is_an_option_d_property_only`. Kept
      rather than deleted: it guards the construction it describes, and §VI's
      Exp. 3 text never claimed the single-trapdoor property.
- [x] **A4 — all four baselines now fix PER-DOMAIN index size** at 10,000
      (`PER_DOMAIN_INDEX_SIZE`), per §VI. They fixed *total* at 100,000 and
      sharded by `d`, so each shard shrank as `d` grew — which is why [35]'s
      Exp. 3 latency *fell* across the sweep.
      *Results-affecting for four published baselines; §VI needs a disclosure
      sentence (section C).*

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
