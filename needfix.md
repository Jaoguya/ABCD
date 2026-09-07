# needfix — what needs fixing, per experiment

**This file and `checkexp.md` are the only two you need.** `checkexp.md` tracks
*which* experiments have been checked and how deep; this tracks *what came out
of it* and what to fix. Each item carries its own evidence — file and line,
measured numbers, why it matters — so nothing here needs a third document.

**One rule, and it is the one the retired `DO_NOT_READ/remainfix.txt` and
`DO_NOT_READ/TASKS.md` broke:** no finding is recorded twice. Keep new items
self-contained rather than pointing elsewhere.

Tags: **[FIXED]** done, verified · **[OPEN]** mine to do, no decision needed ·
**[DECIDE]** needs an author call · **[BLOCKED]** cannot proceed until something
else lands · **—** a standing note, not an action.

Last updated 2026-09-07, second pass.

**Only Exp. 2 and Exp. 3 are finished.** All eight were passed over and every
one produced findings, but the seven-question checklist was NOT run end-to-end
on the other six — see `checkexp.md`'s coverage matrix for exactly which
questions were asked of which experiment. Items below are real findings; the
ABSENCE of items for Exps. 1 and 4-8 is not evidence that nothing is there.

The three coverage gaps that leaves are tracked as G-1..G-3 below.

---

## Coverage gaps — the checks not yet run

These are not findings about an experiment; they are checks `checkexp.md` says
were never performed. Each is one focused pass, and each has already proved
productive on the experiments where it WAS run.

| # | Tag | Item |
|---|-----|------|
| G-1 | **[FIXED]** | **§VI-claims-vs-data has now run on all four outstanding experiments — 7 and 8, then 4 and 6 (2026-09-08). Items 7-3, 8-2, 8-3, 4-3, 4-4, 6-4; 6-2 withdrawn.** The gap is closed. It is the question that produced the largest findings on both deep passes — Exp. 2's selectivity (x23.2 against a claimed x100) and Exp. 3's "baselines accumulate domain-local search overhead" (contradicted by guo and thingom both being flat). Exp. 7's throughput ordering and Exp. 8's utilization spread — the two headline scheduler results — are now checked: the ordering and the three utilization claims hold, one qualifier and panel (c) do not. Exp. 4's "highest per-result cost" holds at all five shared r; its "within 2%" sentence does not (3 of 5 points, CIs disjoint). Exp. 6's five claims all hold, and checking them withdrew 6-2 |
| G-2 | **[FIXED]** | **The banked `psa_*` directories are being compared against their Option D counterparts, experiment by experiment.** Done: `psa_exp1` (4 arms, 1-7), `psa_exp2` (2-6), `psa_exp3`, `psa_exp5_retokenization` (5-5, 1.01x–1.48x), `psa_exp7` + `psa_exp8` (8 arms, **7-5 — the ablation collapses**). **All done 2026-09-08** — `psa_exp4` (4-5) and `psa_exp6` (6-5) were the last two. G-2 is closed. Original note: Where this WAS run it mattered: Exp. 2's psa/option_d gap is 2.2x at N=10^6, and it is the open question in 2-6 |
| G-3 | **[OPEN]** | **Test coverage was only examined for Exp. 2.** Only Exps. 2, 6 and 9 have a dedicated test file; 1, 3, 4, 5, 7 and 8 have none, and what `test_harness.py` covers for them has not been read. On Exp. 2 this question found five missing pins, including `n_eff >= 0` passing on an empty result |
| G-4 | **[FIXED]** | ~~`psa_exp5_retokenization/` is banked under a different experiment NAME than `exp5_keyword_update`.~~ **Resolved 2026-09-08: they genuinely measure different things, and the names are right.** Under Option D a policy change re-policies index entries WITHOUT re-tokenizing — `test_synchronize_reports_the_exp5_metrics` asserts `tokens_rewritten == 0` for exactly this reason — so the Option D experiment is a keyword UPDATE. Under the PSA construction the token embeds `PID` and `PV`, so the same policy change forces re-tokenization, which is a different operation with a different cost (1.01x–1.48x of Option D). Two names for two operations. What §VI still owes is a sentence saying so, which is the substance of 5-4 |

---

## Cross-cutting

| # | Tag | Item |
|---|-----|------|
| X-1 | **[FIXED]** | `README.md` deleted 2026-09-07 on the author's instruction. The six tests that read it were removed; `SCHEME.md` cross-links and `CLAUDE.md` retargeted to `SystemConfiguration.md`. What was rescued and what is still dangling are D-1 and D-3 below |
| X-2 | **[FIXED]** | Nothing checked that schemes in one figure ran under the same `global.yaml`. Check added to `generate_plots.py`; fires on exp1, exp2, exp3, exp5 |
| X-3 | **[OPEN]** | `perera` and `yue_ge` never read `global.yaml` — `--runs`/`--warmup` are hardcoded argparse defaults that happen to match it. Four CLIs; changes no banked number |
| X-4 | **[OPEN]** | `test_psa_exp6_arms_rank_the_way_the_manuscript_says` is a wall-clock comparison with no tolerance — it asserts `dias <= everyone` on raw medians. Now **2 failures in 7 full runs** (0.598 vs 0.577 ms, a 3.6% margin), passing 3/3 when run alone. It fails only under full-suite load, which is the machine, not the claim. Give it a tolerance or raise the ratio to where the arms actually separate |
| X-5 | **[DECIDE]** | Config-hash drift on exp1, exp3 and exp5 is unexamined. Exp. 2's was diffed and proved benign; the other three have not been |
| X-6 | **[BLOCKED]** | **BLAS threading was never pinned in any banked run.** 114 `run_meta.json` files checked: 67 have no `thread_pinning` key, 47 have it all-null, **0 pinned**. `global.yaml` sets `blas_threads: 1` and `provision.sh` exports it, but a non-login ssh shell never sources it. numpy's BLAS claims every core, and the campaign stopped being single-instance-type on 2026-08-30, so latency across 4-vCPU and 16/32-vCPU hosts is not comparable — exactly what the pin exists to remove. `provenance.py` now gates on it (`verify_thread_pinning(require=True)`), so every FUTURE run blocks until the vars are exported, and every PAST run was stamped reportable without them. Fix in-process — set the four vars from `global.yaml` before numpy imports — not in a shell script |
| X-7 | **[OPEN]** | `run_meta.json`'s `secondary_metrics` field arrived in `5143ee7`; no banked run carries it. The panel/label agreement check added in the same commit therefore cannot verify any existing figure — it only warns |

### Config sync, 2026-09-07

Configs were synced against `Overleaf/MA-LB-PQ-VDSE.tex` §VI. No measured number
moves from any of it — these are restatements, comments and one sweep that had
been living in the wrong file.

| # | Tag | Item |
|---|-----|------|
| C-1 | **[FIXED]** | `index.yaml`'s `corpus_reference` block still described **corpus v2** (1,141,072 records, 2,006 keywords, 4 domains) while `dataset.yaml` had been pinned to **v4** (1,143,792 / 2,023 / 10) since 2026-08-28 — the two configs disagreed about which corpus the benchmark runs on. `CorpusReferenceError` guards this but compares against the manifest, which is git-ignored, so it never fired on a machine without a corpus. Synced, and pinned by a new test |
| C-2 | **[FIXED]** | `\|P_U\| ∈ {1,2,4,8}` is a **published** §VI Exp. 1 sweep that lived only in code (`psa_experiments.POLICY_SCOPES`). Moved into `global.yaml` as `exp1.policy_scopes`; a new test asserts the two cannot drift. Values unchanged |
| C-3 | **[FIXED]** | Exp. 7/8's `values` carried "Section VI must be updated to state the full 100-10000 range". §VI now does state it, so the range is `published`, not an unratified extension |
| C-4 | **[FIXED]** | `yue_ge` was labelled Ref[55] in config comments; §VI now cites it as `\cite{ref30}` (Peony++). Renamed to Scheme [30] per the Scheme30/35/41/54 convention |
| C-5 | **[FIXED]** | 46 dangling `README §N` citations across all 7 config files retargeted to `§VI (…)`, `SystemConfiguration.md` or `needfix.md`. `planning/runtime_estimates.csv` left alone — it records what was measured at n=30 and rewriting it would falsify the record |
| C-6 | **[FIXED]** | `global.yaml` bumped to `version: 2` with an `updated:` date, and its header now states the sync explicitly: sweeps are the points the FIGURES draw, not a whitelist — a scheme may measure a superset, and several do. Nothing in the file refuses to run |
| C-7 | — | `corpus.reportable_types: [synthea]` was deliberately **left strict** and annotated as such. It is the one gate whose loosening would let invented data be stamped reportable |

### Deletions, 2026-09-07

| # | Tag | Item |
|---|-----|------|
| D-1 | **[FIXED]** | `README.md` (998 lines) deleted. AWS estate — both AMI IDs, six instance IDs, both SSH keys, the no-Elastic-IP warning, the sshd recovery runbook, the stop-never-terminate rule, the bundle-harvest `git add -A` trap — rescued into `SystemConfiguration.md` §15 first, verified present. `infra/fabric/README.md` rescued into §16 |
| D-2 | **[FIXED]** | `Overleaf/drafts/evaluation_setup.md` deleted. It claimed **n=30** against a n=10 campaign, restated corpus v2, and described a three-baseline evaluation including two dropped schemes (Zhuang [52], XB-Muse [36]). Nothing referenced it; nothing worth rescuing |
| D-3 | **[OPEN]** | ~320 `README §N` prose citations remain in harness docstrings, dangling by decision ("exclude reference"). One pass would retarget them |

---

## Exp. 1 — Policy-state-aware token generation · FULL pass 2026-09-08

Brought to spec upstream in `5143ee7`. The code is right; the banked data is
not — the figure now draws arms that predate the fix that makes them
reportable.

**All seven checklist questions ran 2026-09-08.** The construction is in
excellent shape: `|T_Q| = q·|P_U|` holds **exactly at all 20 cells**, the
per-token cost is flat, and the factorization-independence the `tab:cost` row
claims is measurable. What is weak is the DATA (1-2) and one comparison
sentence (1-7).

| # | Tag | Item |
|---|-----|------|
| 1-1 | **[FIXED]** | `test_exp1_tokens_are_distinct` was never given the `source` fixture when Exp. 1 became corpus-backed. Fixed |
| 1-2 | **[BLOCKED]** | **Fig. 1's proposed-scheme curves are not reportable.** `5143ee7` pointed the figure at the four `psa_exp1_token_generation__pu<N>` arms (`proposed_prefix="psa_"`), and all four bank `corpus_type: psa_in_process`, `reportable: false`. The code fix making Exp. 1 corpus-backed is in; the DATA predates it. `experiment1_clarify.md` says a smoke run closes this in minutes, not a campaign |
| 1-3 | **[OPEN]** | Config-hash drift: 3 different `global.yaml` revisions across the figure. **Resolved to which is which, 2026-09-08:** `1b8f5819…` for all four proposed arms, `032de0d9…` for `[30]`/`[35]`/`[41]`, `8172f55e…` for `[54]`. The split is clean — every curve of a given scheme shares one revision — and the observable parameters agree (all eight sweep q ∈ {1,5,10,15,20}, all `n_runs=10`). Still not a key-level diff of the three revisions, which is what closes it |
| 1-6 | **[DECIDE]** | **The four proposed curves and the baselines are not the same quantity at a given `q`.** Fig. 1's x-axis is `q` for all eight curves, but at `q` the proposed `|P_U|=8` arm generates **8q tokens** where every baseline generates `q` trapdoors — the baselines have no `|P_U|` dimension, so they sit at an implicit `|P_U|=1`. The direction is conservative (it charges the proposed scheme 8x the work), so this is not the Exp. 2 / Exp. 3 sizing defect. But §VI never says which of the four curves is the comparator, and a reader comparing the topmost proposed curve to `[30]` is comparing 160 tokens against 20. Name `pu1` as the like-for-like curve, or state the factor |
| 1-7 | **[DECIDE]** | **§VI's Exp. 1 claims VERIFIED except one comparison (G-1, 2026-09-08).** Holding: `\|T_Q\| = q·\|P_U\|` **exact at all 20 cells**; "approximately linear growth" — cost per token is **6.30–6.99 us across 19 of 20 cells**, the twentieth being `q=1, \|P_U\|=1` at 10.67 us, i.e. the fixed-cost end of a one-token query; and the same `\|T_Q\|` reached by different factorizations agrees to **1.01x–1.13x** (`\|T_Q\|=80` via q=20,\|P_U\|=4 and q=10,\|P_U\|=8 differ by 1%), inside the 1.35x pin. **Not holding as a reader will take it:** "MA-LB-PQ-VDSE maintains relatively low online preparation cost". Scoped to its own sentence — "compared with schemes whose trapdoor construction involves attribute-dependent group operations or more expensive cryptographic processing" — it is true and by a wide margin (`[41]` 412 ms, `[54]` 1.71 ms at q=20 against our 1.01 ms worst-arm). But the proposed scheme ranks **3rd of 5 at every q**, sitting above `[30]` (0.078 ms) and `[35]` (0.0099 ms) — 13x above `[35]` even on the `pu1` arm. Exp. 4 owns being the highest and explains why; Exp. 1 should own being third the same way. Non-reportable (`psa_in_process`) pending 1-2; one point is one `q`; `psa`; measured |
| 1-8 | **[OPEN]** | Test coverage for Exp. 1 is **strong, contrary to G-3's blanket wording** — 13 tests across 5 files, and the two claims that matter are pinned: `test_exp1_token_count_is_the_product` (the identity) and `test_psa_exp1_cost_depends_on_the_product_not_its_factorization` (the `O(\|T_Q\|)T_H` shape). `test_search_token_generation_touches_no_kem_or_pairing` pins both "avoids pairing, exponentiation, or lattice operations" and the ML-KEM exclusion. **One §VI claim is unpinned:** "only policies satisfying `S_U ⊨ P_ℓ` contribute tokens" — nothing fails if an unsatisfied policy starts contributing. Write it |
| 1-4 | **[DECIDE]** | 1.7b: §IV should state that `H` is keyed HMAC-SHA256; §V's leakage model requires it. (1.7 marked pass by the author) |
| 1-5 | **[OPEN]** | `exp1_trapdoor_generation/` (Option D) is banked and reportable but no longer plotted — the mirror image of Exp. 2, where the psa arm is banked and unplotted. Keep or retire it deliberately, not by accident |

---

## Exp. 2 — Search latency · FULL pass 2026-09-07

| # | Tag | Item |
|---|-----|------|
| 2-1 | **[FIXED]** | `N` was sized as index **entries** (`N // keywords_per_record`), so at N=10^6 we indexed 31,250 records against every baseline's 1,000,000 — a **32x** gap, under an axis reading "(records)". The same defect Exp. 4 already had fixed. Corrected in both constructions |
| 2-2 | **[FIXED]** | Query issued **q=1** against §VI's five. The anchor is still drawn at the baselines' selectivity; the other q-1 now come from a record carrying it, so the conjunction is answerable (`n_eff = 15.0`, not 0) |
| 2-3 | **[FIXED]** | No test pinned q, the record sizing, or that the search matched anything — `n_eff >= 0` passes on the empty result, the bug that hid in guo for 150 runs. Five tests added |
| 2-4 | **[FIXED]** | Memory guard added: a point that cannot fit now refuses instead of arriving as SIGKILL |
| 2-5 | **[BLOCKED]** | Corrected Exp. 2 does **not fit the pinned host** above N=10^5: ~3.6 GB at 10^5, ~18 GB at 5x10^5, ~35.9 GB at 10^6, against 16 GiB. Either use the larger-memory host guo's Exp. 2 already needs, or extrapolate the top two points. Blocks the re-run |
| 2-6 | **[DECIDE]** | Does §VI's Exp. 2 report `option_d` or `psa`? The prose says "policy-state-aware token set" (psa), the figure draws `option_d`, and Exp. 1 moved to psa in `5143ee7`. Gap is 13.400 vs 6.040 ms at 10^6. Decides what the re-run runs |
| 2-7 | **[DECIDE]** | §VI claims "query selectivity is kept constant… matching records increase proportionally". Measured: N x100 gives `n_eff` x23.2. Either build a relative selectivity band, or drop the two sentences |
| 2-8 | **[BLOCKED]** | The banked `exp2_search_latency/` numbers are **superseded** — measured at q=1 over a 32x-small corpus. Not quotable until the re-run |

---

## Exp. 3 — Cross-domain search scalability · FULL pass 2026-09-08

The worst workload mismatch found so far. Questions 6 and 7 — the two the
matrix still had at `~` — were closed 2026-09-08, and 3-5 was fixed.

| # | Tag | Item |
|---|-----|------|
| 3-1 | **[OPEN]** | Index is `domain_count * 4` records — **8 at d=2, 40 at d=10** — against guo/perera/yue's **100,000** and thingom's 2,000. A **2,500x** gap at d=10 on a shared axis. Exp. 2's defect in a worse form |
| 3-2 | **[DECIDE]** | §VI says "per-domain index size [is] fixed"; ours fixes per-domain (at 4), while all four baselines fix the **total** (100,000 / 2,000) so their per-domain *shrinks* as d grows. Opposite designs — so all five curve shapes are artifacts of their own sizing rather than of cross-domain orchestration |
| 3-3 | **[DECIDE]** | §VI: "the baselines accumulate domain-local search overhead". The data disagrees — guo is flat (53.8 to 52.0 ms) and thingom is flat (154,708 to 155,270 ms) across d. Only perera and yue rise. Ours rises 2x (0.076 to 0.153 ms), which 3-2 explains as a sizing artifact |
| 3-4 | **[OPEN]** | Query issues **q=1** (`[prepared["keyword"]]`) against §VI's five — the same defect as 2-2, and the one the 2026-09-06 sweep wrongly recorded as fixed everywhere. Not a like-for-like change here: Exp. 3 plants ONE shared keyword by construction, so fixing q means planting q of them |
| 3-5 | **[FIXED]** | `trapdoors_issued` was a **hardcoded `1.0`**, not counted from the token — the experiment's headline claim (§VI: one trapdoor where a baseline issues d) asserted rather than measured. **Both sides were hardcoded**: `test_exp3_issues_exactly_one_trapdoor_at_every_d` asserted `== 1.0` against a `measure` that returned the literal `1.0`, so a regression making the trapdoor domain-bound would have kept reporting the claim. Now `float(len(token.tokens))` — q under Option D, no domain factor. **No banked number moves** (q=1 today, so it still reads 1.0), and a per-domain trapdoor would now read q*d. The test is rewritten as `test_exp3_trapdoor_count_does_not_scale_with_domains`, which pins d-independence across d ∈ {2,4,6} — the actual claim — rather than the literal |
| 3-9 | **[DECIDE]** | **Scheme [54]'s Exp. 3 curve was run under a config declaring `repetitions: 30`.** Q6 diff, 2026-09-08: the three `global.yaml` revisions behind Fig. 3 resolve to `9c6615f` (ours), `ad6486f` (`[30]`/`[35]`/`[41]`) and `5cf65f9` (`[54]`, 2026-08-30). Over `defaults`, `measurement` and `experiments.exp3`, **exactly one key differs** — `measurement.repetitions`, **10 for four schemes and 30 for `[54]`**. Every other key is identical, so the drift is otherwise benign, as Exp. 2's was. The banked `[54]` data is nonetheless `n_runs=10` at every point, because — per **X-3** — `perera` never reads `global.yaml`; its `--runs` is an argparse default that happens to be 10. So the config hash records a contract the run did not obey, and the provenance is misleading rather than wrong. Either make `perera` read the config (closing X-3) or stop hashing a file it ignores |
| 3-10 | **[OPEN]** | Test coverage for Exp. 3, checked 2026-09-08: **four tests**, and after 3-5 they pin the right things — d-independence of the trapdoor count (Option D) and `test_exp3_token_count_grows_with_domains` / `test_exp3_reports_the_option_d_baseline_alongside` (PSA). **Unpinned:** the sizing rule of 3-1/3-2 — nothing fails if the per-domain index size changes, which is the defect the experiment actually has. A test asserting ours and the baselines size the same way would have caught the 2,500x gap |
| 3-6 | **[OPEN]** | The queried keyword is `kw:00000`, **invented**, planted as one entry per domain — so the "search" traverses one entry per domain and the index is inert. `run_meta.json` still reports `corpus_type: synthea` and `reportable: true`. Exactly the pattern `5143ee7` fixed for PSA Exp. 1 ("instead of inventing `kw:00000` / `hospital/pol0`"); Exp. 3 was not included |
| 3-7 | **[OPEN]** | `nodes_searched` saturates at **4** (`fog_search_nodes: 4` < d once d >= 6), so the secondary flattens over half the sweep: 2, 4, 4, 4, 4 |
| 3-8 | **[OPEN]** | Ours sweeps the published 5 points `[2,4,6,8,10]`; the four baselines sweep 9, `[2..10]`. A superset, so the figure can draw both, but the extra points sit outside §VI's stated set. **Generalised 2026-09-08:** this is not Exp. 3-specific — the recheck found the same shape on **Exp. 1 (+15), Exp. 2 (+2), Exp. 4 (+2) and Exp. 5 (+3 / +6)**. `global.yaml`'s exp1 block already blesses it ("their extra points are a superset and stay in results.csv"), and `generate_plots.py` restricts the x-axis, so no figure draws an unstated point. One sentence in §VI covering all five would close it |

---

## Exp. 4 — Verification overhead · FULL pass 2026-09-08

Cleanest of the eight, and the only figure whose five curves — the four
baselines AND the PSA arm — share **one** `global.yaml` revision (`6652245`).
All seven questions ran; the axis, reportability and claims checks are joined by
construction, workload, config hash and tests below. Originally: `prepare` sizes `records=wanted` (r records, one bundle
each), which is the fix Exp. 2 was missing, and every baseline sweeps r as
records too. Its psa arm, its workload parameters and its test coverage are
unexamined, so "clean" is about what was looked at, not about the experiment.

| # | Tag | Item |
|---|-----|------|
| 4-5 | — | **Q4/Q6/Q7 checked 2026-09-08.** Config: **one** `global.yaml` revision behind all five curves, the only figure in the audit where that is true. Construction: the PSA arm costs −3% to +1.7% of Option D (4-4) but carries a **smaller proof** — 0.97 vs 1.81 KB at r=10, 96.7 vs 153.9 KB at r=1000 — because its path is 3 elements against Option D's ~5. Workload: `prepare` sizes `records=wanted` and takes **one bundle per record**, pinned by `test_exp4_sweeps_records_not_index_entries` and `test_exp4_verifies_one_bundle_per_record` — the axis fix Exp. 2 lacked. Tests: **9**, including `test_exp4_is_still_blocked_on_the_fabric_adapter` (which pins 4-2) and `test_exp4_and_exp9_agree_on_what_one_returned_result_is`. No missing pin except the one in 4-1 |
| 4-1 | **[OPEN]** | `path_length` falls **monotonically** across the whole sweep — 5.60, 5.16, 4.92, 4.84, 4.78 at r = 10, 50, 100, 500, 1000 — while `proof_size` grows normally (1.80 to 153.91 KB). A clean monotonic decrease over five points is not what independent sampling noise looks like; the likelier reading is that larger r pulls in records with smaller `\|W_i\|`, i.e. the record SELECTION is correlated with r. §VI's `O(log t)` claim is about exactly this quantity, so it needs an explanation or a fix, not a shrug. **Explained 2026-09-08 — it is a sampling artifact, not a defect.** `prepare` takes the first `r` corpus records, so `path_length` is the RUNNING MEAN of `ceil(log2(\|W_i\|))` over a growing prefix, and it converges rather than varies: 2^5.60 = 48.5 keywords at r=10 falling to 2^4.78 = 27.4 at r=1000, against the manifest's corpus mean of 31.7 and median 29. The first records simply happen to be keyword-rich. **The PSA arm is the control that settles it**: it builds synthetic records at a FIXED `keywords_per_record` and its `path_length` is a flat **3.000 at every r**. So the decline is the law of large numbers over `\|W_i\|`, and `O(log t)` is unrefuted. What remains is presentational — a per-record `t` reported alongside, or a sentence, so a reader does not read convergence as a trend. Downgraded from a suspected defect; **not** verified against the corpus directly, which is not on this host |
| 4-2 | **[OPEN]** | Exp. 4 correctly keeps the `ledger_faithful` gate — but no `FabricLedger` adapter exists, so it cannot pass today. See `SystemConfiguration.md` §16 |
| 4-3 | — | **§VI's headline claim VERIFIED (G-1, 2026-09-08).** "The proposed scheme incurs the highest per-result verification cost of the four compared schemes; the axis is logarithmic for that reason." True at all five shared `r`: T_avg = primary/r gives **1.87, 1.74, 1.72, 1.69, 1.68 ms** against `[35]` 0.0054–0.0067, `[30]` 0.0090–0.0138 and `[54]` 0.2198–0.2207. Two orders of magnitude above `[35]`, which fully earns the log axis. Note the four sweeps only SHARE r = 10, 50, 100, 500, 1000 — `[30]` also banks 25/250 and `[35]` 20/200 — so the figure interleaves points no other scheme measured. Recorded, not a defect. Reportable, `corpus_type: synthea`, `n_runs=10`, `option_d`, measured; one point is one returned-entry count |
| 4-4 | **[DECIDE]** | **§VI's "within 2% at every r" is false at three of five points.** The sentence — "Binding the ciphertext reference and the governing authorities' state into `Commit_i` leaves per-result verification cost unchanged within measurement error — within 2% at every r" — against `exp4_verification_overhead` (option_d) and `psa_exp4_verification_overhead` (psa), same host, `n_runs=10` each: **+1.67% (r=10), −3.09% (r=50), −2.30% (r=100), −2.28% (r=500), −0.40% (r=1000)**. Three exceed 2%, and at all three the 95% CIs are **disjoint** — 87.13 ± 1.11 vs 84.44 ± 0.73 at r=50 — so it is not measurement error either: the PSA commitment is measurably ~2–3% **faster** at mid-range r. Either widen the stated bound to 4%, or report the direction as the finding. Changes a manuscript sentence, hence `[DECIDE]` |

---

## Exp. 5 — Dynamic index update · FULL pass 2026-09-08

Axis, workload and claims were checked 2026-09-07; **construction,
reportability, config hash and tests ran 2026-09-08**, closing the experiment.
5-2 turned out to be stale data rather than a live defect, and 5-1 closed
benign. The axis is sound — all three schemes count `k` as (keyword,
document) pairs. What differs is what they update, and what they update INTO.
The psa-track naming problem is G-4.

| # | Tag | Item |
|---|-----|------|
| 5-1 | **[FIXED]** | Config-hash drift: 2 `global.yaml` revisions across the figure — **diffed 2026-09-08 and BENIGN.** They resolve to `9c6615f` (ours) and `ad6486f` (`[35]`, `[30]`), and over `defaults`, `measurement` and `experiments.exp5` **zero keys differ**. Same outcome as Exp. 2's, and unlike Exp. 3's, where `repetitions` split 10 vs 30 (3-9) |
| 5-2 | **[BLOCKED]** | **`entries_rewritten` is 0.000000 at all four banked points** — **root-caused 2026-09-08: stale data, not a live defect.** Commit `3950d3e` (2026-09-06) INTRODUCED the counting path — `carries_index_delta`, the `ordinals_for_cid` repolicy loop and `rewritten += 1` are all additions in that diff. The banked Exp. 5 ran at `79a5739`, finished **2026-09-03**, three days earlier, when nothing incremented the column. Re-measured on current code: **102.0 at k=100** (and a single MODIFY receipt reports 6 entries rewritten across 6 keywords), against the banked 0.0. Two tests already pin it — `test_exp5_refuses_a_global_rebuild` asserts `> 0` and `test_synchronize_reports_the_exp5_metrics` asserts `== 6` — and both pass, so the claim is guarded going forward. **Nothing to fix in the code; the figure needs the re-run.** Third instance of the same class as 1-2 and 8-1: code fixed, data predates it |
| 5-3 | **[DECIDE]** | §VI: "**The total index size is fixed** to isolate the effect of increasing update volume." Ours sizes the deployment as ceil(k / \|W_i\|), so the index GROWS with k and there is no base index at all; guo builds a fixed 100,000-record base and adds into it, yue_ge likewise. At k=100 we update a ~4-record index against their 100,000. Third occurrence of the Exp. 2 / Exp. 3 sizing class |
| 5-4 | **[DECIDE]** | §VI says "**modified** keyword-record pairs" and ours does a MODIFY (policy-id delta) — correct. But both baselines ADD new pairs. Either §VI acknowledges the operations differ, or one side changes |
| 5-5 | — | **Q4/Q5 checked 2026-09-08.** Fig. 5 draws `exp5_keyword_update` (**option_d**); the PSA arm lives in `psa_exp5_retokenization/` and has its own `fig_psa_exp5_retokenize.pdf`, so the two are never merged. At matching k the PSA arm costs **1.01x, 1.18x, 1.48x, 1.28x** of Option D — the gap is real but far smaller than Exp. 2's 2.2x. Reportability: ours, `[35]` and `[30]` are all `corpus_type: synthea`, `reportable: true`; the PSA arm is `psa_in_process`, `reportable: false` by construction. Note ours ran at `79a5739` where both baselines ran at `ad6486f` — different commits behind one figure, which is what let 5-2 through |
| 5-6 | **[OPEN]** | Test coverage checked 2026-09-08: **11 tests**, and Exp. 5 is better pinned than Exp. 3 was — `entries_rewritten > 0` is asserted on the harness path AND `== 6` on the `dias.synchronize` path, so 5-2 cannot recur silently. **The sizing rule is unpinned**, exactly as in 3-10: nothing fails if the deployment keeps growing with k (5-3), which is the defect Exp. 5 actually has. One test asserting a FIXED base index would pin §VI's "the total index size is fixed" |

---

## Exp. 6 — DIAS synchronization ablation · FULL pass 2026-09-08

Reportability and the metric/column mismatch were checked 2026-09-07;
**§VI-claims-vs-data ran 2026-09-08 against the three banked
`psa_exp6_affected_ratio__*` arms (6-4) and all five claims hold.** That pass
also withdrew 6-2, which was wrong on its facts. A
proposed-scheme-only ablation, so there is no cross-scheme axis to disagree
about. All four Option D arms are banked.

| # | Tag | Item |
|---|-----|------|
| 6-1 | **[OPEN]** | The ledger gate was removed 2026-09-03 because Exp. 6 never anchors on a timed path — `sync/dias.py` takes `ledger` as optional and the runner never passes one. That still holds in the code. But §VI must STATE the exclusion and report anchoring separately, and it does not yet |
| 6-2 | **[WITHDRAWN]** | ~~The code declares three secondaries and every banked `results.csv` has two.~~ **Wrong on the facts, checked 2026-09-08.** All four Option D arms carry all three — `secondary_1` = `dias_message_size` (0.204102 KB), `secondary_2` = `fsns_touched` (1 / 4 / 37), `secondary_3` = `delivered_kb` (0.204102 / 0.816406 / 2.172852) — populated at every δ. The PSA arms, which are what Fig. 6 actually draws (`prefix="psa_"`), carry four. The `~3x` overcharge the item cites is real and is exactly why `delivered_kb` is measured rather than derived: for `full_rebuild`, message_size × fsns_touched = 7.55 KB against a measured 2.17 KB, a 3.48x gap. But the column is present. Nothing to fix |
| 6-5 | **[DECIDE]** | **The two constructions sweep different variables, and only one matches §VI.** Q4, 2026-09-08: Option D's `exp6_authorization_sync__*` sweeps `delta` ∈ **{100, 1000, 10000, 100000}** (an update COUNT); the PSA `psa_exp6_affected_ratio__*` sweeps **{0.1, 0.25, 0.5, 0.75, 1.0}** (a FRACTION of policies). §VI states the latter — "as the fraction of policies affected by an authority-state update increases from 10% to 100%" — and `generate_plots.py` draws the PSA arms accordingly. This is divergence **D8**, and it is the one place where the figure in the paper comes from the PSA track while every other cross-scheme figure comes from Option D. It is correct as built; what it costs is that Exp. 6's **plotted numbers are non-reportable by construction** (`psa_in_process`, `reportable: false`) while its Option D counterpart is reportable and unplotted — the mirror of 1-5. §VI should say which construction Fig. 6 is |
| 6-6 | — | **Q7 checked 2026-09-08: the best-covered experiment in the audit — 20 tests.** Both halves of the DIAS claim are pinned independently: SELECTIVE by `test_aim_selective_propagation_touches_one_node_in_four` / `..._leaves_other_nodes_stale` / `test_propagation_lands_only_on_the_serving_node` / `test_propagation_has_no_broadcast_helper`, and INCREMENTAL by `test_exp6_dias_evolves_only_the_affected_fraction`. The axis itself is pinned by `test_exp6_sweeps_the_ratio_not_an_update_count`, which is what would catch 6-5 flipping back. `test_exp6_is_not_blocked_on_the_fabric_adapter` and `test_exp6_runner_passes_no_ledger` pin 6-1's premise in code, so the ledger exclusion cannot silently regress — only §VI's sentence is missing |
| 6-4 | — | **§VI's Exp. 6 claims VERIFIED (G-1, 2026-09-08)**, against the three `psa_exp6_affected_ratio__*` arms the figure draws. (i) "DIAS achieves the lowest synchronization overhead" — lowest at all five ratios. (ii) "particularly when authority updates affect only a small fraction of policies" — full_state/DIAS is **10.18x at ratio 0.1**. (iii) "As the affected-policy ratio approaches 100%, the advantage of DIAS narrows" — 10.18x → 4.16 → 2.13 → 1.42 → **1.07x at 1.0**, monotonic. (iv) "Because the evaluation harness models no network, Incremental-All's unnecessary propagation appears chiefly in transferred synchronization data rather than in sender-side latency" — the cleanest confirmation in the audit: latency ratio IA/DIAS is **1.055–1.061x** (≈6%) while delivered_kb ratio is **exactly 4.00x at every ratio**, i.e. the four-node fan-out shows up entirely in bytes and not in time. (v) "Full-State ... processes substantially more state" — flat at 141.05 KB / 40 policies / 240 entries regardless of ratio, against DIAS's 3.52 → 35.09 KB. Non-reportable by construction (`corpus_type: psa_in_process`, `reportable: false`); one point is one affected-policy ratio; `psa`; measured |
| 6-3 | — | `fsns_touched` is a constant 1 under `dias` **by construction** (one domain per node, one domain per message) and is evidence of nothing unless read against `broadcast`. Already documented in the class docstring; recorded here so it is not mistaken for a defect |

---

## Exp. 7 / 8 — Throughput and load balance · FULL pass 2026-09-08

Workload provenance and reportability were checked 2026-09-07. **G-1 (§VI
claims vs data) was run for both on 2026-09-08** — items 7-3, 8-2, 8-3 below.
Headline result: **Exp. 7's ordering claim survives at every point; Exp. 8's
three utilization claims survive; one qualifier and one panel do not.** The
eight banked `psa_exp7_*` / `psa_exp8_*` arms are still uncompared against
Option D (G-2), and neither experiment has a dedicated test file (G-3).

| # | Tag | Item |
|---|-----|------|
| 7-1 | **[FIXED]** | `round_robin` had collapsed into `no_lb` — `5143ee7` moved `select()` onto `assign()` + `busiest()`, whose cursor realigns whenever the shard count is a multiple of the pool size. 8 consecutive calls returned `FSN1`. Fixed; no banked number affected, since nothing has run against `5143ee7` |
| 7-2 | **[FIXED]** | Confirmed post-fix: all four variants ran at commit `9519a02`, which carries `config.defaults.keywords_per_query` in `SchedulerAblation`. All six concurrency points (100 to 10,000) are banked for every arm |
| 7-3 | **[DECIDE]** | **Exp. 7's ordering claim VERIFIED, with one qualifier that is not.** AASS ranks 1/4 at all six concurrency points, and the strict order `no_lb < round_robin < least_loaded < aass` holds at every one — exactly §VI's narrative. The advantage grows with load (5.5% → 11.9 → 13.2 → 15.5 → 16.8 → 18.8% over least_loaded), supporting "particularly under high concurrency". **But at concurrency 100 the 95% CIs overlap**: AASS 1756.1 ± 66.0 → [1690.1, 1822.1] against least_loaded 1665.0 ± 36.6 → [1628.4, 1701.6]. §VI's Exp. 8 paragraph says AASS "leads on throughput at **every** concurrency level in Experiment 7" — true on the means, not separated at the lowest point. Either qualify that sentence or drop the 100-query point. Reportable, `corpus_type: synthea`, `n_runs=10`, `option_d`, measured; one point is one concurrency level. **Caveat added 2026-09-08:** this was verified against banked data produced by the FIVE-term scheduler — see 7-4 — so the ordering must be re-confirmed after the re-run |
| 8-2 | **[DECIDE]** | **"AASS trades a *small* amount of spread" is unquantified and is 1.90x at its worst.** §VI's three utilization claims all hold: AASS is 2.81x–6.38x below `no_lb` on utilization std dev ("substantially below" ✓); `least_loaded` attains the lowest variation at all six points ("follows directly from its rule" ✓); and AASS has the lowest max-utilization at all six, 0.873–0.931 against 0.948–0.960 for `no_lb` (panel (b)'s hot-spot claim ✓). The trade qualifier is the outlier — AASS/least_loaded spread runs **1.63, 1.34, 1.90, 1.62, 1.32, 1.09** across the sweep. It is non-monotonic, so "small" is defensible only at the top of the range, and a reviewer reading panel (a) sees the 1.90x. Put the ratio in the sentence or soften it. Reportable, `option_d`, `n_runs=10`, measured |
| 8-3 | **[BLOCKED]** | **Panel (c) does not show what §VI says even on its own (wrong) data — extends 8-1.** Beyond drawing `max_queue_depth` under a "Cross-node forwards" label, the drawn column **contradicts** the sentence "AASS instead considers only FSNs satisfying S ∈ S_j … It therefore reduces unnecessary forwarding" at the two lowest points: AASS 26.4 vs least_loaded 24.9 at concurrency 100, and 125.1 vs 114.9 at 500. AASS is lower only from 1,000 up. So the figure as published shows AASS *worse* on the axis the text uses to claim it is better, for a third of the sweep. Same fix as 8-1 — the Exp. 7-8 re-run, which emits true forwards (0 under AASS by construction) — but recorded separately because it is a text/figure contradiction, not only a label error |
| 7-4 | **[BLOCKED]** | **The banked Figs. 7 and 8 were measured with a scheduler that no longer exists.** Q6, 2026-09-08: all 16 arms share **one** `(global, scheduler, workload)` triple — the cleanest config result in the audit — but **all three files have since changed**. The one that matters is `scheduler.yaml`'s weight vector, which went from **five terms to four**: banked `lambda_1_auth=0.2, lambda_2_index=0.4, lambda_3_verify=0.1, lambda_4_sync=0.2, lambda_5_queue=0.1`; current `lambda_1_index=0.5, lambda_2_verify=0.125, lambda_3_sync=0.25, lambda_4_queue=0.125`, with `cost_terms.auth` removed outright. The surviving four keep the sweep's ratio (0.4 : 0.1 : 0.2 : 0.1 renormalised), so relative preference among them is preserved — but `C_j^auth = \|P_Q\|`, the authorization-awareness term and the scheme's own contribution to the score, carried **0.2 of the weight and is now gone**. Every banked AASS point therefore came from a different scoring rule than the code computes today, and the re-run will move those numbers for a reason that is not noise. Decide before re-running: is the four-term `eq:search-cost` the intended rule, or should `C^auth` come back? |
| 7-5 | **[DECIDE]** | **Under the PSA construction the scheduler ablation collapses, and `no_lb` sometimes wins.** Q4, 2026-09-08, comparing the four `psa_exp7_*` arms against Option D's: Option D separates the arms by **1.7x–2.5x** (no_lb 1194 to AASS 3022 q/s at 10,000); PSA separates them by **1.003x–1.054x**, and the winner is `no_lb` at concurrency 100 and 500, `least_loaded` at 1,000 / 2,500 / 10,000, `round_robin` at 5,000 — **AASS wins at none of the six**. Exp. 8 is the same story: PSA's `no_lb` has the *lowest* utilization spread at 100 and 500. This is not the 7-1 regression (both data sets predate `5143ee7`, which introduced it) and not a plumbing bug (`test_psa_scheduler_ablation_only_overrides_prepare` pins that the scheduler, replay, FSN pool and utilization sampling are Option D's, unchanged). §VI already disclaims these numbers — "the construction's own throughput and utilization figures characterise that per-request cost, and are not evidence about scheduler quality" — and the data confirms the mechanism it gives. **What §VI does not say is how strong the effect is: under the manuscript's own D1 token, AASS's advantage is not measurable at any concurrency.** If D1 is ever adopted in place of Option D, Exp. 7-8's contribution claim does not survive with it. Worth a sentence, because a reviewer who runs the PSA track will find this |
| 8-4 | — | **Q2/Q7 checked 2026-09-08.** Exp. 8 shares Exp. 7's runs and workload — pinned by `test_exp7_and_exp8_share_one_workload_engine`, `test_exp7_and_exp8_record_the_same_arrival_trace` and `test_config_exp7_and_exp8_are_the_same_runs` — so Exp. 7's workload check covers it and the matrix's separate `-` was an artifact of listing them apart. Test coverage across both: **14 tests**, including `test_both_exp7_traces_use_the_published_q` (q=5 in both constructions) and `test_psa_exp7_requests_actually_match_records`, which is the pin Exp. 2 lacked and paid for. No missing pin found |
| 8-1 | **[BLOCKED]** | **Fig. 8(c) is still mislabelled in the banked data.** `global.yaml` declares three secondaries; every banked `exp8_*/results.csv` has **two**, so panel (c) — `PanelSpec(2, "Cross-node forwards")` — draws `max_queue_depth`. Confirmed by the values: AASS reads 26.4 rising to 957.8 with concurrency, where true forwards under AASS are **0 by construction**. `5143ee7` fixed the code to emit forwards; the data predates it, and `secondary_metrics` is absent so the new agreement check cannot catch it. Needs the Exp. 7-8 re-run |
