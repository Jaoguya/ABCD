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
| G-1 | **[OPEN]** | **§VI-claims-vs-data was never run on Exps. 4, 6, 7, 8.** It is the question that produced the largest findings on both deep passes — Exp. 2's selectivity (x23.2 against a claimed x100) and Exp. 3's "baselines accumulate domain-local search overhead" (contradicted by guo and thingom both being flat). Exp. 7's throughput ordering and Exp. 8's utilization spread are the two headline scheduler results and have never been checked arithmetically against `raw_runs.csv` |
| G-2 | **[OPEN]** | **The 19 banked `psa_*` directories were never compared against their Option D counterparts** — `psa_exp4`, `psa_exp5_retokenization`, `psa_exp6` (3 arms), `psa_exp7` (4 arms), `psa_exp8` (4 arms). Where this WAS run it mattered: Exp. 2's psa/option_d gap is 2.2x at N=10^6, and it is the open question in 2-6 |
| G-3 | **[OPEN]** | **Test coverage was only examined for Exp. 2.** Only Exps. 2, 6 and 9 have a dedicated test file; 1, 3, 4, 5, 7 and 8 have none, and what `test_harness.py` covers for them has not been read. On Exp. 2 this question found five missing pins, including `n_eff >= 0` passing on an empty result |
| G-4 | **[OPEN]** | `psa_exp5_retokenization/` is banked under a different experiment NAME than `exp5_keyword_update`. Either they measure different things — in which case the psa track has no Exp. 5 counterpart and §VI should say so — or the directory is misnamed. Unresolved either way |

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

## Exp. 1 — Policy-state-aware token generation · PARTIAL pass 2026-09-07

Brought to spec upstream in `5143ee7`. The code is right; the banked data is
not — the figure now draws arms that predate the fix that makes them
reportable.

| # | Tag | Item |
|---|-----|------|
| 1-1 | **[FIXED]** | `test_exp1_tokens_are_distinct` was never given the `source` fixture when Exp. 1 became corpus-backed. Fixed |
| 1-2 | **[BLOCKED]** | **Fig. 1's proposed-scheme curves are not reportable.** `5143ee7` pointed the figure at the four `psa_exp1_token_generation__pu<N>` arms (`proposed_prefix="psa_"`), and all four bank `corpus_type: psa_in_process`, `reportable: false`. The code fix making Exp. 1 corpus-backed is in; the DATA predates it. `experiment1_clarify.md` says a smoke run closes this in minutes, not a campaign |
| 1-3 | **[OPEN]** | Config-hash drift: 3 different `global.yaml` revisions across the figure |
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

## Exp. 3 — Cross-domain search scalability · FULL pass 2026-09-07

The worst workload mismatch found so far.

| # | Tag | Item |
|---|-----|------|
| 3-1 | **[OPEN]** | Index is `domain_count * 4` records — **8 at d=2, 40 at d=10** — against guo/perera/yue's **100,000** and thingom's 2,000. A **2,500x** gap at d=10 on a shared axis. Exp. 2's defect in a worse form |
| 3-2 | **[DECIDE]** | §VI says "per-domain index size [is] fixed"; ours fixes per-domain (at 4), while all four baselines fix the **total** (100,000 / 2,000) so their per-domain *shrinks* as d grows. Opposite designs — so all five curve shapes are artifacts of their own sizing rather than of cross-domain orchestration |
| 3-3 | **[DECIDE]** | §VI: "the baselines accumulate domain-local search overhead". The data disagrees — guo is flat (53.8 to 52.0 ms) and thingom is flat (154,708 to 155,270 ms) across d. Only perera and yue rise. Ours rises 2x (0.076 to 0.153 ms), which 3-2 explains as a sizing artifact |
| 3-4 | **[OPEN]** | Query issues **q=1** (`[prepared["keyword"]]`) against §VI's five — the same defect as 2-2, and the one the 2026-09-06 sweep wrongly recorded as fixed everywhere. Not a like-for-like change here: Exp. 3 plants ONE shared keyword by construction, so fixing q means planting q of them |
| 3-5 | **[OPEN]** | `trapdoors_issued` is a **hardcoded `1.0`**, not counted from the token — and it is the experiment's headline claim (§VI: one trapdoor where a baseline issues d). `psa_exp3` measures its equivalent; Option D asserts it |
| 3-6 | **[OPEN]** | The queried keyword is `kw:00000`, **invented**, planted as one entry per domain — so the "search" traverses one entry per domain and the index is inert. `run_meta.json` still reports `corpus_type: synthea` and `reportable: true`. Exactly the pattern `5143ee7` fixed for PSA Exp. 1 ("instead of inventing `kw:00000` / `hospital/pol0`"); Exp. 3 was not included |
| 3-7 | **[OPEN]** | `nodes_searched` saturates at **4** (`fog_search_nodes: 4` < d once d >= 6), so the secondary flattens over half the sweep: 2, 4, 4, 4, 4 |
| 3-8 | **[OPEN]** | Ours sweeps the published 5 points `[2,4,6,8,10]`; the four baselines sweep 9, `[2..10]`. A superset, so the figure can draw both, but the extra points sit outside §VI's stated set |

---

## Exp. 4 — Verification overhead · PARTIAL pass 2026-09-07

Cleanest of what was examined — but only the axis, reportability and a partial
claims check were run. `prepare` sizes `records=wanted` (r records, one bundle
each), which is the fix Exp. 2 was missing, and every baseline sweeps r as
records too. Its psa arm, its workload parameters and its test coverage are
unexamined, so "clean" is about what was looked at, not about the experiment.

| # | Tag | Item |
|---|-----|------|
| 4-1 | **[OPEN]** | `path_length` falls **monotonically** across the whole sweep — 5.60, 5.16, 4.92, 4.84, 4.78 at r = 10, 50, 100, 500, 1000 — while `proof_size` grows normally (1.80 to 153.91 KB). A clean monotonic decrease over five points is not what independent sampling noise looks like; the likelier reading is that larger r pulls in records with smaller `\|W_i\|`, i.e. the record SELECTION is correlated with r. §VI's `O(log t)` claim is about exactly this quantity, so it needs an explanation or a fix, not a shrug |
| 4-2 | **[OPEN]** | Exp. 4 correctly keeps the `ledger_faithful` gate — but no `FabricLedger` adapter exists, so it cannot pass today. See `SystemConfiguration.md` §16 |

---

## Exp. 5 — Dynamic index update · PARTIAL pass 2026-09-07

Axis, workload and claims were checked; reportability, construction and tests
were not. The axis is sound — all three schemes count `k` as (keyword,
document) pairs. What differs is what they update, and what they update INTO.
The psa-track naming problem is G-4.

| # | Tag | Item |
|---|-----|------|
| 5-1 | **[OPEN]** | Config-hash drift: 2 different `global.yaml` revisions across the figure |
| 5-2 | **[OPEN]** | **`entries_rewritten` is 0.000000 at all four points** (k = 100, 1,000, 10,000, 100,000) while guo reports about k (104 to 103,226) and yue_ge exactly k (100 to 100,000). §VI says "for each changed entry, the policy-state-aware token and leaf are recomputed" — a headline secondary reading zero either contradicts that sentence or is not wired to what it names. `merkle_nodes_recomputed` does vary (681, 5,848, 42,622, 517,725), so the run is doing work; it is this column that is silent |
| 5-3 | **[DECIDE]** | §VI: "**The total index size is fixed** to isolate the effect of increasing update volume." Ours sizes the deployment as ceil(k / \|W_i\|), so the index GROWS with k and there is no base index at all; guo builds a fixed 100,000-record base and adds into it, yue_ge likewise. At k=100 we update a ~4-record index against their 100,000. Third occurrence of the Exp. 2 / Exp. 3 sizing class |
| 5-4 | **[DECIDE]** | §VI says "**modified** keyword-record pairs" and ours does a MODIFY (policy-id delta) — correct. But both baselines ADD new pairs. Either §VI acknowledges the operations differ, or one side changes |

---

## Exp. 6 — DIAS synchronization ablation · PARTIAL pass 2026-09-07

Reportability and the metric/column mismatch were checked; §VI-claims-vs-data
and the three banked `psa_exp6_affected_ratio__*` arms were not. A
proposed-scheme-only ablation, so there is no cross-scheme axis to disagree
about. All four Option D arms are banked.

| # | Tag | Item |
|---|-----|------|
| 6-1 | **[OPEN]** | The ledger gate was removed 2026-09-03 because Exp. 6 never anchors on a timed path — `sync/dias.py` takes `ledger` as optional and the runner never passes one. That still holds in the code. But §VI must STATE the exclusion and report anchoring separately, and it does not yet |
| 6-2 | **[OPEN]** | The code declares three secondaries (`dias_message_size`, `fsns_touched`, `delivered_kb`) and every banked `results.csv` has **two**. `delivered_kb` was added precisely because message_size x fsns_touched overcharges `full_rebuild` by ~3x — so the column the panel's claim rests on is the one missing from the data |
| 6-3 | — | `fsns_touched` is a constant 1 under `dias` **by construction** (one domain per node, one domain per message) and is evidence of nothing unless read against `broadcast`. Already documented in the class docstring; recorded here so it is not mistaken for a defect |

---

## Exp. 7 / 8 — Throughput and load balance · PARTIAL pass 2026-09-07

Workload provenance and reportability were checked. **Neither experiment's §VI
claims were checked against the data** — Exp. 7's throughput ordering and
Exp. 8's utilization spread are the two headline scheduler results and remain
unverified arithmetically. The eight banked `psa_exp7_*` / `psa_exp8_*` arms
were not compared against Option D either.

| # | Tag | Item |
|---|-----|------|
| 7-1 | **[FIXED]** | `round_robin` had collapsed into `no_lb` — `5143ee7` moved `select()` onto `assign()` + `busiest()`, whose cursor realigns whenever the shard count is a multiple of the pool size. 8 consecutive calls returned `FSN1`. Fixed; no banked number affected, since nothing has run against `5143ee7` |
| 7-2 | **[FIXED]** | Confirmed post-fix: all four variants ran at commit `9519a02`, which carries `config.defaults.keywords_per_query` in `SchedulerAblation`. All six concurrency points (100 to 10,000) are banked for every arm |
| 8-1 | **[BLOCKED]** | **Fig. 8(c) is still mislabelled in the banked data.** `global.yaml` declares three secondaries; every banked `exp8_*/results.csv` has **two**, so panel (c) — `PanelSpec(2, "Cross-node forwards")` — draws `max_queue_depth`. Confirmed by the values: AASS reads 26.4 rising to 957.8 with concurrency, where true forwards under AASS are **0 by construction**. `5143ee7` fixed the code to emit forwards; the data predates it, and `secondary_metrics` is absent so the new agreement check cannot catch it. Needs the Exp. 7-8 re-run |
