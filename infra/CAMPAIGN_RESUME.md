# Campaign state at shutdown — 2026-08-30 ~22:35 UTC

Everything was stopped on the user's instruction. This file is what you need to
resume; it records what was running, how far it got, and what is **not** yet
banked. Written by the coder pane at shutdown.

## What was actually banked

**Nothing new landed from the interrupted runs.** Both nodes were still inside
Exp. 2's index-build phase, which writes no output until the whole experiment
completes. So ~1h of build work per node is lost on resume, but **no completed
result was lost** — every `run_meta.json` already on disk predates the stop and
survives on the EBS volumes (stopping an instance does not delete them).

Banked this campaign, one per node, both verified `reportable: true`,
`corpus_type: synthea`, clean 40-hex commit:

| scheme | banked |
|---|---|
| `guo_vdsse` | `exp1_trapdoor_generation` |
| `yue_ge` | `exp1_trapdoor_generation` |
| `thingom_pq_abse` | `exp1_trapdoor_generation` (stopped earlier, separately) |
| `perera_lv_pqabse` | exp1, exp2, exp3 — **complete**, 3/3 clean |
| `ma_lb_pq_vdse` | 12 dirs, **12/12 clean SHA** (exp1,2,3,5 + exp7/8 x 4 variants) |

## Exact state at stop

| | `guo_vdsse` | `yue_ge` |
|---|---|---|
| instance | `i-0e5ae20e113bae9f7` | `i-0e1bfef657d39bf67` |
| type | m6i.4xlarge (61 GB) | m6i.4xlarge (61 GB) |
| IP at stop | 98.93.66.21 | 100.53.7.248 |
| commit | `6c97ee9` | `6c97ee9` |
| branch on node | `final-debug` | `final-debug` |
| elapsed / CPU | 1:02:08 / 1:02:05 | 58:59 / 58:56 |
| RSS at stop | 14.1 GB | 5.3 GB |
| log on node | `~/guo_vdsse-20260829T212758Z.log` | `~/yue_ge-20260829T213110Z.log` |
| progress | Exp. 2 build, no per-N lines emitted | Exp. 2 build, through N=100,000; mid-build on 200,000 |

**IPs change on stop/start.** Rediscover them; do not reuse the values above.

Both were launched as:

```bash
setsid nohup ~/.venv-malbpq/bin/python -u -m Schemes.<scheme>.src.main \
  --experiment 2,3,4,5 --require-reportable > ~/<scheme>-<UTC>.log 2>&1 < /dev/null &
```

`--experiment 2,3,4,5` deliberately skips the banked exp1. `python -u` matters:
without it these two block-buffer stdout to a file and look hung for hours.

## Estimated remaining work

Derived from measured data, not from `runtime_estimates.csv` alone — that file
has been wrong by 8x in both directions.

- **`yue_ge` ≈ 9.1 h total, ≈ 8.2 h remaining.** Dominated by exp2 index builds
  (4.85 h across 7 points to N=10^6), then exp3 2.31 h, exp5 1.94 h. Its build
  rows are genuinely MEASURED: predicted 27.9 min cumulative through N=100k
  against 28.4 min observed, 1.8% off.
- **`guo_vdsse` ≈ 4.0 h known, ≈ 3.1 h remaining, plus an unquantified gap.**
  exp2 builds 2.85 h + search 0.11 h + exp5 1.00 h. **`guo` has no exp3 rows at
  all**; its exp3 *search* is trivial (~75 ms/run) but the per-d-point index
  build is unmeasured. Treat guo as 3–5 h with that spread stated.
  The 7.5 h `build_exp2` row does **not** apply — it is measured at N=10^6 and
  guo's sweep is hardcoded to stop at 2x10^5.

## Blocking issue — do not simply relaunch

**Both nodes report `pinned=False`.** `global.yaml` pins `m6i.xlarge`; these are
`m6i.4xlarge`, resized mid-campaign to survive an OOM (guo came within ~5 min of
a kill; yue_ge projected ~21 GB at N=10^6 against a 15 GB host). All 85 earlier
run_metas record `m6i.xlarge` / `pinned=True`. Nothing enforces `require=True`,
so runs proceed and record `pinned=false` rather than refusing.

So **anything these two produce is non-conforming to §V's identical-hardware
sentence.** Resuming without settling this spends money on inadmissible numbers.

One nuance not yet run down: `verify_experiment_host()` returns
`instance_type=None`, not `m6i.4xlarge` — that is **detection failing**, not a
detected-wrong-type, and probably IMDSv2 requiring a token. Worth confirming
before concluding anything, because it also bears on how the earlier
`pinned=True` results were determined.

Three decisions were with the user when work stopped: the host question above,
whether ma_lb's 20 dirty-tree results get re-run, and the Exp. 2 estimand
mismatch (the proposed scheme measures one fixed 1-keyword query; the baselines
measure 30 drawn 5-keyword queries).
