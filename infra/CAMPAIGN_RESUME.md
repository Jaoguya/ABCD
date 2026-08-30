# Campaign state at shutdown — 2026-08-30 ~22:35 UTC

Everything was stopped on the user's instruction. This file is what you need to
resume; it records what was running, how far it got, and what is **not** yet
banked. Written by the coder pane at shutdown.

## READ THIS FIRST — nothing from this campaign is in git

**All 85 committed `run_meta.json` files predate this campaign. Zero are at
`6c97ee9`, the commit every node ran.** Everything the 2026-08-29/30 campaign
produced exists ONLY on the stopped instances' EBS volumes:

- `ma_lb_pq_vdse` — 12 dirs, **12/12 clean 40-hex SHA**, verified on its node at
  20:36 UTC before it was stopped. These are the first results this repo has ever
  produced with a working provenance marker. **Not harvested.**
- `perera_lv_pqabse` — 3/3 clean, complete. **Not harvested.**
- `guo_vdsse`, `yue_ge`, `thingom_pq_abse` — exp1 each, clean. **Not harvested.**

**So do not delete the ~270 GB of EBS to save the $21.60/month.** That is the only
copy. Harvest first: start the instances, run `./infra/fleet.sh harvest <dir>`,
unpack, commit. The harvest filter rejects `-dirty` by default and these runs are
clean at `6c97ee9`, so they pass without an override.

An earlier version of this file listed those same results under a heading that
read as "banked", which invited exactly the wrong conclusion. What is in git is
the PREVIOUS campaign: ma_lb at `55aa3c8`/`5cf65f9`/`d65df6b`, 20 of its 26 dirs
carrying a `-dirty` suffix.

## What the interrupted runs lost

**No completed result.** guo and yue_ge were both inside Exp. 2's index-build
phase, which writes nothing until the experiment finishes, so ~1h of build per
node is gone and nothing else. Their exp1 dirs were already on disk and survive
the stop.

## On the `-dirty` stamps in git

Do not read them as evidence that code was modified. `dfa7e69` diagnosed the
marker: `git_commit()` ran `git status --porcelain` over the whole repo including
tracked result directories, so a run's own output tripped it. Its own conclusion
stands — the stamps "are not evidence that code was modified, and equally cannot
rule it out."

Corroborating: at the SAME commit `55aa3c8`, `exp7` base and its five
`__points-N` shards are clean while `exp8` base, its five shards, and `exp6` are
dirty. Same commit, same sweep, opposite verdicts — that is write-order
contamination, not modified source.

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

Why it returned `instance_type=None` rather than `m6i.4xlarge`: **not** an
IMDSv2 token problem — `_detect_aws_instance_type()` already does the correct v2
dance (PUT for a token, then GET with the header), and both instances had
`HttpEndpoint=enabled`, `HttpTokens=required`, hop limit 2. The leading
explanation is its **0.3 s timeout** (`Common/crypto/config.py:95`, applied
twice) expiring under index-build load — guo was at 14.1 GB RSS and 100% CPU when
probed. Fix the probe before spending anything on re-runs: re-pinning could buy
85 re-runs that still record `pinned=false`.

Three decisions were with the user when work stopped: the host question above,
whether ma_lb's 20 dirty-tree results get re-run, and the Exp. 2 estimand
mismatch (the proposed scheme measures one fixed 1-keyword query; the baselines
measure 30 drawn 5-keyword queries).

## One trap for a resuming session

Relaunching guo or yue_ge with `--experiment 2,3,4,5` writes into result
directories that **already contain** run_meta.json files from an earlier campaign
(`f745880` / `55aa3c8`, 2026-08-29). The directories will not be empty and the
old files are overwritten in place. That is intended, but harvest anything you
still want from them first.
