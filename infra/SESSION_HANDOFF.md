# Handoff — 2026-09-03

State at the end of the session that fixed guo's Exp. 2. Written for whoever
picks up Exp. 1, 4 and 6.

## Where things stand

**Fleet: all 9 `Project=OJCOMS` instances STOPPED.** $0/hr compute. EBS only.

**NEVER touch instances `i-03d6a71139ed198eb` (SSO) or `i-0d4abbbd682da69c3`
(test-).** Untagged, unrelated, user's explicit standing order. Always filter
fleet commands on `Project=OJCOMS`.

**Branches merged.** `exp78-diagnosis` and `final-debug` are fully contained in
`main`; `git branch --no-merged main` is empty. The user asked for branches to be
DELETED and a "never create new branches" policy written into README.md. Neither
is done — held back because another session had a staged working tree.

**Refer to schemes by number, never by author name:** Scheme30 (`yue_ge`),
Scheme35 (`guo_vdsse`), Scheme41 (`thingom_pq_abse`), Scheme54
(`perera_lv_pqabse`), and "the proposed scheme" (`ma_lb_pq_vdse`).

**The manuscript is `Overleaf/MA-LB-PQ-VDSE.tex`** (renamed this session from
`PQ-AVDSE-OJCOMS`, which had no extension). The `.md` beside it is a lossy export
— do not read it. Note `References/Ref[55]/` holds the **Scheme30** paper despite
its folder name; that mismatch is what produced the wrong-citation bug below.

## Done, verified

guo/Scheme35 Exp. 2 was re-run at `cc722ad` after two bugs were found and fixed.
All five points pass acceptance: `prune_ratio > 0` everywhere (was identically
`0.0` in 150/150 rows), **0/120 n_eff decreases** (the superseded run scored
44/120), no flat secondaries, `n_runs=30`, clean provenance.

| N | superseded | corrected |
|---|---|---|
| 10,000 | 271 ms | 3,729 ms |
| 50,000 | 266 ms | 19,233 ms |
| 100,000 | 388 ms | 40,853 ms |
| 500,000 | 1,004 ms | 198,175 ms |
| 1,000,000 | 877 ms | 394,221 ms |

The old numbers measured a search that aborted after ~1 crypto op and returned
nothing. Both fixes are in `Schemes/guo_vdsse/src/exp2_search.py`: query sets
drawn eagerly from a fixed `reference_n`, and query keywords drawn from a real
document so the conjunction can match.

## Open — the three tasks

### Exp. 1 — measurement scope. Fixable without new code.

Scheme30 runs `peony_plus`, whose `token_gen` is the user's `F.Cons` call PLUS
owner-side MSRE revocation PLUS the deletion filter
(`Schemes/yue_ge/src/peony_plus.py:367`). The spec says *"only online trapdoor
generation is measured"* — owner-side assistance is not that. A `peony` variant
already exists that times only the user's part.

**This is a reported-number change and it moves AGAINST us** — Scheme30's
latency will drop, narrowing our margin. It was put to the user and NOT yet
answered. Do not just do it.

Separately the spec's baseline list is stale: it names XB-Muse [36] and Zhuang
[52] (neither implemented; [52] dropped 2026-08-27) and omits [30] and [54],
which are implemented and plotted.

### Exp. 4 — Scheme54's Exp. 4 does not exist.

`Schemes/perera_lv_pqabse/src/main.py` `EXPERIMENT_MAP` is `{"1","2","3"}`.
Verified on two commits and inside a live instance; no `exp4` in any harvest
tarball across all 9 nodes including an `ALLOW_DIRTY=1` pass. `--experiment 4`
would print *"Unknown experiment"* and exit.

The user believes the proposed scheme should place SECOND here and currently it
places third of three. That is consistent with Scheme54 — which does a signature
per RECORD against our per-DOMAIN signatures — being absent. Manuscript cost:
`O(x log N)T_H + O(x)(T_Ver + T_MAC)`.

Also the sweep is truncated: spec says 10→1000, banked data stops at 100/50/50
and on three DIFFERENT x-point sets, so the figure has no shared axis.

### Exp. 6 — the ablation axis does not exist.

The manuscript wants full-state sync vs no-selective-sync vs proposed IAS. `grep`
for `full_state` or `no_selective` across `Schemes/ma_lb_pq_vdse/src/` returns
nothing. Only the four SCHEDULER variants exist, which are Exp. 7/8's axis, and
`main.py:195` says outright they "should be indistinguishable here". The data
agrees: 4% spread across Exp. 6 variants against 71% in Exp. 7.

Both levers are in `Schemes/ma_lb_pq_vdse/src/sync/ias.py::synchronize`:
- selective propagation is `targets = affected_nodes(message, nodes)` (:738)
- incremental state is the `evolve_*` calls (:708-727)

There is **no full-rebuild function to reuse** — one has to be written. A faked
slowdown would be worse than no figure.

## Traps this session hit, so you don't

- **`run_meta.json` existing does NOT mean a point finished.** Restoring tracked
  files before a run recreates old `run_meta.json` files. Distinguish by
  `git_commit`, not by presence or mtime.
- **`python -u` or the log is useless.** Without it a working run block-buffers
  and looks hung; a 900s "timeout" was diagnosed off an empty log.
- **Long runs go in `tmux` on the node.** Three separate incidents had the WORK
  survive while the RECORD of it died with an SSH drop.
- **`pkill -f smoke.sh` does not kill `timeout`-wrapped children.** Orphans kept
  writing after their output dir was deleted.
- **The egress IP rotates.** Every host times out at once and looks dead; it is
  the security group. Re-authorise and retry before diagnosing anything else.
- **Never blanket-unpack harvest tarballs.** Each node's tarball carries stale
  copies of every other scheme; alphabetical order silently overwrites fresh
  with stale. Extract scoped, per scheme, from the one node that produced it.

## Credentials

The user pasted a long-lived access key in plaintext this session
(`AKIAXWAJ4NY3WNBQP47G`, written to `~/.aws/credentials`). **It should be
rotated.** It is in the transcript.
