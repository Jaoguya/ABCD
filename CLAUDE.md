# MA-LB-PQ-VDSE — working rules

This file loads on every turn, so it stays short. The long-form specification is
`README.md`; the operator's guide is `SystemConfiguration.md`.

## Every reply

Follow `.claude/skills/report-back` **before delivering any result, figure,
number, fix, or explanation** — not only when invoked. Lead with the answer,
scannable bullets, numbers in tables, cut preamble and restatement. Spend extra
lines only on a number that moved, a thing that failed, or a decision that is
the user's.

Alongside any number, always state: **reportable or not** (corpus type, host,
`n_runs`), **what one point on the axis is**, **which construction produced it**
(`option_d` or `psa` — they time different functions at the same experiment
number), and **measured vs extrapolated**.

## Fixing things

Follow `.claude/skills/bug-sweep`'s boundary to decide what gets RECORDED,
but **do not ask which option to take** (granted 2026-09-06). Pick the option
you would recommend and execute it. Anything that changes a number already in
a `results.csv`, a figure, or the manuscript still gets an entry in
`.claude/skills/bug-sweep/DECISIONS.md`, marked `RESOLVED: <what you did>` in
the same pass. Report what changed, not what you considered.

This does not override the refusal rules: destructive or irreversible actions
— terminating instances, discarding measured data, force-pushing — are still
confirmed first.

## Hard rules

- **`Overleaf/*.tex` may be edited** (granted 2026-09-06). Back the file up
  first, change only the sentences the decision names, and show the diff.
  `README.md` is still edit-only-when-asked.
- **Stop an idle instance.** The moment a fleet node has no task left —
  campaign finished, harvested, or blocked awaiting a decision — stop it:
  `aws ec2 stop-instances --instance-ids <id>`. Never leave one running to
  wait for a human; restarting costs ~2 minutes, idling costs ~$0.19/hr per
  `m6i.xlarge`. Only `Project=OJCOMS` instances are ever touched.
- **No branches.** Commit straight to `main`, repo and fleet nodes alike.
- **The corpus is frozen.** Only `corpus_type: synthea` on the pinned AWS
  `m6i.xlarge` is reportable. `~/.venv-malbpq` is the Mac dev venv; nothing run
  there is reportable.
- **Thingom (Ref[41]) Exp. 2 is measured only at N=10⁴.** 50k–1M are linear
  scalings from that anchor (`n_runs=1`, blank `ci95`). Never launch a run above
  10⁴ — one at 10⁶ costs ~11.3 h.
- **No fabricated data**, no baseline held to a weaker standard than the
  proposed scheme, and never gate on speed — slowness is a finding.
- Say **Scheme30/35/41/54**, never author names. Ours is "the proposed scheme".

## Tests

`~/.venv-malbpq/bin/python -m pytest -q` from the repo root. A green suite is
the floor, not the goal — every defect found so far was found with it green.
