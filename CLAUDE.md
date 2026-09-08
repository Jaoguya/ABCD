# MA-LB-PQ-VDSE — working rules

This file loads on every turn, so it stays short. It contains only rules that
are **currently true**; a rule that has gone stale is worse than no rule,
because it is followed.

`SystemConfiguration.md` is the operator's guide — environment, dataset,
sweeps, how to run it, the AWS estate and the operational traps. It opens with
the rule for deciding what is true when two sources disagree.

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

**Say where a claim came from.** A number read out of a document is not a number
verified against the data. If you did not open the `results.csv` or run the
command, say so in the same breath as the number.

## Fixing things

Follow `.claude/skills/bug-sweep`'s boundary to decide what gets RECORDED, but
**do not ask which option to take** (granted 2026-09-06). Pick the option you
would recommend and execute it. Report what changed, not what you considered.

Record a finding in the **commit message**, with its evidence — the file and
line, the measured numbers, why it matters. Anything that changes a number
already in a `results.csv`, a figure, or the manuscript is called out there
explicitly as results-affecting, and is not folded in silently.

`.claude/skills/bug-sweep/DECISIONS.md` is a **closed archive**: do not read it
and do not append to it. It holds history up to 2026-09-07 and nothing after.

This does not override the refusal rules: destructive or irreversible actions
— terminating instances, discarding measured data, force-pushing, spending on
AWS — are still confirmed first.

## Documents

**Two prose files, and no more:** this one (rules) and `SystemConfiguration.md`
(operator's guide). Do not create a third. Every document retired from this repo
has left dangling citations behind — 338 of them when `README.md` went — and the
cost scales with how many there are to retire.

**Prose is never evidence.** Cite the file and line, the config key, or the
command you ran. When a document and the code disagree, the code wins and the
document is wrong; fix it in the same commit, do not note it for later.

**Cite a line number only against a file that is in the repo.** 64 citations in
`Common/` and the schemes point at `Ref[35].txt`, `Ref[41].txt` and
`Ref[52].txt`; no `.txt` extraction exists, the surviving `.md` files are far
shorter than the lines cited, and `Ref[52]` is not in the repo at all. That is
how parameter provenance stops being checkable.

When you change a config value, a gate, or a sweep range, grep
`SystemConfiguration.md` for it before committing.
`Schemes/ma_lb_pq_vdse/src/tests/test_document_config_agreement.py` checks the
machine-checkable half automatically — it is the enforcement, this section is
only the reason. Open questions that outlive a commit go in that guide's
**Known gaps**, not into a new file.

## Hard rules

- **`Overleaf/*.tex` may be edited** (granted 2026-09-06). Back the file up
  first, change only the sentences the decision names, and show the diff.
- **Stop an idle instance.** The moment a fleet node has no task left —
  campaign finished, harvested, or blocked awaiting a decision — stop it:
  `aws ec2 stop-instances --instance-ids <id>`. Never leave one running to
  wait for a human; restarting costs ~2 minutes, idling costs ~$0.19/hr per
  `m6i.xlarge`. Only `Project=OJCOMS` instances are ever touched.
- **Work is on `OJCOMS_expByexp`.** That is the tracking branch and where every
  commit since `a6cba3f` has landed; `main` is stale behind it. Commit and push
  to the branch that is checked out, and never force-push.
- **The corpus is frozen.** Only `corpus_type: synthea` matching
  `dataset.yaml`'s SHA-256 pin is reportable. Note the host is **not** part of
  that check — `environment.instance_type` was dropped from `global.yaml` on
  2026-08-30, so `verify_experiment_host()` passes vacuously and the campaign
  runs on more than one instance size. A run is stamped reportable without any
  host guarantee; treat cross-host latency comparisons as unsound until the pin
  returns.
- **Thingom (Ref[41]) Exp. 2 is measured only at N=10⁴.** 50k–1M are linear
  scalings from that anchor (`n_runs=1`, blank `ci95`). Never launch a run above
  10⁴ — one at 10⁶ costs ~11.3 h.
- **No fabricated data**, no baseline held to a weaker standard than the
  proposed scheme, and never gate on speed — slowness is a finding.
- Say **Scheme30/35/41/54**, never author names. Ours is "the proposed scheme".

## Tests

`python -m pytest -q` from the repo root, inside the venv
(`~/.venv-malbpq` is the convention `infra/provision.sh` uses). A green suite is
the floor, not the goal — every defect found so far was found with it green.

Two things that will trip you up:

- **`pytest` is not in `requirements.txt`** and is not installed on the AWS
  host. Install it into the venv separately; never into a system Python.
- **There is no agreed pass count.** Figures of 609, ~651 and 895 have all been
  recorded at different times. Establish the floor by running it before you
  change anything, rather than trusting a number written down somewhere.
