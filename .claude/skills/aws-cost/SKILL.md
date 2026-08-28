---
name: aws-cost
description: Report AWS spend for this project's EC2 fleet - total to date, per-instance breakdown, current burn rate, and what is running right now. Use when asked how much AWS has cost, what is still billing, whether instances can be stopped, or to check spend before or after an experiment campaign.
---

# AWS cost for the benchmark fleet

Answers "how much have I spent, and what is costing me money right now."

## SCOPE — this project only. Never touch anything else.

**Hard rule, from the user, 2026-08-28:**

> Focus on my project only, don't ever touch other instance that not our[s].

This AWS account also runs instances belonging to **other, unrelated
projects** (BVCRSA, Blockchain_BVCRSA, SSO, test-, EKS/ECR resources). They
are **out of scope in every respect**:

- **Never stop, start, terminate, reboot, resize, tag, or modify them.**
- **Never create, delete, or modify their volumes, snapshots, AMIs, security
  groups, or networking.**
- Do not act on them even when they look obviously wasteful — an idle
  instance up for a year, or an unattached volume, is still someone else's
  decision. Report it once if genuinely notable, then leave it alone.

**This project's resources are exactly those tagged `Project=OJCOMS`**
(instance `OJCOMS` plus the `abcd-worker` fleet). That tag is the single
source of truth; do not infer membership from names, instance types, or
launch times.

`aws_cost.py` filters on that tag by default. `--all-account` exists only
because a billed total is account-wide and cannot be attributed otherwise —
it is a **reporting** flag and confers no permission to act on anything it
displays.

Two independent sources, because they answer different questions and can
legitimately disagree:

- **Cost Explorer** (`aws ce`) — what AWS actually billed. Authoritative, but
  lags by up to ~24h and is not free: **each `get-cost-and-usage` call costs
  $0.01**. Do not poll it in a loop.
- **Live instance state** (`aws ec2`) — what is running *now* and therefore
  what the burn rate is. Free, instant, but says nothing about past spend.

Use `scripts/aws_cost.py`. It needs configured credentials (`aws sts
get-caller-identity` must succeed).

## Usage

```bash
python3 .claude/skills/aws-cost/scripts/aws_cost.py             # summary: MTD + running now
python3 .claude/skills/aws-cost/scripts/aws_cost.py --days 7    # last 7 days, daily
python3 .claude/skills/aws-cost/scripts/aws_cost.py --by-instance
python3 .claude/skills/aws-cost/scripts/aws_cost.py --running   # free: skip Cost Explorer entirely
python3 .claude/skills/aws-cost/scripts/aws_cost.py --all-account  # reporting only, see SCOPE
```

`--running` makes no Cost Explorer call, so it costs nothing — prefer it when
the question is only "what is billing right now".

Default output covers **only `Project=OJCOMS`**. Anything outside that tag is
listed solely under `--all-account`, and only so an account-wide bill can be
explained; it is never a target for action.

## Reading the output

- **Burn rate** is computed from instances in the `running` state only.
  A `stopped` instance bills **no compute**, but its EBS volume still bills
  (~$0.08/GB-month for gp3), which is why stopping is not the same as
  terminating and why a long-stopped fleet is not free.
- **Cost Explorer totals include everything** — EBS, snapshots, data transfer,
  and any non-EC2 service on the account — so they will exceed a
  hand-computed `instances x hourly rate`. That gap is usually storage, and is
  expected rather than an error.
- Unblended cost is used, which is what a single-account user is actually
  charged.

## Cautions

- Prices are read live from the AWS Pricing API where reachable, and fall back
  to a small table of us-east-1 on-demand rates otherwise. A fallback rate is
  **labelled as such** in the output — never present a fallback number as a
  billed figure.
- Cost Explorer must be enabled once in the console before the API returns
  anything; if it is not, the script says so rather than reporting $0.
- This reports cost only. It never stops, starts, or terminates anything.
