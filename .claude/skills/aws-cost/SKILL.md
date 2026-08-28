---
name: aws-cost
description: Report AWS spend for this project's EC2 fleet - total to date, per-instance breakdown, current burn rate, and what is running right now. Use when asked how much AWS has cost, what is still billing, whether instances can be stopped, or to check spend before or after an experiment campaign.
---

# AWS cost for the benchmark fleet

Answers "how much have I spent, and what is costing me money right now."

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
```

`--running` makes no Cost Explorer call, so it costs nothing — prefer it when
the question is only "what is billing right now".

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
