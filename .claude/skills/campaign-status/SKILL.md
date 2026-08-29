---
name: campaign-status
description: Show live campaign progress in the Claude Code status line - which fleet nodes are running or idle, the burn rate, and how many results are reportable. Use when asked to display experiment progress, add campaign info to the status bar, or check what is still running.
---

# Campaign status line

Adds a right-aligned segment to the status line:

```
~/abcd | Opus 5 | ██░░░░ 120k/500k (24%)        ▶ 3/9 busy · $1.71/hr · 58/64 rep · 9 inst
```

Segments: fleet activity, burn rate, reportable results, fleet size.

## Why it is split in two

The status line re-renders constantly, so it must return in milliseconds.
Querying nine EC2 instances over SSH takes tens of seconds. So:

- **`scripts/probe.py`** talks to AWS and the fleet, and writes a snapshot to
  `~/.cache/ojcoms-campaign.json`. Run it on demand, or on a loop.
- **`scripts/statusline.py`** only reads that file. It never touches the
  network. A missing or stale cache degrades to a dim hint rather than
  stalling the prompt; anything older than 10 minutes is marked `(Nm old)`.

## It composes, it does not replace

`statusline.py` runs whatever status-line command was already configured and
appends to it, so the existing context-window display is kept. Override the
inner command with `CAMPAIGN_STATUS_INNER`.

## Install

```bash
python3 .claude/skills/campaign-status/scripts/probe.py      # refresh once
```

Then point `statusLine.command` in `~/.claude/settings.json` at
`scripts/statusline.py`. Keep it refreshed while a campaign runs:

```bash
while true; do python3 .claude/skills/campaign-status/scripts/probe.py >/dev/null; sleep 120; done &
```

## What the colours mean

| Shown | Meaning |
|---|---|
| `▶ 3/9 busy` green | nodes are working |
| `⚠ 4 up, idle` **red** | instances running with nothing to do — the expensive state, and the one worth acting on |
| `fleet idle` dim | everything stopped, $0/hr |
| `$1.71/hr` yellow/red | red at or above $1/hr |
| `58/64 rep` | results.csv files present, and how many carry `reportable: true` |

The idle-but-running warning exists because that is the actual leak: a finished
node that never shut down bills at $0.19/hr indefinitely, and nothing else in
the interface says so.

## Counting note

`reportable` counts `run_meta.json` files with `reportable: true` next to a
`results.csv`. Sharded runs (`__points-*`) each count separately until
`infra/merge_points.py` reassembles them, so the number drops on merge — that
is the shards collapsing into one result, not results being lost.
