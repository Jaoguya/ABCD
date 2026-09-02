#!/usr/bin/env bash
# tmux dashboard: agent activity, fleet state, live experiment progress, cost.
#
# WHAT THIS ACTUALLY SHOWS. Subagents run inside the Claude Code process, not as
# separate shells, so there is nothing to attach a terminal to. What they do is
# streamed to per-task .output files, and those are tailable -- so this watches
# their output, the fleet, and the running experiments side by side. It does not
# "run agents in tmux", and it cannot make one interactive.
#
# Read-only. Nothing here starts, stops or changes anything.
set -uo pipefail

SESSION="${1:-ojcoms}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Task output lives in a session-scoped scratch dir; take the most recent.
TASKS="${CLAUDE_TASKS_DIR:-}"
if [ -z "$TASKS" ]; then
  TASKS=$(ls -dt /private/tmp/claude-*/*/*/tasks 2>/dev/null | head -1)
fi
[ -z "$TASKS" ] && TASKS="/tmp/nonexistent"

tmux has-session -t "$SESSION" 2>/dev/null && {
  echo "session '$SESSION' already exists — attaching"; exec tmux attach -t "$SESSION"; }

# --- pane 0: agent activity -------------------------------------------------
tmux new-session -d -s "$SESSION" -n dash -c "$REPO" \
  "while :; do clear;
     echo '=== AGENT ACTIVITY ===';
     f=\$(ls -t $TASKS/*.output 2>/dev/null | head -3);
     if [ -z \"\$f\" ]; then echo '  (no agent tasks yet)';
     else for x in \$f; do
            echo \"--- \$(basename \$x .output)  [\$(stat -f '%Sm' -t '%H:%M:%S' \$x 2>/dev/null || date '+%H:%M:%S')]\";
            tail -6 \"\$x\" 2>/dev/null | cut -c1-110; echo;
          done; fi;
     sleep 5; done"

# --- pane 1: fleet ----------------------------------------------------------
tmux split-window -h -t "$SESSION:dash" -c "$REPO" \
  "while :; do clear; echo '=== FLEET ==='; ./infra/fleet.sh status 2>/dev/null | head -12; sleep 20; done"

# --- pane 2: experiment progress on busy nodes ------------------------------
tmux split-window -v -t "$SESSION:dash.1" -c "$REPO" \
  "while :; do clear; echo '=== EXPERIMENTS ===';
     for ip in \$(aws ec2 describe-instances --filters Name=tag:Project,Values=OJCOMS Name=instance-state-name,Values=running --query 'Reservations[].Instances[].PublicIpAddress' --output text 2>/dev/null | tr '\t' '\n' | grep -v None); do
       ssh -n -i ~/.ssh/ojcoms.pem -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=8 ubuntu@\$ip \
         \"printf '%-16s ' \\\$(hostname); L=\\\$(ls -t ~/*.log 2>/dev/null|head -1); [ -n \\\"\\\$L\\\" ] && tail -1 \\\$L | cut -c1-64 || echo idle\" 2>/dev/null;
     done; echo; sleep 30; done"

# --- pane 3: results + cost -------------------------------------------------
tmux split-window -v -t "$SESSION:dash.0" -c "$REPO" \
  "while :; do clear; echo '=== RESULTS / COST ===';
     ~/.venv-malbpq/bin/python .claude/skills/campaign-status/scripts/probe.py 2>/dev/null | tail -9;
     sleep 60; done"

tmux select-layout -t "$SESSION:dash" tiled
tmux select-pane -t "$SESSION:dash.0"
echo "dashboard '$SESSION' started (tasks: $TASKS)"
echo "  attach: tmux attach -t $SESSION     detach: Ctrl-b d     kill: tmux kill-session -t $SESSION"
