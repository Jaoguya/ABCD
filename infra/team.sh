#!/usr/bin/env bash
# Three-role agent team in one tmux session.
#
#   hand   (sonnet) — git, fleet, suite, plots: procedural work with a known recipe
#   coder  (opus)   — the hard code: schemes, harness, scheduler, plotting, infra
#   scout  (sonnet) — search and read: README, SCHEME.md, debug_history, manuscript
#
# Each pane is its own `claude` process with its own context, so they do not
# share a conversation. Talk to whichever pane owns the job.
#
#   ./infra/team.sh          start (or re-attach if already running)
#   ./infra/team.sh kill     tear the session down
set -euo pipefail

SESSION="abcd-team"
REPO="/Users/puumax/ABCD"
# Not `claude` from PATH: that is a cmux shim under a per-boot temp directory
# which will not resolve inside a fresh tmux server.
CLI="/Users/puumax/.local/bin/claude"

if [[ "${1:-}" == "kill" ]]; then
  tmux kill-session -t "$SESSION" 2>/dev/null && echo "killed $SESSION" || echo "no session $SESSION"
  exit 0
fi

[[ -x "$CLI" ]] || { echo "claude CLI not found at $CLI" >&2; exit 1; }

COMMON="You are one of three agents on a shared benchmark repo at $REPO.
AGENT_RULES.md is binding: never edit README.md on your own initiative, never
fabricate or tune results, and stop and ask when a decision would change a
reported number. Log every debugging change to debug_history.md.
Stay in your role; hand work outside it to the pane that owns it."

HAND="$COMMON
YOUR ROLE: routine mechanical operations. git add/commit/push/pull, fleet
start/deploy/harvest/stop via ./infra/fleet.sh, unpacking and moving results,
running the pytest suite, regenerating figures via Plots/generate_plots.py.
Follow the recipe. If what you hit is not covered by a recipe, stop and say so
rather than improvising. You do not write new logic and you do not diagnose."

CODER="$COMMON
YOUR ROLE: the hard code. Scheme constructions, experiment runners, the harness,
the AASS scheduler, plotting and infra scripts. You own correctness. Measure
before you claim a cause, and state what you measured. When a change affects a
reported number, say so explicitly and mark it results-affecting."

SCOUT="$COMMON
YOUR ROLE: search and read. README.md, the per-scheme SCHEME.md files,
debug_history.md, Overleaf/PQ-AVDSE-OJCOMS.md, References/. Answer questions
about what the spec, the manuscript or the history actually says, with file and
line citations. Read-only by default: do not edit code or results. If you find
something that needs changing, report it to the coder pane rather than fixing it."

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "session $SESSION already running — attach with: tmux attach -t $SESSION"
  exit 0
fi

launch() { printf '%s --model %s --append-system-prompt %q\n' "$CLI" "$1" "$2"; }

tmux new-session  -d -s "$SESSION" -n team -c "$REPO"
tmux split-window -h -t "$SESSION:team" -c "$REPO"
tmux split-window -v -t "$SESSION:team.1" -c "$REPO"

# A tmux USER OPTION, not -T: Claude Code sets its own pane title via an escape
# sequence the moment it starts, so a -T label is overwritten within seconds.
tmux set-option -p -t "$SESSION:team.0" @role "coder  (opus)"
tmux set-option -p -t "$SESSION:team.1" @role "hand   (sonnet)"
tmux set-option -p -t "$SESSION:team.2" @role "scout  (sonnet)"

tmux send-keys -t "$SESSION:team.0" "$(launch opus   "$CODER")" C-m
tmux send-keys -t "$SESSION:team.1" "$(launch sonnet "$HAND")"  C-m
tmux send-keys -t "$SESSION:team.2" "$(launch sonnet "$SCOUT")" C-m

tmux set-option -t "$SESSION" pane-border-status top
tmux set-option -t "$SESSION" pane-border-format " #{@role} "
tmux select-pane -t "$SESSION:team.0"

echo "started $SESSION — coder(opus) | hand(sonnet) / scout(sonnet)"
echo "attach with: tmux attach -t $SESSION"
