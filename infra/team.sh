#!/usr/bin/env bash
# Three-role agent team in one tmux session.
#
#   headmaster (opus)   — direction: decides, prioritises, proposes the fix
#   coder      (opus)   — the hard code: schemes, harness, scheduler, infra
#   kiki       (sonnet) — hands and eyes: run the recipe, read and cite the spec
#
# kiki is the former `hand` and `scout` merged. They were split so a mechanical
# operator could not wander into interpretation, but in practice most tasks
# needed both halves -- harvest the results AND say what the spec expects of
# them -- and the handoff cost more than the separation bought.
#
# Each pane is its own `claude` process with its own context, so they do not
# share a conversation. Talk to whichever pane owns the job.
#
#   ./infra/team.sh          start (or re-attach if already running)
#   ./infra/team.sh kill     tear the session down
#
# For one terminal per role instead of one session with three panes (cmux and
# friends), use ./infra/role.sh — same prompts, one tmux session each.
set -euo pipefail

SESSION="abcd-team"
# REPO, CLI and the four role prompts. Shared with infra/role.sh.
source "$(dirname "${BASH_SOURCE[0]}")/roles.sh"

if [[ "${1:-}" == "kill" ]]; then
  tmux kill-session -t "$SESSION" 2>/dev/null && echo "killed $SESSION" || echo "no session $SESSION"
  exit 0
fi

[[ -x "$CLI" ]] || { echo "claude CLI not found at $CLI" >&2; exit 1; }

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "session $SESSION already running — attach with: tmux attach -t $SESSION"
  exit 0
fi

# -n names the session: that is the address other panes use with SendMessage.
launch() { printf '%s --model %s -n %s --append-system-prompt %q\n' "$CLI" "$1" "$2" "$3"; }

tmux new-session  -d -s "$SESSION" -n team -c "$REPO"
tmux split-window -h -t "$SESSION:team" -c "$REPO"
tmux split-window -v -t "$SESSION:team.1" -c "$REPO"

# A tmux USER OPTION, not -T: Claude Code sets its own pane title via an escape
# sequence the moment it starts, so a -T label is overwritten within seconds.
tmux set-option -p -t "$SESSION:team.0" @role "coder       (opus)"
tmux set-option -p -t "$SESSION:team.1" @role "headmaster  (opus)"
tmux set-option -p -t "$SESSION:team.2" @role "kiki        (sonnet)"

# zsh startup is not instant; keys sent before zle is up are dropped, which
# truncates the quoted prompt and strands the pane at a `>` continuation prompt.
sleep 3

tmux send-keys -t "$SESSION:team.0" "$(launch opus   coder      "$CODER")"      C-m
tmux send-keys -t "$SESSION:team.1" "$(launch opus   headmaster "$HEADMASTER")" C-m
tmux send-keys -t "$SESSION:team.2" "$(launch sonnet kiki       "$KIKI")"       C-m

tmux set-option -t "$SESSION" pane-border-status top
tmux set-option -t "$SESSION" pane-border-format " #{@role} "
tmux select-pane -t "$SESSION:team.0"

echo "started $SESSION — coder(opus) | headmaster(opus) / kiki(sonnet)"
echo "attach with: tmux attach -t $SESSION"
