#!/usr/bin/env bash
# One role, one tmux session, one terminal.
#
# team.sh puts all three agents in one tmux session as side-by-side panes. That
# is the wrong shape when the terminal app already does the splitting (cmux),
# because a pane cannot be attached to on its own. This gives each role its own
# session instead, so one terminal attaches to exactly one agent.
#
#   ./infra/role.sh headmaster   -> session "hm"     -> tmux attach -t hm
#   ./infra/role.sh kiki         -> session "kiki"   -> tmux attach -t kiki
#   ./infra/role.sh coder        -> session "coder"  -> tmux attach -t coder
#   ./infra/role.sh kill <role>  tear that one down
#
# Detach with C-b d; the agent keeps running and reattaches where it was.
# Role prompts come from roles.sh, shared with team.sh.
set -euo pipefail

if [[ "${1:-}" == "kill" ]]; then
  ROLE="${2:?usage: role.sh kill <headmaster|kiki|coder>}"
else
  ROLE="${1:?usage: role.sh <headmaster|kiki|coder> | role.sh kill <role>}"
fi

source "$(dirname "${BASH_SOURCE[0]}")/roles.sh"

case "$ROLE" in
  headmaster|hm) SESSION=hm;    MODEL=opus;   NAME=headmaster; PROMPT="$HEADMASTER" ;;
  kiki)          SESSION=kiki;  MODEL=sonnet; NAME=kiki;       PROMPT="$KIKI"       ;;
  coder)         SESSION=coder; MODEL=opus;   NAME=coder;      PROMPT="$CODER"      ;;
  *) echo "unknown role: $ROLE (want headmaster, kiki or coder)" >&2; exit 1 ;;
esac

if [[ "${1:-}" == "kill" ]]; then
  tmux kill-session -t "$SESSION" 2>/dev/null && echo "killed $SESSION" || echo "no session $SESSION"
  exit 0
fi

[[ -x "$CLI" ]] || { echo "claude CLI not found at $CLI" >&2; exit 1; }

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "$SESSION already running — attach with: tmux attach -t $SESSION"
  exit 0
fi

tmux new-session -d -s "$SESSION" -c "$REPO"

# zsh startup is not instant; keys sent before zle is up are dropped, which
# truncates the quoted prompt and strands the pane at a `>` continuation prompt.
sleep 3

# -n names the session: that is the address the other roles use with SendMessage.
tmux send-keys -t "$SESSION" \
  "$(printf '%s --model %s -n %s --append-system-prompt %q\n' "$CLI" "$MODEL" "$NAME" "$PROMPT")" C-m

echo "started $SESSION — $NAME ($MODEL) — attach with: tmux attach -t $SESSION"
