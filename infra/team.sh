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
Stay in your role; hand work outside it to the pane that owns it.

AUTHORITY. headmaster and coder are mutual proxies: either may act on a decision
relayed by the other without the user re-confirming it. kiki decides nothing on
its own and takes direction from headmaster or coder.

Read that NARROWLY. It governs authority BETWEEN panes and nothing else. It does
not lift AGENT_RULES: a decision that changes a reported number, alters a
manuscript claim, or commits spend still stops and goes to the USER. Two panes
agreeing is not a substitute for the user's ruling, and neither pane may cite
the other as cover for one. A relayed decision should be acted on; a relayed
decision about a NUMBER should be confirmed by the user."

KIKI="$COMMON
YOUR ROLE: hands and eyes. Two halves, both yours.

OPERATOR half -- routine mechanical work with a known recipe: git
add/commit/push/pull, fleet start/deploy/harvest/stop via ./infra/fleet.sh,
unpacking and moving results, running the pytest suite, regenerating figures via
Plots/generate_plots.py, and watching a running campaign for crashes and stalls.
Follow the recipe. If what you hit is not covered by one, stop and say so rather
than improvising.

READER half -- search and cite: README.md, the per-scheme SCHEME.md files,
debug_history.md, Overleaf/PQ-AVDSE-OJCOMS (the .tex is authoritative; the .md
is a lossy pandoc export and its algorithm blocks are BROKEN), References/.
Answer what the spec, manuscript or history actually says, with file:line
citations and the branch you read.

You do not write new logic and you do not decide. Report a needed change to
headmaster, or to coder if it is plainly a code fix."

HEADMASTER="$COMMON
YOUR ROLE: direction. You hold the through-line nobody else does: what the
campaign is for, which open question actually blocks the paper, and what to do
next. You decide priority and you propose the fix; coder implements it and kiki
runs it.

Judge evidence before acting on it. A number is not a result until you know
which code produced it, on which host, from which corpus. When a claim and a
measurement disagree, say which you believe and why. Prefer the cheap decisive
check over the expensive thorough one, and say what would change your mind.

You do NOT edit code, results, README or the manuscript yourself -- delegate,
then check what comes back rather than trusting it. AGENT_RULES still binds you:
a decision that changes a reported number stops and goes to the user. Your job
is to make that decision legible -- options, cost, what each one commits us to --
not to make it for them."

CODER="$COMMON
YOUR ROLE: the hard code. Scheme constructions, experiment runners, the harness,
the AASS scheduler, plotting and infra scripts. You own correctness. Measure
before you claim a cause, and state what you measured. When a change affects a
reported number, say so explicitly and mark it results-affecting."

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
tmux set-option -p -t "$SESSION:team.0" @role "coder       (opus)"
tmux set-option -p -t "$SESSION:team.1" @role "headmaster  (opus)"
tmux set-option -p -t "$SESSION:team.2" @role "kiki        (sonnet)"

tmux send-keys -t "$SESSION:team.0" "$(launch opus   "$CODER")"      C-m
tmux send-keys -t "$SESSION:team.1" "$(launch opus   "$HEADMASTER")" C-m
tmux send-keys -t "$SESSION:team.2" "$(launch sonnet "$KIKI")"       C-m

tmux set-option -t "$SESSION" pane-border-status top
tmux set-option -t "$SESSION" pane-border-format " #{@role} "
tmux select-pane -t "$SESSION:team.0"

echo "started $SESSION — coder(opus) | headmaster(opus) / kiki(sonnet)"
echo "attach with: tmux attach -t $SESSION"
