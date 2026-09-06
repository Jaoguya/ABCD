---
name: report-back
description: The reporting discipline for this project - roll the whole thread up into a short, scannable answer before delivering any result, figure, number, fix, or explanation. Use before reporting what a run produced, handing over a figure or artifact, explaining a mechanism or a decision, or answering "summarize" / "what is the state" / "what is open".
---

# Report back

Before anything is delivered — a result, a figure, a fix, an explanation —
roll up the thread. The reader has not been watching the tool calls and should
never have to scroll back to reconstruct what happened.

## The gate

Answer these five before writing. Anything with no answer gets **cut**, not
padded.

1. **What moved?** A number, with before → after. No number, no line.
2. **What failed, or what did I get wrong?** Say it plainly, once, early.
3. **What is theirs to decide?** One question carrying every facet.
4. **What is still open?** Named, not implied.
5. **What is the state?** Suite count, tree state, what is committed.

## Shape

From the user's standing instructions, and non-negotiable here:

- **Lead with the answer.** Never with what you are about to do, or a
  restatement of the question.
- **Scannable bullets by default.** One fact per bullet, one line each.
- **Bold the word the bullet turns on** — the claim, not the topic.
- **Numbers go in tables.** Every table has the unit in the header.
- Prose paragraphs only when prose was asked for.
- Spend extra lines only on: a number that moved, a thing that failed, or a
  decision that is theirs.

## Cut every time

- Preamble, restatement, and narration of what you are about to do.
- Re-deriving what the thread already settled.
- Options you will not pursue.
- Apology and self-criticism. Correct the fact, move on.
- Praise for the question.
- A finding manufactured to justify the reply having content.

## Decisions

**One question with every number-changing facet in it.** Serial option cards
read as stalling — the user has said so directly.

When options are listed, each row states: what it costs, what it keeps, what it
breaks. Name the one you would take. Never present four options with no
recommendation.

If a decision is theirs but nothing is blocked on it, say **"Blocked:
nothing"** and keep working. Do not stop the work to wait.

## Delivering a result

Alongside the number, always:

- **Whether it is reportable.** Corpus type, host, `n_runs`. A development
  number said plainly is fine; one that reads as reportable and is not, is not.
- **What the axis means.** This project has shipped three defects where the
  number was plausible and the unit was wrong (`d1cdf9c`, the Exp. 9 unit, the
  Exp. 5 halving). State what one point *is*.
- **Which construction produced it** — Option D or PSA. They time different
  functions at the same experiment number.
- **Computed vs measured.** Extrapolated points are named as extrapolated.

## Verification claims

Report only what was actually run. "Tests pass" needs the count. "It works"
needs the command and its output. If a step was skipped, say which and why.
Never report a fix as verified when only the happy path ran.

## The floor

If the honest summary is "nothing moved, here is what is open" — write that.
A short true report beats a long one padded to look like progress.
