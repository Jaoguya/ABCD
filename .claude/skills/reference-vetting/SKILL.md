---
name: reference-vetting
description: Rules and checks for selecting a paper to cite or implement as a baseline in the OJ-COMS manuscript. Use whenever searching for a reference, proposing a new baseline scheme, adding a bibitem, or deciding whether a found paper is acceptable to cite.
---

# Vetting a reference for this paper

Applies to the OJ-COMS submission (`Overleaf/PQ-AVDSE-OJCOMS`). Two gates: the
**venue** gate, which is absolute, and the **content** gate, which is where
the real work is.

## GATE 1 — Venue: IEEE only. Non-negotiable.

**Hard rule, from the user's co-author, 2026-08-28:**

> My author reject BL-ABSE paper with reason MDPI is the most unaccept in
> journal work. So from now on provide me only IEEE paper for citation.

**Only propose IEEE-published references.** IEEE Transactions, IEEE Journals
(IoT-J, Access, OJ-COMS…), and IEEE conference proceedings are acceptable.

**Do not propose**, regardless of how good the paper looks:

- **MDPI** (*Electronics*, *Sensors*, *Applied Sciences*, …) — explicitly
  rejected by the co-author
- Springer, Elsevier, Wiley, ACM, or any other non-IEEE publisher
- arXiv preprints, ePrint, or anything not peer-reviewed

This is a **co-author's editorial decision, not a quality judgement you may
re-litigate.** A paper can pass every content check below and still be
unusable. Ref[57] (BL-ABSE, MDPI *Electronics*) did exactly that — it was the
most rigorous of the three references vetted in this project, and was still
rejected. If a non-IEEE paper looks like the only good fit, say so and stop;
do not argue for an exception.

Foundational/classic citations already in the bibliography (Boneh EUROCRYPT
2004, Shor 1994, NIST FIPS) are not affected — this governs **new** additions,
especially baseline schemes.

## GATE 2 — Content: verify, do not trust the abstract

Read the actual PDF. Three checks, all of which have caught real problems here.

**a. The DOI resolves to a real, indexed venue.** `WebFetch` the
`doi.org/...` URL and follow the redirect. Confirm the journal, volume, and
year independently.

**b. The claimed security actually matches the construction.** Read the
algorithms, not the abstract. Ref[41] (Thingom, IEEE TCE) is titled
"Post-Quantum" but every operation is a bilinear pairing under DBDH — which
Shor breaks — and the paper *says so itself* in two places while still
claiming post-quantum security. That is now a documented finding in
`References/Ref[41]/Ref[41].md`, and it is why "the title says PQ" is never
sufficient.

For a genuinely post-quantum scheme, expect lattice (LWE/RLWE/SIS), hash-based
or code-based hardness. **Any bilinear pairing or DBDH on the critical path
disqualifies a post-quantum claim.**

**c. The paper is internally coherent.** Watch for duplicated paragraphs,
off-topic filler, and self-contradiction. Ref[41] contains a passage that
drifts from cryptographic "aggregate keys" into construction aggregates
("sand, gravel, and crushed stone") — a keyword-collision artifact indicating
generated text nobody proofread.

Positive signals worth noting: a paper that quantifies its own leakage, labels
simulated baseline numbers as simulated, and lists its own limitations is
being honest with the reader.

## Recording the outcome

Write findings to `References/Ref[N]/Ref[N].md` in the established format —
citation, construction summary, published parameters, and a **legitimacy
assessment** section stating what passed and what did not. Record what the
paper does *not* publish (Ref[41] never fixes `u`; Ref[54] never fixes
`(n,q,σ)`), because those become benchmark decisions that must be made
deliberately rather than defaulted.

## Implementing vs. citing

Citing is cheap; implementing a baseline is roughly **2,000 lines** of real
cryptographic code (Thingom 1,978; Guo 2,351). A `SCHEME.md` is a
specification, not an implementation. Getting lattice crypto subtly wrong
produces plausible-looking numbers that are wrong — the worst failure mode for
a paper. Recommend citation-only unless the baseline fills a genuinely empty
experiment slot, and say plainly which it is.
