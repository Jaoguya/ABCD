# Bug-sweep decisions

Findings `bug-sweep` will not decide on its own, because they change a reported
number, pick between two defensible readings, or need §V to move.

Newest last. Mark an entry `RESOLVED: <answer>` in place once answered — the
history is the point, so do not delete entries.

---

## 2026-09-06 — Exp. 6's `full_state` omits authorization-state redistribution

**RESOLVED: A — mirrored Option D.** `full_state` now has every non-moved
authority recompute `C_k^auth` and republish it to every FSN, once per update
event, inside the timer. Payload sized before the timer, as `experiments.py`
does at the same point, so the arm is not charged for measurement work the
other two do not do. `FS/DIAS` at a 10% ratio **9.70x -> 10.04x**;
`delivered_kb` **140.35 -> 141.05 KB**. Pinned by
`test_psa_exp6_full_state_redistributes_authority_state`, which asserts against
the other arms at a 100% ratio rather than a literal KB figure.

**Residual, deliberately not fixed:** the RECOMPUTATION is modelled as a digest
over the authority's commitment, not as real work. Option D's
`Authority.commitment()` rebuilds a Merkle root over the revocation list; the
PSA world holds `world.commitments` as fixed 32-byte constants with no
authority state behind them. Giving it one would mean inventing an authority
state size, which is a parameter the paper does not publish. So the
redistribution half is now measured and the recomputation half is still a lower
bound. §V should say so rather than let a reviewer assume otherwise.

**Found:** `harness/psa_experiments.py::PsaExp6AffectedRatio.measure`. §V
defines Full-State Synchronization as reconstructing and propagating the
relevant **authorization/index** state to all FSNs. The index half was already
right — it re-evolves every policy, and each message carries the record's
complete re-tokenized entry set plus `AMeta` (not a delta; checked). The
authorization half was absent.

---

## 2026-09-06 — Exp. 1's baselines in §V no longer exist in the repo

**RESOLVED: A — name the four that are actually measured.** Overleaf is edited
by the user, so the replacement text is below; nothing in the repo changes.

`Overleaf/MA-LB-PQ-VDSE.tex` lines **2200-2201**, replace:

    with Guo \textit{et al}.~\cite{ref35}, XB-Muse~\cite{ref36}, Thingom
    \textit{et al}.~\cite{ref41}, and Zhuang \textit{et al}.~\cite{ref52}.

with:

    with Guo \textit{et al}.~\cite{ref35}, Ge \textit{et al}.~\cite{ref55},
    Thingom \textit{et al}.~\cite{ref41}, and Perera and
    Fugkeaw~\cite{ref54}.

Those four are the ones holding Exp. 1 data (20 points each; ours 5).


**Found:** `Overleaf/MA-LB-PQ-VDSE.tex:2200-2201` names XB-Muse `\cite{ref36}`
and Zhuang `\cite{ref52}` as Exp. 1 comparisons. Ref[36] was dropped
2026-08-23 (needs Intel SGX; `m6i.xlarge` exposes none) and Ref[52] was
replaced by Ref[54] on 2026-08-27. Neither has an implementation or a
`results.csv`.

**Costs:** no measured number. `fig_exp1_trapdoor.pdf` draws 5 schemes and the
sentence names two that are not among them, so the figure and its text
disagree.

**Options:**
- **A (would take)** — §V Exp. 1 names Guo [35], Thingom [41], Ge [55] and
  Perera & Fugkeaw [54], which is what is actually measured.
- **B** — keep the citations as related work rather than as compared baselines,
  and say so.

**Blocked:** nothing measurable. Worth settling before Exp. 1 is re-run, so the
rerun and the text land together.

---

## 2026-09-06 — Exp. 4's per-result wording is a restored regression (D13)

**RESOLVED: A — restore "the highest of the four".** Overleaf is edited by the
user. Two changes in §V's Exp. 4 paragraph:

1. "incurs a moderate per-result verification cost" -> "incurs the highest
   per-result verification cost of the four compared schemes", and say Fig.
   4(a) is on a log axis for that reason.
2. Restore the sentence stating Scheme [54] is absent from panel (b) because it
   verifies per record rather than by an aggregate check, so the all-or-nothing
   behaviour that panel measures does not describe it.

Both were already fixed once in `d558d63` and reverted by the Overleaf
paste-back. Also still outstanding from TASKS.md DECIDE-1: §V says Scheme [54]
was not measured in Exp. 4, and it now is.


**Found:** `MANUSCRIPT_DIVERGENCE.md` D13. The revision says the framework
"incurs a moderate per-result verification cost". Commit `d558d63` had already
changed that to "the highest of the four compared schemes", which is what the
data says and why Fig. 4(a) is on a log axis. The Overleaf paste-back restored
the weaker-and-wrong wording.

**Costs:** no number. A reviewer reading the figure sees the highest curve
described as moderate.

**Options:**
- **A (would take)** — restore "the highest of the four", plus the sentence
  saying Scheme [54] is omitted from panel (b) because it verifies per record.
- **B** — keep "moderate" and drop the log axis, which hides the spread. Not
  recommended; that is choosing the axis after seeing the result.

**Blocked:** nothing.

---

## 2026-09-06 — PSA runs were marked reportable on the campaign host

**RESOLVED: fixed, no decision needed.** Recorded because it changed what a
`run_meta.json` claims, and because the false assurance was in a docstring.

**Found:** `main.py` passed the outer `source.corpus_type` and
`corpus_sha256` into `build_metadata` for PSA runs too. A PSA experiment
builds its world in-process via `build_world()` and never opens the corpus, so
on the campaign host — where the corpus IS present — every PSA run came back
stamped `corpus_type: synthea`, carrying a corpus SHA it never used, and
`reportable: true`. `psa_experiments.py`'s module docstring asserts the
opposite ("provenance.reportability() refuses it for the same reason it
refuses any corpus_type: synthetic run"), and that assertion held only by the
accident of the dev host having no corpus.

**Fix:** PSA runs stamp `corpus_type="psa_in_process"` with no SHA, so the
existing gate refuses them on any host. Verified: `reportable: False`, refused
for corpus type and for the missing pin.

**Consequence:** the first PSA campaign (2026-09-06, host 3.81.228.58) wrote
`reportable: true` into five directories. Those runs are being re-run on the
corrected code rather than hand-edited.

---

## 2026-09-06 — PSA Exp. 4 and Option D Exp. 4 are not on a common axis

**RESOLVED: stamped, not silently compared.** The numbers are both correct;
putting them on one figure would not be.

**Found:** PSA Exp. 4's Phase VIII Step 3 runs against an in-process anchor
map. The banked Option D Exp. 4 ran against **real Hyperledger Fabric** —
commit `5ee7c16`, "like-for-like axis against real Fabric — we are now
slowest". Measured at r=1000: Option D **1675.34 ms**, PSA **16.86 ms**.
Essentially all of that ~99x is the ledger backend, not the construction.

**Fix:** `PsaExp4Verification.LEDGER_BACKEND` is stamped into every run's
`run_meta.json` with an explicit note that the two latencies are not on a
common axis. No figure merges them.

**Still open, and the user's call:** whether to wire the Fabric adapter into
PSA Exp. 4 so the comparison becomes real. That needs the Fabric network up on
the campaign host (`infra/fabric/`), which is the same gate TASKS.md BUILD-1
describes. Until then the PSA Exp. 4 curve prices verification WITHOUT chain
consistency, which §5 puts inside Exp. 4's boundary — so it is a lower bound,
not the experiment §V describes.

**Blocked:** nothing else; Exp. 1, 3, 5 and 6 are unaffected.

---

## 2026-09-06 — a timing assertion in the Option D Exp. 6 unit tests is flaky

**Found:** `test_exp6_propagation_ablation.py::test_full_rebuild_costs_more_than_the_incremental_path`
failed once in a full-suite run and passed three times in isolation and on the
next full run. It compares wall-clock latency between two arms inside a unit
test, so it loses a race whenever the suite is under load.

**Costs:** no measured number — it is a test, not an experiment. The cost is a
red suite that is not a real regression, which is how a real one gets ignored.

**Options:**
- **A (would take)** — assert on the mechanism instead of the clock: the arm
  does more WORK (authorities re-committed, nodes touched), which is already
  recorded and is deterministic. Same claim, no race.
- **B** — keep the timing assertion and give it a wide margin. Cheaper, but a
  margin wide enough to never flake is wide enough to never catch anything.

**Blocked:** nothing. Not touched this session because it is Option D's test
and the session's changes are on the psa side.

---

## 2026-09-06 — Option D's Exp. 7-8 workload uses ONE keyword, not §V's five

**Found:** `experiments.py:1616`, `SchedulerAblation.prepare`:

    token = token_mod.generate_search_token(
        deployment.scheme, profile, [record["record"].keywords[0]]
    )

One keyword per query, with no comment saying why. README §6 fixes
`q = 5`, sourced to §V ("each query contains five keywords"), and every other
experiment honours it. So Exp. 7's throughput and Exp. 8's utilization spread
were both measured on a `q=1` workload and reported against a paper that says
5.

Same class as the 2026-09-03 Exp. 2 defect (`keywords[0]` of the first record):
the number is real, the workload is not the published one.

**Costs:** `exp7_search_throughput__*` and `exp8_load_balance__*` — 4 variants
each, all banked, all in §V. Throughput at `q=5` will be LOWER: each request
does five posting-list lookups instead of one. Whether the AASS-vs-baseline
ORDERING survives is the open question, and it is the ordering the paper's
claim rests on.

**Options:**
- **A (would take)** — use `keywords[:q]` with `q` from `config.defaults`, and
  re-run Exp. 7-8 for all four variants under both constructions. Makes the
  workload the one §V describes.
- **B** — keep `q=1` and state it in §V as a deliberate single-keyword
  workload. Honest, but it contradicts §V's own sentence and README §6, and
  weakens Exp. 7 as evidence for a multi-keyword scheme.

**Blocked:** nothing today. The PSA arm deliberately uses the SAME one keyword
so that its comparison against Option D isolates the construction; if this is
fixed, both arms change together and stay comparable.

---

## 2026-09-06 — PSA Exp. 8's arms do not separate, and I cannot yet say why

**Found:** psa_exp8 was measured on the pinned host, n=10, four variants. Its
utilization spread is flat across all of them, where Option D's separates ~9x
on the same experiment at the same q:

              aass   least_loaded   no_lb   round_robin   (std dev @ conc=10000)
    PSA      0.0810     0.0726      0.0640     0.0831
    OptD     0.0587     0.0437      0.3885     0.0748

`no_lb` is the tell. It pins every request to one FSN, so its spread must be
the WORST by construction -- Option D shows exactly that (0.3885, and 8364
cross-node forwards). Under PSA it is the BEST (0.0640, 936 forwards), which
cannot be right.

**What is ruled out:** routing. The scheduler's node selection is byte-identical
between the two constructions -- same picks {FSN1:36, FSN2:12, FSN3:8, FSN4:4},
same |P_U| distribution, same request count -- because PsaSchedulerAblation
reuses Option D's decision objects and `_population`. So the arms ARE being
scheduled differently from each other; what differs is what each request COSTS
once dispatched.

**What is not ruled out:** the per-request work profile. PSA carries q*|P_U|
tokens (10-40) against Option D's q (5), and max_node_utilization is lower
under PSA (0.77 against 0.95) while throughput is comparable. That combination
-- more tokens, less node saturation -- has no explanation yet. The likeliest
candidate is that PSA's policy-state-bound tokens are far more selective, so
each of the many lookups is rejected by the Bloom filter almost immediately and
the work per request becomes both smaller and more uniform. Not verified.

**Costs:** psa_exp8 only. psa_exp7, psa_exp1-6 and every Option D result are
unaffected -- Option D's Exp. 8 separates correctly and is the one §V cites.

**Options:**
- **A (would take)** — instrument entries_traversed per request in the psa
  Exp. 7/8 replay and compare the distribution against Option D's. If PSA
  requests really do near-zero traversal, Exp. 8 under PSA is measuring an
  empty search and the fixture needs queries that match.
- **B** — report psa_exp8 as inconclusive in §V and cite Option D's Exp. 8 for
  the load-balancing claim, which is what the paper already does.

**Blocked:** nothing. NOT reported as a result in the meantime; the psa_exp8
directories are banked with their numbers, and this entry is why they must not
be read as "AASS and no_lb are equivalent".
