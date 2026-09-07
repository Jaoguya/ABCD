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

**RESOLVED: A — asserts the mechanism now, not the clock.** Fixed in 202cdbd.
`test_full_rebuild_costs_more_than_the_incremental_path` compares FSNs touched
and bytes delivered, both recorded per run and deterministic; that IS the
claim (Full-State processes more state) and it cannot race. 27 passed, three
consecutive runs.

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

**RESOLVED: A — fixed and re-run, on the user's instruction.** Both
constructions now take `keywords[:q]`. Exp. 7-8 were re-measured for all four
variants on the pinned host at commit 37aa787 and the banked q=1 data is
superseded. The ORDERING the paper rests on did not just survive, it improved:
AASS is now first at every concurrency (2255/3275/3622 q/s at 100/1000/10000),
where at q=1 the field was tight and the order moved around below 1000.
Exp. 8 is unchanged in character -- least_loaded still takes the lowest spread.

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

**RESOLVED: A was done, and it answered the question.** Instrumenting
`entries_traversed` found TWO defects underneath -- the conjunctive query
could never match >1 keyword (9519a02) and the PSA query was posed as one flat
conjunction across policies (2e98705, 7bf4152). With both fixed the queries
match and the arms STILL do not separate, for a reason now understood: see the
2026-09-07 entries for Exp. 8 and Exp. 7. Not a scheduler defect; §V cites the
cross-scheme results for both.

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

---

## 2026-09-06 — I cited the wrong reference in §V Exp. 1

**RESOLVED: fixed.** `yue_ge` is **Scheme [30]** (Ge *et al.*, IEEE IoT-J 2024),
not `ref55` (Cao *et al.*, puncturable encrypted search). My earlier §V Exp. 1
edit wrote `\cite{ref55}`, putting a reference into the baseline list that has
no implementation and no results — the exact defect that edit was made to fix.
Corrected to `\cite{ref30}`.

Caught by cross-checking §V's citations against the measured roster rather than
by re-reading my own edit. That audit now covers all five cross-scheme
experiments and every one passes: Exp. 1-3 cite [30],[35],[41],[54];
Exp. 4 cites [30],[35],[54]; Exp. 5 cites [30],[35] — each exactly what has a
`results.csv`.

**Costs:** nothing measured. A reviewer following the citation would have found
an unrelated paper.

---

## 2026-09-06 — the task board was stale on its highest-impact item

**RESOLVED: TASKS.md corrected.** `BUILD-2b` ("batch Exp. 4's chain lookup")
was listed `open` and described as "what actually reaches 2nd". It has been
LANDED since `e252cc9`; `Exp4Verification.measure` calls
`vledger_mod.batched_chain_checker`, and `d3452c0` measured it at 2.19x with
the O(r) chain term surviving.

So the batching target was met and reaching 2nd was not — that needs BUILD-2's
aggregate proof alongside it, which `TASKS.md` separately records as
insufficient alone (9.08 ms against [30]'s 9.139, a tie).

`DECIDE-1` was also stale: §V already names the measured Exp. 4 roster.

**Why this matters:** I recommended BUILD-2b as the single highest-impact open
item, on the board's word. Had that recommendation been acted on it would have
been a day spent re-implementing something already in `main`.

---

## 2026-09-06 — a conjunctive query over >1 keyword can NEVER match

**Found:** `index/dsi.py::lookup` intersects **ordinals**:

    matched = hits if matched is None else (matched & hits if conjunctive else ...)

An ordinal is one index ENTRY, and an entry carries exactly ONE token. Two
distinct keywords therefore never share an ordinal, so a conjunctive query over
two or more keywords returns the empty set by construction. Measured directly:
a single-keyword lookup on a record's own shard returns 8 hits; the same
record's 5 keywords conjunctively return 0, traversing 26 entries to do it.

The docstring says "``conjunctive=True`` implements the q-keyword conjunctive
query of §V; the corpus's ``min_keywords_per_record: 5`` exists so that such a
query can match at all" -- so per-RECORD intersection is what was intended. The
implementation intersects per entry. §V's central search claim is a
`q`-keyword conjunctive query, and the index cannot answer one.

**Blast radius, measured not assumed:**

* `psa_exp2_search_latency` -- **n_eff = 0.000000 at every sweep point.** I
  banked this today and called it "the first reportable PSA number". It times
  a search that matches nothing. Superseded.
* `exp7_*`/`exp8_*` at q=5, both constructions, banked today -- every request
  returns 0 hits. Traversal is real (PSA 13.2 entries/req, Option D 25.3) so
  the throughput figures are not empty, but they price a workload where nothing
  matches, and that is not the workload §V describes.
* **`exp2_search_latency` is NOT affected** -- it rotates ONE keyword per run
  (the 2026-09-03 fix), so it never takes the conjunctive path. Banked n_eff
  runs 9.5 -> 220.1, non-zero and meaningful.
* Exp. 1, 3, 4, 5, 6 do not search. Unaffected.

**This also explains PSA Exp. 8.** With no hits, per-request work is dominated
by token lookup, which is uniform -- so no node saturates and the four arms
cannot separate. PSA traverses HALF what Option D does (13.2 against 25.3)
despite carrying twice the tokens, because policy-state-bound tokens are more
selective, which is why its `no_lb` failed to pin. Not a scheduler defect at
all.

**RESOLVED: fix the index to intersect per RECORD (by CID), not per entry.**
That is what the docstring says it does and what §V describes, it makes
`min_keywords_per_record: 5` meaningful, and it is the only version in which a
multi-keyword query can return anything. Then re-run Exp. 2 (psa), Exp. 7 and
Exp. 8 under both constructions.

The alternative -- keep per-entry semantics and call every §V query
single-keyword -- would mean the paper's q=5 conjunctive claim has never been
measured by anything, which is worse than a re-run.

---

## 2026-09-07 — Scheme [41]'s Exp. 2 stays extrapolated above N=10^4

**RESOLVED: author's call, and the numbers support it.** Measuring the missing
points was launched on three boxes and stopped within minutes on the
instruction "search single or 10k, then multiply into a straight line, do not
run the whole million".

From Scheme [41]'s own banked `raw_runs.csv` -- 740.1 s per run at N=10^4, 10
runs = 123 min -- and its published O(N) search with no early termination:

    N          per run    per point (10 runs + 5 warm-ups)
    50,000       1.03 h      15.4 h
    100,000      2.05 h      30.8 h
    500,000     10.2  h     154   h
    1,000,000   20.5  h     307   h    (~12.8 days)

~508 instance-hours for one baseline's one experiment, against ~$98 of compute
and nearly a fortnight of wall clock on the pinned host.

**What this does NOT weaken:** every other scheme measures N=10^6 at n=10 --
the proposed scheme, [30], [35] and [54]. Scheme [41] is the only curve with
extrapolated points, its markers are already drawn hollow, and
`MANUSCRIPT_FIXES.txt` item 1 carries the caption text that says so.

**Blocked:** nothing. Three boxes were started for this and are stopped again.

---

## 2026-09-07 — PSA Exp. 8 still does not separate, and now I know why

**Not a scheduler result. A harness modelling limit.** After the conjunctive
and per-policy-grouping fixes, PSA requests match (950 hits / 40 requests) and
the nodes saturate (max_util 0.83-0.91, up from 0.77). The four arms still sit
at 0.04-0.12 std dev with no ordering, where Option D separates ~9x.

**The mechanism:** a request is dispatched to ONE node. Under PSA the query is
one group per authorized policy, and the shard evaluates only the groups whose
domain it serves -- a request with |P_U|=8 spanning four domains does 2 of its
8 groups on the chosen node and drops the rest. So per-request work varies with
how well the user's policies match that node's domain, which flattens
utilization regardless of which scheduler chose the node. Routing is identical
between constructions ({FSN1:36, FSN2:12, FSN3:8, FSN4:4} in both), so the
scheduler is not what differs.

Option D has one token with no policy, so the chosen node always does the same
work and `no_lb` pins as it should.

**The real fix is cross-node forwarding** -- a multi-domain PSA request should
reach every node holding an authorized shard, which is the communication
README §5 already records as unmeasurable at d = m = 4. That is a change to
what Exp. 7-8 model, not a bug fix.

**RESOLVED: cite Option D's Exp. 8 for the load-balancing claim** (which §V
already does) and report psa_exp8 as measuring the construction's per-request
cost, not scheduler quality. `MANUSCRIPT_FIXES.txt` item 6 already tells §V to
separate the two constructions' results; this is why it matters for Exp. 8
specifically.

---

## 2026-09-07 — psa Exp. 8 is not cited for the load-balancing claim

**RESOLVED: author accepted the recommendation.** §V's setup paragraph now
says the load-balancing results of Experiment 8 are the CROSS-SCHEME ones, and
states why the construction's own figures do not carry that claim: under a
policy-bound token a request is evaluated only against the query groups whose
domain the selected node serves, so per-request work varies with the match
between a user's authorized policies and that node's domain rather than with
the scheduling rule.

psa_exp8's data stays banked and stays in the repository -- it characterises
the construction's per-request cost, which is a real quantity. It simply is not
evidence about schedulers, and the paper no longer implies that it is.

---

## 2026-09-07 — three superseded n=30 directories removed (FIX-4)

**RESOLVED: removed.** `exp7_search_throughput`, `exp8_load_balance` (both
unsuffixed, n=30, from 55aa3c8) and `exp6_authorization_sync__no_lb` (n=30,
`reportable=false`, a scheduler variant that Exp. 6 does not have) are gone.

Checked before deleting, not after: `generate_plots.py` reads only the
`__variant` directories for Exps. 6, 7 and 8, and all 8 figures still render
with the same series after removal. The data is git-tracked, so the removal is
reversible from history -- which is what makes this a cleanup rather than a
destructive act.

TASKS.md carried this as FIX-4, "two stale merged directories". There were
three.

---

## 2026-09-07 — psa Exp. 7 cannot discriminate schedulers either

**RESOLVED: §V excludes psa Exp. 7 from the scheduler claim, as it already
does Exp. 8.** Extends the 2026-09-07 Exp. 8 entry rather than contradicting
it.

After the per-policy grouping fix, psa Exp. 7's queries match (950 hits / 40
requests) and it was re-measured at n=10 on the pinned host. The four variants
land within noise of one another -- 2453.6 / 2516.2 / 2493.9 / 2515.2 q/s at
concurrency 10,000 -- and the rank order shuffles across sweep points with no
variant leading twice in a row. Option D at the same q separates cleanly, with
AASS first at every concurrency.

**Same mechanism as Exp. 8, and I should have predicted it there.** A request
is dispatched to ONE node and that node evaluates only the query groups whose
domain it serves, so the work a dispatch actually costs is set by the overlap
between the user's authorized policies and the node's domain, not by which
node the scheduler chose. Throughput and utilization are two views of the same
per-request cost, so if one cannot discriminate, neither can the other.

An earlier §V edit today said psa throughput WAS obtained comparably; that was
written before this run existed and is now corrected -- the setup paragraph
excludes both Experiments 7 and 8.

**Not a defect to repair.** The fix is cross-node forwarding, which changes
what Exps. 7-8 model. README §5 already records that communication as
unmeasurable at d = m = 4.

---

## 2026-09-07 — extrapolated points were drawn SOLID, and §V claimed otherwise

**RESOLVED: fixed.** `generate_plots.py` marked a point computed when
`n_runs == 0`. `infra/extrapolate_points.py` writes `n_runs=1` with
`measurement_type=projected`, so the rule never fired: Scheme [41]'s four
extrapolated Exp. 2 points rendered as solid markers, visually identical to the
measured ones.

Worse, the fig:exp2 caption applied to the manuscript earlier the same day
states they "are drawn with hollow markers". The figure did not do what the
paper said it did.

The plotter now reads the `measurement_type` column and treats `projected` as
computed; the `n_runs == 0` rule is kept for older files that predate the
column. Verified: hollow at N = 50k, 100k, 500k, 1M and solid at 10^4, which
matches the results.csv exactly.

**Found by looking at the rendered figure**, not by reading code -- the first
time these plots had been generated from final data rather than into a
scratch directory.

---

## 2026-09-07 — `Plots/output/*.pdf` shipped the pre-fix figures beside the fixed ones

**RESOLVED: regenerated the flat set from current code.** `f68ac60` fixed the
hollow-marker rule and regenerated `Plots/output/pdf/` and `Plots/output/png/`,
but the eight files it *added* at the flat path `Plots/output/fig_exp*.pdf|png`
came from a run made **before** the code fix. Byte sizes show it:
`Plots/output/fig_exp2_search.pdf` was 19,644 bytes — exactly the pre-fix
`pdf/fig_exp2_search.pdf` — while the post-fix one is 19,910. Rendering both
confirms it: the flat copy drew Scheme [41]'s four extrapolated Exp. 2 points
**solid**, which is the defect `f68ac60`'s message says it fixed, and which
`fig:exp2`'s caption ("drawn with hollow markers") contradicts.

So the repo carried two sets of the same eight figures, disagreeing, and the
flat set — the one a person grabs first — was the wrong one.

All four sets regenerated from the current banked data at `e503655` + this
session's doc-only edits: flat PDF, flat PNG, `pdf/`, `png/`, plus the eight
`fig_psa_*.png`. Verified by rendering `Plots/output/fig_exp2_search.pdf`:
hollow at N = 50k, 100k, 500k, 1M; solid at 10^4.

**No measurement changed** — the same `results.csv` cells, drawn correctly.

---

## 2026-09-07 — `scheduler.yaml` and `aass.py` still published the five-term SC_j

**RESOLVED: aligned both to `eq:search-cost`'s four terms.** `59e11f3` dropped
`C_j^auth` from `CostVector` and `config.py`, and `scheduler.yaml`'s `weights`
block, but left the five-term formula in three places a reader reproducing the
scheduler would hit first: `aass.py`'s module docstring, `estimate_costs`'s and
`_scored`'s docstrings ("the five raw terms"), and `scheduler.yaml`'s header
formula plus its `cost_terms.auth` entry labelled `# published`. The code was
right and its documentation described a scheduler the paper does not define.

`cost_terms.auth` removed, the two formulas rewritten to four terms, and the
manuscript's actual `C_j^sync` (the count of query-relevant authorities the
node lags) now recorded next to the scalar `|VID_U - VID_j|` the code uses, so
divergence D2 is visible at the point of use. `sweep:` is left describing the
1001-vector L1..L5 grid: that is a record of what was run on 2026-08-28, not a
current rule.

**Config hash moves.** `scheduler.yaml`'s SHA-256 no longer matches the
`config_hashes` in the banked `run_meta.json` files. Nothing measured changed —
the removed key was never read by `config.py` — but a re-run will stamp a
different hash than the banked campaign, and that needs saying rather than
discovering.

---

## 2026-09-07 — `\usepackage{graphi  cx}` stopped the manuscript compiling

**RESOLVED: fixed to `\usepackage{graphicx}`.** A stray double space inside the
package name. LaTeX would fail with "File `graphi.sty' not found" before
reaching any of the nine `\includegraphics` calls. Backed up to
`Overleaf/MA-LB-PQ-VDSE.tex.bak-20260907`; one-line diff shown in the session.

---

## 2026-09-07 — `requirements.txt` was deleted while `provision.sh` still installs from it

**RESOLVED: restored verbatim from `95eb49f~1`.** `95eb49f`
("chore: remove AGENT_RULES.md, debug_history.md, requirements.txt") took it
out with two agent-workflow files, but it is not an agent file — it is the
dependency manifest for the EC2 experiment host.

`infra/provision.sh:58` is

    pip install --quiet -r "${REPO}/requirements.txt"

under `set -euo pipefail`. With the file absent, provisioning **aborts at line
58** — before the ML-KEM backend, before the charm-crypto build Ref[41] needs
for its Type-I pairing, and before the primitive-test gate at line 163 that is
the whole point of the script. A fresh instance could not be built at all, and
the failure lands early enough that none of the warnings the script prints for
partial setups would ever appear. `MacOS/SETUP.md:47` reads from it too.

Restored content checked against what the campaign actually ran, from
`run_meta.json`: cryptography 50.0.0 (>= 43.0.0, and >= 46.0 so its ML-KEM
module is live, matching `kem_backends_available.cryptography: true`), numpy
2.4.6 (>= 1.26.0), scipy 1.17.1 (>= 1.12.0), pyyaml 6.0.3 (>= 6.0.0), Python
3.11.15. `petrelic` stays commented out, which matches the banked
`pairing_backends_available.petrelic_bn254: false`. `pip install --dry-run`
resolves every pin.

**No measurement changed.** This restores the ability to build a host that
reproduces them.

**Must be committed and pushed before the next `fleet.sh deploy`.** Deploy does
`git reset --hard origin/main`, so an uncommitted fix does not reach the nodes —
they would land on `e503655`, which has no `requirements.txt`.

---

## 2026-09-07 — BLAS thread pinning was configured, recorded, and gated nowhere

**RESOLVED: wired `verify_thread_pinning(require=True)` into `reportability()`
as a blocker.** Its own docstring already said "`require=True` is for reportable
runs", but the only call site in the repo was a test passing `require=False`.
So the pin was declared in `global.yaml` (`blas_threads: 1`), exported by
`provision.sh`, RECORDED into `run_meta.json` by `build_metadata` — and never
checked. All 85 banked runs carry

    blas_thread_env: {OMP_NUM_THREADS: UNSET, OPENBLAS_NUM_THREADS: UNSET,
                      MKL_NUM_THREADS: UNSET, NUMEXPR_NUM_THREADS: UNSET}

and every one was still stamped `reportable: true`.

`provision.sh` writes the exports to `/etc/profile.d/malbpq-threads.sh`, which
only a **login** shell sources; work dispatched over `ssh host "cmd"` never
reads it. That is the likely mechanism, though the AMI's build date could
equally explain it — either way the guard would have caught it and did not.

**Why it matters more now than when it was written.** The rationale in the code
still names Ref[52], a scheme that no longer exists. The live reason is
different: `environment.instance_type` was dropped 2026-08-30 so guo Exp. 2
could have the ~52 GB its forward index needs, so the campaign now spans
`m6i.xlarge` (4 vCPU) and `r6i.4xlarge` (16 vCPU). Unpinned BLAS across two core
counts is precisely the cross-host incomparability the pin exists to remove.

**A blocker, not a note**, matching the documented intent: an unpinned run now
fails on its first point instead of after a campaign. Verified both directions —
refuses with the vars unset, passes with them exported.

**This does not change any banked number.** It changes what a FUTURE run is
allowed to call reportable. Before the next campaign, export

    OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1

in the same shell as the run, or source `/etc/profile.d/malbpq-threads.sh`
explicitly. **The 85 banked runs were measured unpinned and that is now a stated
limitation, not a silent one.**

---

## 2026-09-07 — three test gaps that let documentation drift past a green suite

**RESOLVED: all three closed.** `CLAUDE.md` says "every defect found so far was
found with it green"; these are three reasons why.

1. **`test_cost_table_agreement.py`'s coverage guard did not cover what its
   docstring claimed** ("everything else that produces a latency curve is
   asserted above"). Its loop ran over four schemes — `thingom_pq_abse` absent —
   and two experiments, 1 and 4. Added thingom and Exp. 5, plus the three claims
   that then became required: `[41]` Trapdoor `O(u+q)(T_H+T_Mul)+T_E`, `[30]`
   Dynamic Update `O(k)`, `[35]` Dynamic Update. All three fit linear on the
   banked data.

2. **`PSA_CLAIMS` omitted the Verification row on a stale premise.** The scope
   note said the PSA track does not fork Verification, so the row was
   "correspondingly absent". It IS forked — `PsaExp4Verification` is in
   `PSA_EXPERIMENTS` and `psa_exp4_verification_overhead/` holds a 10-run sweep.
   Added `O(r log t)T_H + O(r)T_BC`, linear in `r`.

   Exp. 2 stays absent in both tables, now with the reason recorded in
   `EXP2_NOT_SHAPE_ASSERTABLE`: every Search row is written in a variable that
   is not the swept `N`, so the measured rise is a property of the
   constant-selectivity workload rather than a prediction the row makes.
   Asserting a shape there would invent a claim the table does not make.

3. **`test_repetition_count_agreement.py` read `README.md` and the `.tex`
   only.** That is why the 30 -> 10 migration reached both of those and none of
   the six documents that print runnable commands: on 2026-09-07
   `SystemConfiguration.md` and all five `SCHEME.md` files still said
   `--runs 30` against a config of 10 and 85 banked runs at `n_runs=10`. Three
   separate fixes of this number passed a green suite. Added
   `test_every_document_printing_a_command_matches_the_config`, which
   parametrises over all six; it caught 15 stale commands, all corrected.

**No measurement changed.** These make the suite able to see the drift class it
has now missed three times.

---

## 2026-09-07 — two dead cross-references in the code

**RESOLVED.** `yue_ge/src/digest.py:15` and `msre.py:21` both cited
**"README §245"**, which has never existed; the `Common/` scope rule they quote
is README **§8** ("Repository Structure"). Retargeted.

Separately, five docstrings described the frozen corpus as having a
**2,006-keyword** vocabulary; `Dataset/dataset_manifest.json` says
`keyword_universe_size: 2023`. Corrected in `index/tokens.py` (x2),
`psa/tokens.py`, `harness/provenance.py` and `tests/test_phase4.py`. These are
prose claims about the corpus and carry a security argument (the cost of
inverting an unkeyed token by dictionary attack), not a measured number.

The literal `2006` in `psa_experiments.py:512` is left alone deliberately: it
sizes the PSA track's **synthetic** vocabulary, which has no corpus behind it,
and is self-consistent. `experiments.py:104`'s `vocabulary: int = 2006` is a
dataclass default that line 203 overwrites from the manifest on every real run.

---

## 2026-09-07 — Exp. 2's workload is not the one §VI describes (four findings)

**RESOLVED (partly): Found 1 and 2 fixed in code; 3 and 4 still need an
author's call, and the banked Exp. 2 numbers are superseded either way.**

Found 2 was decided by precedent, not by me: Exp. 4 carried the identical
`// keywords_per_record` defect and had already been fixed, with the reasoning
spelled out in `Exp4VerificationOverhead.prepare` ("the figure's x-axis counted
index entries under a caption reading *returned results*... Every baseline
sweeps r as RECORDS"). Exp. 2 fixed the same way: `record_count = int(value)`,
in both `Exp2SearchLatency` and `PsaExp2SearchLatency` so the two constructions
stay comparable.

Found 1 fixed by following the Exp. 7/8 precedent, with one addition. Five
INDEPENDENTLY drawn keywords match nothing over `|W_i| ~= 32`, so the query is
now built as: the anchor is drawn by `select_query_keywords` at the baselines'
selectivity (unchanged, still matching `yue_ge`), and the remaining `q-1` come
from a record that CARRIES the anchor. The anchor sets selectivity; the
completion makes the conjunction answerable. Verified `n_eff = 15.0`, not 0.

Exp. 3 carries the same `q=1` shape but its construction indexes ONE shared
keyword across every domain deliberately -- that is the property it measures --
so it is not a like-for-like change and is left for its own pass.

Tests added: query carries `q`; query keywords co-occur in a real record; the
query changes run to run; `n_eff > 0` (was `>= 0`, which passes on the empty
result); `N` builds `N` records. `test_psa_exp2_shares_fewer_posting_lists_than_
option_d` hardcoded the old sizing and was comparing a 50,000-record PSA index
against an 8,333-record Option D one; aligned, and it passes like-for-like.

**Still open:** Found 3 (drop §VI's constant-selectivity sentences, or build a
relative band) and Found 4 (does §VI's Exp. 2 report `option_d` or `psa`). Found
4 decides what gets re-run; both arms are fixed identically so neither blocks
the other. The banked `exp2_search_latency/` numbers are not quotable until the
re-run — they were measured at `q=1` over a 32x-small corpus.


Audit of Exp. 2 against `Overleaf/MA-LB-PQ-VDSE.tex` §VI, the banked
`exp2_search_latency/`, and the code that produced it. All four change a number
already in `results.csv` and in `fig:exp2`, so none is taken unilaterally.

**Found 1 — `q = 1`, against §VI's five.** `experiments.py:765`:

    token = token_mod.generate_search_token(
        d.scheme, prepared["profile"], [keyword]
    )

Verified by running it: `len(token.tokens) == 1`, against
`global.yaml defaults.keywords_per_query: 5` ("published: §VI *each query
contains five keywords*"). This is the SAME defect the 2026-09-06 entry
("Exp. 7 and 8 measure a `q=1` workload") fixed for Exp. 7/8 at
`experiments.py:1641`. That entry states *"every other experiment honours it"* —
that sentence is wrong. Exp. 2 was never fixed, and neither was Exp. 3
(`experiments.py:863`, same single-keyword shape). `PsaExp2SearchLatency`
DOES use `q=5` (`psa_experiments.py:1063`), so the two constructions plotted at
experiment 2 do not share a query size.

**Found 2 — the axis lies: entries against records.** `experiments.py:718` sizes
the deployment as `record_count = int(value) // self.source.keywords_per_record`
— with the frozen corpus's `keywords_per_record.mean = 31.70` (→ 32), the
`N = 10^6` point indexes **31,250 records**. All four baselines index `records[:n]`
= **1,000,000** (`guo_vdsse/src/exp2_search.py`, `yue_ge/.../runner.py:130`,
`perera_lv_pqabse/.../runner.py:87`). `generate_plots.py:191` labels the shared
x-axis **"Index size $N$ (records)"**, and §VI reads "from $10^4$ to $10^6$
encrypted records". So the proposed scheme is drawn at ~32x less corpus than
every baseline at the same plotted x, under a label that says otherwise. This is
the sweep-value-is-not-the-work-done class the bug-sweep rule calls mine, but it
has banked reportable data and a manuscript sentence behind it, so it is here.

**Found 3 — "query selectivity is kept constant" is contradicted by the data.**
§VI: *"query selectivity is kept constant. Hence, the number of matching records
increases proportionally with the index size."* From the banked
`raw_runs.csv`, N grew **100x** and `n_eff` grew **23.2x** (9.5 -> 220.1).
Cause: `select_query_keywords` (`experiments.py:665`) draws uniformly from an
ABSOLUTE frequency band (`QUERY_MIN_FREQUENCY = 5`, `QUERY_MAX_SHARE = 0.5`),
so the floor of 5 binds hard at small N and loosens as N grows — relative
selectivity drifts down instead of holding. Constant selectivity needs a
RELATIVE band. `test_cost_table_agreement.py:120` records the same assumption
("Under the constant-selectivity workload the match count rises with N") as the
reason Exp. 2 is exempt from the shape assertions, so the exemption rests on a
premise the data does not support. The bounds themselves are a faithful copy of
`yue_ge/src/workload.py::select_keywords` and are pinned by
`test_bounds_match_the_baselines` — the copy is correct; what it implements is
not what §VI claims.

**Found 4 — `fig:exp2` draws `option_d`, §VI's Exp. 2 prose describes `psa`.**
The figure is `images/fig_exp2_search.pdf`, built by
`ExperimentSpec(2, "exp2_search_latency", ...)` with no `proposed_prefix`, so
the proposed curve is Option D. The §VI paragraph describes the AIM deriving
"the policy-state-aware token set $\mathcal{T}_Q$" — the PSA construction.
`psa_exp2_search_latency/` is banked, reportable, and never plotted: 13.400 ms
against Option D's 6.040 ms at `N=10^6`, **2.2x**. Exp. 1 was moved onto the PSA
track by 5143ee7 (`proposed_prefix="psa_"`); Exp. 2 was not, so the two figures
now describe different constructions of "the proposed scheme".

**Costs:** `fig:exp2` and every §VI sentence about it. Fixing 1 raises the
proposed curve (five posting-list lookups per query, not one). Fixing 2 raises it
again and by far the most (32x the records). Both move it toward the baselines,
and the "slower latency growth" claim is what rests on the gap. Fixing 3 changes
the shape, not just the level. Fixing 4 swaps the curve for one 2.2x higher.
Re-running Exp. 2 for all five schemes is an AWS campaign, and Scheme [41] stays
extrapolated above 10^4 per the 2026-09-07 entry.

**Options:**
- **A (would take)** — fix 1 and 2 together (`keywords[:q]` from
  `config.defaults`; size the deployment as `records = N` like the baselines),
  re-run Exp. 2 for all five schemes, and settle 4 by deciding which
  construction §VI's Exp. 2 is about. For 3, either implement a relative
  selectivity band or drop the "kept constant / proportionally" sentences from
  §VI — the sentences are the cheaper half and the workload is already shared
  with two baselines.
- **B** — change §VI to describe what was measured: a single-keyword query over
  an index of N ENTRIES. Costs no compute, but contradicts §VI's own "five
  keywords" sentence and README §6, and leaves the proposed scheme measured on a
  32x smaller corpus than its baselines, which is not defensible as a comparison.

**Blocked:** nothing else. Exps. 1, 3-9 proceed; Exp. 3 carries Found 1's
single-keyword shape and should be settled in the same decision.

---

## 2026-09-07 — Fig. 2's six runs used four different `global.yaml` files

**RESOLVED: A was done. The drift is benign for Exp. 2, and the check that
would have said so now exists.**

Diffed all four revisions plus HEAD over every key Exp. 2 reads. `defaults`
(`keywords_per_query`, `domains`, `fog_search_nodes`, `index_size`,
`returned_results`) and `experiments.exp2_search_latency` are IDENTICAL across
all five. The only difference in `measurement` is `repetitions`: perera's
revision carried 30 where every other carried 10 — and perera's banked
`raw_runs.csv` has exactly 10 rows per point, so the data is comparable.

Why it agreed anyway is its own small finding: perera never reads `global.yaml`.
`--runs` is an argparse default hardcoded to 10 (`perera_lv_pqabse/src/main.py:76`),
and `yue_ge/src/main.py:63` does the same. They happened to match the config.
Not fixed here — it is four CLIs and changes no banked number — but it is why
the config hash drifted without the data drifting.

`generate_plots.py` now warns when the schemes drawn in one figure carry
different `global.yaml` hashes, or when one carries none. It fires today on
**exp1, exp2, exp3 and exp5**; the other three have not been diffed yet.


**Found:** the `config_hashes["global.yaml"]` recorded by the six runs that make
up `fig:exp2` are four distinct values, and none is the file at HEAD:

    ma_lb_pq_vdse  exp2       ac5568611661bda2   79a5739
    ma_lb_pq_vdse  psa_exp2   1b8f581994c3a145   2e98705
    guo / yue_ge / thingom    032de0d9dcaf5b48   ad6486f
    perera_lv_pqabse          8172f55ef8baffc1   6c97ee9
    (HEAD, after 5143ee7)     bf22f61f9d2cebc3

`global.yaml`'s own header: *"CHANGING ANY VALUE HERE IS RESULTS-AFFECTING and
invalidates every existing results.csv."* It fixes `keywords_per_query`,
`repetitions`, `warmup_runs` and the Exp. 2 sweep values — the parameters that
make the five curves comparable. The hashes are recorded faithfully in every
`run_meta.json`; nothing checks that they AGREE across the schemes sharing a
figure, so the drift is invisible at plot time.

`ad6486f` is the "10 repetitions" commit, so the guo/yue/thingom runs are at
least on the reduced count; the ma_lb and perera hashes predate or postdate it
and were not audited value-by-value here.

**Costs:** unknown until the four files are diffed. If they differ only in
sections Exp. 2 does not read, nothing moves and the fix is a provenance check.
If `defaults` or `measurement` differ, `fig:exp2` compares schemes run under
different parameters.

**Options:**
- **A (would take)** — diff the four `global.yaml` revisions over the keys Exp. 2
  reads (`defaults`, `measurement`, `experiments.exp2_search_latency`) and report
  before deciding anything. Cheap, and it converts an unknown into a fact.
- **B** — re-run everything at HEAD's `global.yaml` regardless. Correct by
  construction, but pays for a full campaign to answer a question a diff answers.

Then add a plot-time check that every scheme in one figure carries the same
`global.yaml` hash, and name the mismatch instead of drawing it.

**Blocked:** the Exp. 2 re-run above should not be launched until this is
answered, or it will be launched against a config that has not been reconciled.

---

## 2026-09-07 — `5143ee7` collapsed round_robin into `no_lb`, and two stale tests

**RESOLVED: all three fixed. No banked number moves — the regression existed
only in code, since nothing has been re-run against `5143ee7` yet.**

The pull brought three failures. `test_phase6.py` and `test_psa_experiments.py`
were fully green at `a6cba3f` (71 passed, verified in a throwaway worktree), so
all three arrived with the commit.

**1. round_robin became no-load-balancing (a real regression, code fixed).**
`select()` used to advance the cursor ONCE PER REQUEST. `5143ee7` made it
`assign()` + `busiest()`, and `assign()` advances the cursor once per SHARD --
so whenever `|S_Q|` is a multiple of the pool size the cursor lands back on the
same offset every request, the first shard always goes to `pool[0]`, and
`busiest()`'s first-assigned tie-break returns that same node forever.
Measured: 8 consecutive `select()` calls over a 4-node, 4-shard federation
returned `FSN1` eight times.

`busiest()`'s own docstring warns about exactly this collapse ("silently
collapsing round-robin into no-load-balancing and erasing the arm Exp. 7-8
compare against") and says the tie-break is assignment order because that
"rotates with the cursor". It does not rotate, in precisely the case the
docstring names. Fixed by offsetting the rotation by a per-REQUEST counter as
well as the per-shard cursor: shards still rotate across the pool within a
request, and where that rotation starts now advances between requests. That
restores the pre-`5143ee7` request-level rotation while keeping per-shard
placement.

**2. `test_costs_are_the_four_published_terms` was stale (test fixed).** It
asserted `costs.sync == 0.0` commented "VID_U == VID_j" -- the previous
revision's scalar. `C_j^sync` is now a lag count over `V_Q` and the code
matches eq:search-cost. The fixture gives each FSN one of four domains and
`sync_nodes` only syncs domains a node serves, so against a four-domain `V_Q`
every node lags on three; `sync == 3.0` is correct. Now pinned both ways: 3.0
cross-domain, and 0.0 when `V_Q` is scoped to the node's own domain, which is
the per-shard case `eligible` actually presents.

**3. `test_exp1_tokens_are_distinct` was missed (test fixed).** Exp. 1 became
corpus-backed in `5143ee7`; every other test in that file was given the
`source` fixture, this one was not, and it raised `ValueError`.

---

## 2026-09-07 — corrected Exp. 2 does not fit the pinned host above N=10^5

**Found:** sizing Exp. 2's index in RECORDS (same day, above) multiplies it by
~32, and the top of the published sweep no longer fits `m6i.xlarge`'s 16 GiB.

Measured with `tracemalloc` over `Exp2SearchLatency.prepare` on the synthetic
source (|W_i| = 6): 7,689 / 6,959 / 6,797 bytes per record at N = 2,000 /
5,000 / 10,000 -- converging on ~6.8 KB/record. Scaled by the frozen corpus's
|W_i| = 31.70:

    N = 10^5      ~3.6 GB     fits
    N = 5*10^5   ~18.0 GB     does NOT fit
    N = 10^6     ~35.9 GB     does NOT fit

Rough -- a linear extrapolation of Python allocations, not an RSS reading -- but
the right order, and it agrees with guo hitting rc=137 at anon-rss 15.67 GB on
the same host. Note this is the pre-existing shape of the problem, not a new
one: guo already needs a larger-memory host for its own Exp. 2 and
`exp2_search.py` says §V must disclose it.

`assert_memory_for` is now called in `Exp2SearchLatency.prepare`, so a point
that cannot fit refuses with a clear message instead of arriving as SIGKILL.

**Costs:** the two top points of Exp. 2 for the proposed scheme. Without a
larger host the corrected sweep is measurable only to N = 10^5, and §VI claims
10^4 to 10^6.

**Options:**
- **A (would take)** — run the corrected Exp. 2 for the proposed scheme on the
  larger-memory instance guo's Exp. 2 already requires, and disclose the host in
  §V alongside guo's. One disclosure covers both.
- **B** — measure to 10^5 and extrapolate 5*10^5 and 10^6, as Scheme [41] does.
  Cheaper, but it makes the proposed scheme's own headline figure partly
  extrapolated, which is much harder to defend than doing it for a baseline.

**Blocked:** the Exp. 2 re-run. It should not be launched at 5*10^5 or 10^6 on
`m6i.xlarge`; the guard will now refuse it rather than burn the campaign.

---

## 2026-09-07 — `README.md` is empty, and five tests assert its contents

**Found:** `e503655` ("no more claude") deleted all 998 lines / 97,667 bytes of
`README.md`, alongside the `harvest-campaign-20260830/` tarballs. The file is
0 bytes at HEAD.

Five tests in `test_repetition_count_agreement.py` read README §7 for the
reportable `n_runs` requirement, the failure policy, the parameter table, the
reportability sentence and the `results.csv` example row. All five fail, and
have since before the `OJCOMS_expByexp` pull -- they are not a regression from
it. Beyond the tests, `CLAUDE.md` names `README.md` as the long-form
specification, and docstrings across the harness cite README §4, §5, §7, §13,
§14 and §15 as their authority. Those citations now point at nothing.

**Costs:** no measured number. It is the project's stated specification and the
provenance rules the reportability gate is written against.

**Options:**
- **A (would take)** — restore it (`git checkout e503655^ -- README.md`) if the
  deletion was collateral to clearing the harvest tarballs, which the commit
  message and the mixed diff suggest.
- **B** — if the deletion was deliberate, retarget the five tests to read
  `global.yaml` directly (they already have `_required_repetitions()` for
  exactly that) and strip the dangling README citations from the docstrings.

**Blocked:** nothing. But `CLAUDE.md` says README is edit-only-when-asked, so
this one is not mine to take either way.

---

## 2026-09-07 — `test_psa_exp6_arms_rank_the_way_the_manuscript_says` is flaky

**Found:** it compares wall-clock medians of the DIAS and Incremental-All arms
and asserts `dias <= everyone`. Observed failing once in five full-suite runs at
0.598 ms against 0.577 ms -- a 3.6% margin -- and passing three times out of
three when run alone. It is a timing comparison with no tolerance, on a dev
machine, between two arms whose separation at ratio 0.1 is genuinely small.

**Costs:** none measured. It is a false alarm that will fire at random and train
readers to re-run the suite rather than read it.

**Options:**
- **A (would take)** — keep the ranking assertion but give it a tolerance, or
  raise the affected ratio to where the arms actually separate, and say in the
  docstring which.
- **B** — leave it; it is right about the ordering and only noisy about the
  margin.

**Blocked:** nothing.

---

## 2026-09-07 — Exp. 3 measures a 40-record toy index against the baselines' 100,000

**Found:** `Exp3CrossDomain.prepare` (`experiments.py:897`) sizes the deployment
as `records=domain_count * 4` — **8 records at d=2, 40 at d=10**. The four
baselines each fix a TOTAL index and slice it:

    guo_vdsse/src/exp3_crossdomain.py:46          DEFAULT_N        = 100_000
    perera_lv_pqabse/.../runner.py:59             TOTAL_INDEX_SIZE = 100_000
    yue_ge/.../runner.py:79                       TOTAL_INDEX_SIZE = 100_000
    thingom_pq_abse/src/main.py:98                EXP3_TOTAL_INDEX_SIZE = 2_000

A **2,500x** gap at d=10. Same class as the Exp. 2 defect fixed today, worse by
two orders of magnitude.

It is not only a size gap, it is the opposite experiment. §VI says "The query
size and per-domain index size are fixed to isolate cross-domain search
overhead". Ours fixes PER-DOMAIN (at 4) so the total grows with d; all four
baselines fix the TOTAL so their per-domain size *shrinks* as d grows. Each
curve's shape is therefore an artifact of its own sizing rule:

* ours rises 2x (0.076 -> 0.153 ms) because the index grows with d
* guo is flat (53.79 -> 52.02 ms) and thingom is flat (154,708 -> 155,270 ms)
  because their total work is constant
* only perera (4.04 -> 11.79) and yue (62.8 -> 194.2, CI95 +/- 65 to 164) rise

So §VI's central Exp. 3 sentence -- "the baselines accumulate domain-local
search overhead because their search procedures are independently executed
across the participating domains" -- is contradicted by two of the four
baselines in the banked data.

**Three more, found in the same pass:**

* **`trapdoors_issued` is a hardcoded `1.0`** (`experiments.py`, Exp. 3
  `measure`), not counted from the token. It is the experiment's headline claim
  -- one trapdoor where a baseline issues d -- asserted rather than measured.
  `psa_exp3_crossdomain_tokens` measures its equivalent in a real column, which
  is why the plot spec can call that comparison "read from measured columns".
* **The queried keyword is invented.** `shared = "kw:00000"`, planted as one
  entry per domain, so the timed search traverses exactly one entry per domain
  over an otherwise inert index. `run_meta.json` still reports
  `corpus_type: synthea` and `reportable: true`. This is precisely the pattern
  `5143ee7` fixed for PSA Exp. 1 -- "reads the corpus for its policies and
  keyword vocabulary instead of inventing kw:00000 / hospital/pol0, so it can
  inherit corpus provenance rather than being stamped psa_in_process" -- and
  Exp. 3 was not included in that change.
* **`nodes_searched` saturates at 4.** `global.yaml` fixes
  `fog_search_nodes: 4` (published, §VI) while d sweeps to 10, so the secondary
  reads 2, 4, 4, 4, 4 and carries no information for d >= 6.
* **q=1**, as Exp. 2 had. Not a like-for-like fix here: Exp. 3 plants ONE shared
  keyword deliberately, so honouring `keywords_per_query: 5` means planting five
  and deciding whether they are conjunctive across domains.

**Costs:** all of `fig:exp3` and the §VI paragraph reading it. Sizing Exp. 3
like the baselines changes every proposed-scheme point; whether the "slower
growth" claim survives is exactly the open question, since our present rise is
a sizing artifact and two baselines' flatness is theirs.

**Options:**
- **A (would take)** — adopt the baselines' convention: fix the TOTAL index at
  100,000 and split it across d, then re-run Exp. 3 for the proposed scheme
  only (the baselines are already on that convention, so their banked data
  stands). Amend §VI's "per-domain index size [is] fixed" to say total, since
  four of five schemes already implement total and the sentence is what
  disagrees with them.
- **B** — hold per-domain fixed at a realistic size (say 10,000/domain) and
  re-run ALL FIVE schemes, making §VI's sentence true instead. Correct on the
  paper's own terms, but it pays for four baseline re-runs to keep one sentence.

Under either, `trapdoors_issued` must be counted rather than asserted, the
query must come from the corpus, and `nodes_searched` needs either a cap
disclosed in §VI or a different secondary.

**Blocked:** Exp. 3's re-run, and the §VI paragraph. Not Exp. 4-8.
