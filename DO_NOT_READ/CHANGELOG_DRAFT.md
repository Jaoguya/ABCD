# README §16 change-log — MERGED 2026-09-07

**All three rows below are now IN `README.md` §16.** This file is kept as the
working note that produced them; do not paste them again.

Two rows rather than one: they invalidate different things and a reader
tracking down a superseded number needs to know which.

---

## Row 1 — the defect that made a whole class of query unanswerable

| Date | Change |
|------|--------|
| 2026-09-06 | **A conjunctive query over more than one keyword could never match, for any data.** `index/dsi.py::lookup` intersected ORDINALS; an ordinal is one index entry and an entry carries exactly one token, so two distinct keywords never shared one and §V's `q`-keyword search returned the empty set by construction. Measured: one keyword on a record's own shard returns 8 hits, that record's own 5 keywords return 0 after traversing 26 entries. It survived because `test_dsi_conjunctive_query_requires_every_keyword` **asserted** it — `assert found == ()` under a docstring reading "§V's q-keyword conjunctive query" — and because `exp2_search_latency` rotates ONE keyword per run and so never took the path. Conjunctive now intersects CIDs and returns the entries that answered the query among records satisfying every token; at `q=1` the result is byte-identical, which is what leaves Exp. 2 untouched. A second layer sat on top for the policy-state-aware construction: its query is a disjunction ACROSS policies of a conjunction OVER keywords, and posing it as one flat conjunction asked a record to satisfy tokens bound to five different policies. **[results-affecting: exp7/exp8 all variants, and every psa_exp* that searches]** |

## Row 2 — the workload Exp. 7–8 actually used

| Date | Change |
|------|--------|
| 2026-09-06 | **Exp. 7–8 measured a one-keyword workload against a paper that says five.** `SchedulerAblation.prepare` built its trace from `[record.keywords[0]]`, uncommented, while README §6 and §V both fix `q=5`. Same class as the 2026-09-03 Exp. 2 defect: the number was real, the workload was not the published one. Both constructions now take `keywords[:q]`. Re-measured for all four variants on the pinned host; the ordering the paper rests on did not merely survive, it improved — AASS is first at every concurrency (1756 / 2938 / 3022 q/s at 100 / 2500 / 10000) and leads `no_lb` by 2.5x, where at `q=1` the field was tight and the order moved around below concurrency 1000. `least_loaded` still takes the lowest utilization spread, which follows from its rule; §V now says so. **[results-affecting: exp7_*/exp8_* superseded, both constructions]** |

---

## Optional third row, if you want the psa track in the log

| Date | Change |
|------|--------|
| 2026-09-07 | **The policy-state-aware track gained a corpus and a chain.** `psa_build_deployment` reads the same record source `build_deployment` reads, so both constructions index identical records; `psa_exp2` is the first psa result the reportability gate accepts. `psa_exp4` now anchors and verifies against the real Hyperledger Fabric network, putting it on a common axis with the cross-scheme Exp. 4 for the first time — within 2% at every `r` and below it at four of five points, so D3's richer commitment costs nothing measurable. PSA runs no longer inherit corpus provenance they never used: an experiment declares `CORPUS_BACKED`, and one that builds its own world stamps `corpus_type: psa_in_process` and is refused. Exps. 7–8 under this construction cannot discriminate schedulers — a request reaches one node and that node evaluates only the query groups whose domain it serves — so §V cites the cross-scheme results for both. **[not results-affecting for any Option D number]** |

---

## What these rows deliberately leave out

* The five defects in code written the same day (a Merkle leaf comparison, a
  short-circuit that made a tampered record cheaper under one construction than
  the other, a swallowed `NameError`, a metric named backwards, a wrong
  citation). None reached a banked number or a figure, so none belongs in a log
  of what invalidates results.
* Three superseded n=30 directories removed (FIX-4), and a flaky timing
  assertion replaced by a deterministic one. Housekeeping.
* `MANUSCRIPT_FIXES.txt`, which is §V's business rather than the benchmark's.
