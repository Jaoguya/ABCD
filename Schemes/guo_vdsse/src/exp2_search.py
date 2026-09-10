"""Exp. 2 — Search Latency.

Variable:  index size ``N`` = 10^4 → 10^6 (log scale)
Primary:   latency (ms)
Secondary: entries traversed (n_eff), prune ratio

Measurement boundary (global.yaml, Exp. 2):
    Full online path: token generation → server inverted-index retrieval →
    forward-index filtering → client final eval → result assembly.
    Index construction is offline (not timed).

Defaults: q = 5 keywords, d = 4 domains.
"""

from __future__ import annotations

import gc

from pathlib import Path
from typing import Optional, Any, Dict, List

from Common.crypto import config as crypto_config
from Common.crypto.rng import DeterministicRNG
from Dataset.corpus import Record

from .harness import (
    RunResult,
    aggregate_results,
    measure_ns,
    run_experiment,
    write_raw_runs,
    write_results,
    write_run_meta,
)
from .scheme import GuoVDSSE

from infra import sweep


EXPERIMENT_NAME = "exp2"
SECONDARY_NAMES = ["n_eff", "entries_traversed", "prune_ratio",
                   "matched_records"]

# Index sizes — log scale from 10^4 to 10^6
# CAPPED at 2*10^5 on 2026-08-29 -- a hardware limit, disclosed, not a choice.
#
# Guo's forward index stores a t-punctured GGM key per document, sized
# O(|W_id| * log|X|). At the configured 64-bit domain and corpus v4's 31.7
# keywords/document that is 50.5 KB per document, measured:
#
#     N = 10^5  ->  5.2 GB      N = 5*10^5  ->  25.9 GB
#     N = 2*10^5 -> 10.3 GB     N = 10^6    ->  51.7 GB
#
# THE CAP IS LIFTED. This was [10_000, 20_000, 50_000, 100_000, 200_000],
# stopping at 2*10^5 because global.yaml pins a 16 GiB host and 51.7 GB does not
# fit in it. The answer is a bigger host, not a shorter sweep: guo now runs the
# same five points as every other scheme so the Exp. 2 figure has one shared
# x-axis instead of four schemes on four ranges.
#
# Note 20_000 and 200_000 are GONE. They were guo's alone -- in no other scheme
# and in no config -- so they contributed points no one could compare against.
# These five are exactly global.yaml's exp2_search_latency.values.
#
# MEMORY, measured byte-exact from the EDB dicts at real corpus density
# (51,675 B/record for Tf plus 1,773 for Ti; see the corrected note below):
#     N = 10^5 -> 5.0 GB    N = 5*10^5 -> 24.9 GB    N = 10^6 -> 49.8 GB
# Plus ~2 GB for the materialised corpus. So 10^6 needs ~52 GB and REQUIRES a
# host with real headroom above that -- it will OOM on the pinned m6i.xlarge
# exactly as the 2026-08-28 campaign did at 128-bit domain (rc=137, anon-rss
# 15.67 GB).
#
# Ref[35]'s own evaluation ran on 112 GB over a dataset averaging 3.85
# keywords/document; corpus v4 averages 31.70 and this index is linear in that.
# So the memory here is a property of OUR corpus density, not of the scheme
# being unfairly run.
#
# §V MUST STATE that guo's Exp. 2 ran on a larger-memory host than the other
# schemes, and why: 31.70 keywords/document against Ref[35]'s 3.85. It is a
# hardware disclosure, not a caveat about the result.
VARIABLE_RANGE = [10_000, 50_000, 100_000, 500_000, 1_000_000]

# Default query size (global.yaml: "each query contains five keywords")
DEFAULT_Q = 5


def _find_conjunctive_keywords(
    records: List[Record],
    rng: DeterministicRNG,
    q: int,
    attempts: int = 100,
) -> List[str]:
    """Select q keywords that have at least some matching documents.

    We pick keywords that actually appear in the corpus and try to find
    combinations where the least-frequent term has a reasonable number
    of matches, to avoid measuring empty-result queries.
    """
    from collections import Counter

    kw_counts: Counter[str] = Counter()
    for rec in records:
        kw_counts.update(rec.kw)

    # Exclude extremely frequent keywords (>50% of records) — they
    # dominate the scan and hide the scaling behaviour.
    eligible = [
        kw
        for kw, cnt in kw_counts.items()
        if cnt >= 10 and cnt <= len(records) * 0.5
    ]
    if len(eligible) < q:
        eligible = sorted(kw_counts.keys())
    eligible_set = set(eligible)

    # THE q KEYWORDS MUST CO-OCCUR IN A REAL DOCUMENT.
    #
    # This used to draw q keywords that were each INDIVIDUALLY frequent enough,
    # and never checked they appear together anywhere. Over a corpus averaging
    # 31.70 keywords/document, five independently-common keywords essentially
    # never all land in one document -- so the conjunction matched NOTHING, in
    # all 150 banked runs. Evidence: prune_ratio is
    # `len(result_ids) / single_count` (exp2_search.py:277) and is the string
    # "0.0" in 150/150 rows, one distinct value, while entries_traversed is
    # nonzero -- so single_count > 0 and the zero is a real empty result set,
    # not the divide-by-zero fallback.
    #
    # It corrupted the LATENCY, not just prune_ratio. scheme.py:513-518 breaks
    # out of the keyword loop on the FIRST miss, so every candidate was
    # rejected after ~1 punctured-PRF eval instead of the q-1 a real
    # conjunctive match costs. guo's Exp. 2 measured a search that
    # short-circuits immediately and returns nothing -- which UNDERSTATES guo.
    # guo is a baseline, so it understated a baseline and made the proposed
    # scheme's advantage look smaller. Conservative in our disfavour, which is
    # probably why it survived, and still not a valid measurement.
    #
    # Now: pick a document that carries at least q eligible keywords, and draw
    # the query from ITS keywords. The conjunction is then guaranteed to match
    # at least that document. The frequency bound still applies as a filter on
    # top, so the selectivity property the original was reaching for is kept.
    carriers = [rec for rec in records
                if len(eligible_set.intersection(rec.kw)) >= q]
    if carriers:
        for _ in range(attempts):
            doc = rng.choice(carriers, size=1, replace=False)[0]
            pool = sorted(eligible_set.intersection(doc.kw))
            selected = rng.choice(pool, size=q, replace=False)
            if len(selected) == q:
                return selected

    # No document carries q eligible keywords. Fall back to the old
    # independent draw rather than failing the run, but the caller's
    # prune_ratio will be 0 and the acceptance check will catch it -- which is
    # the point: this path must be visible, not silently equivalent.
    for _ in range(attempts):
        selected = rng.choice(eligible, size=min(q, len(eligible)),
                              replace=False)
        if len(selected) == q:
            return selected
    return rng.choice(eligible, size=min(q, len(eligible)), replace=False)


def run(
    scheme: GuoVDSSE,
    records: List[Record],
    manifest: Dict[str, Any],
    output_dir: Path,
    *,
    runs: int = 30,
    warmup: int = 5,
    seed: int = 20260804,
    points: Optional[str] = None,
) -> None:
    """Run Experiment 2: Search Latency vs. Index Size."""
    rng = DeterministicRNG(seed).spawn("exp2_search")

    # --points MUST filter the sweep, not just name the output directory.
    #
    # This was the ONE experiment in this scheme that ignored it: exp1, exp3,
    # exp4 and exp5 all call sweep.select, exp2 did not, and `points` reached
    # only sweep.shard_dir below. So `--points 50000` ran the WHOLE five-point
    # sweep -- including the 49.8 GB build at 10^6 -- and wrote it to a
    # directory named `__points-50000`.
    #
    # That is worse than slow. global.yaml's fleet block sets
    # granularity: sweep_point, so sharding Exp. 2 across instances would have
    # given every node the entire sweep, each ~12.4 h instead of its share, and
    # then merge_points.py would have concatenated five copies of the same full
    # sweep as though they were disjoint shards -- 5x the runs at every point,
    # a confidence interval computed over duplicated samples, and nothing
    # anywhere saying so. Caught 2026-08-30 when two "single-point" runs both
    # reported flushing N=10000 and sat at identical RSS.
    #
    # Selected BEFORE the corpus cap so an unknown point raises
    # SweepSelectionError naming the real sweep, rather than being silently
    # filtered out by a short corpus and reported as "does not sweep".
    selected = sweep.select(VARIABLE_RANGE, points)
    max_available = len(records)
    actual_range = [n for n in selected if n <= max_available]
    if not actual_range:
        actual_range = [max_available]

    # Pre-select keyword queries — SAME keywords across all N values
    # so the difference is attributable to index size alone.
    #
    # DRAWN EAGERLY, HERE, FROM A FIXED REFERENCE PREFIX -- not lazily from
    # whichever point this process happens to build first.
    #
    # It used to be drawn inside _ensure_built() on first call, guarded by
    # `if not query_sets`. In ONE process walking the whole sweep that gives
    # the smallest N and the invariant holds. Under --points it does not: each
    # shard builds exactly one point, so each drew its own queries from its own
    # prefix, and _find_conjunctive_keywords' eligibility bound
    # (`cnt <= len(records) * 0.5`) is computed over that prefix, so the
    # candidate pool moved with N too. Five shards, five different query sets.
    #
    # Proven, not suspected: records[:N] are NESTED, so a fixed query's n_eff
    # can only rise with N. Across the 2026-08-30 sharded run, 44 of 120
    # adjacent pairs FELL -- 37%. One run matched 1056 records at N=5x10^5 and
    # 216 at N=10^6, a corpus containing all of them. That is impossible for a
    # single query and it is what made the curve non-monotonic (877 ms at 10^6
    # against 1004 ms at 5x10^5).
    #
    # REFERENCE_N, not `actual_range[0]`: the reference must not depend on
    # which points this shard was asked to run, or two shards disagree again.
    # This is the pattern exp3_crossdomain.py:102-111 already uses correctly.
    reference_n = min(min(VARIABLE_RANGE), max_available)
    query_sets: List[List[str]] = []
    for _ in range(warmup + runs):
        query_sets.append(
            _find_conjunctive_keywords(records[:reference_n], rng, DEFAULT_Q)
        )

    # Build the EDB ONCE and GROW it through the sweep — not timed.
    #
    # Every sweep point is `records[:n]` — the points are nested prefixes, and
    # `run_experiment` walks them in ascending order. Rebuilding from scratch at
    # each point therefore re-inserted every record already indexed: the seven
    # points cost 1,880,000 inserts to produce a largest index of 1,000,000.
    # Growing one EDB costs exactly 1,000,000 — the same work the largest point
    # needs anyway, so six of the seven points become free.
    #
    # IDENTICAL, not merely similar. `update()` is called on the same records in
    # the same order either way (0..n-1 ascending), so after reaching n the EDB
    # is byte-for-byte what a fresh `records[:n]` build produces. This is a
    # harness change only: no scheme code, no call order, no parameter differs.
    # `test_exp2_incremental_build_matches_a_fresh_build` pins that.
    #
    # The saving is TIME, not peak memory. An earlier version of this comment
    # claimed "~9.5 GB at N = 10^6, measured", which is wrong by ~5.4x and would
    # have made the 2*10^5 cap below look unnecessary. Re-measured byte-exact
    # from the EDB's own dicts, on synthetic records whose per-document keyword
    # count is drawn to match dataset_manifest.json's real distribution
    # (mean 31.70): 51,675 bytes/record for Tf plus 1,773 for Ti, stable to
    # under 3% across N = 200..2000. That extrapolates to 10.7 GB at 2*10^5 and
    # 53.5 GB at 10^6, agreeing with line 50 above and with crypto.yaml's
    # independently derived 50.5 KB/document.
    #
    # It cannot be otherwise: index.py's EncryptedDatabase is plain dicts that
    # only ever insert. Nothing is evicted or compacted, so peak memory is the
    # largest index, whichever way it was built.
    #
    # What growing one EDB does avoid is the TRANSIENT: rebuilding per point
    # briefly held the old index and the new one at once during the handover.
    # That is a real gain at the margin and is why the previous
    # build-all-then-hold version could not complete, but it does not lower the
    # steady-state ceiling that sets the cap below.
    #
    # One deliberate consequence: a single `setup()` means one key set across
    # the whole sweep, where rebuilding drew fresh keys per point. That removes
    # a confound rather than adding one — search latency must not depend on
    # which keys were drawn, and now it demonstrably cannot.
    built_to = [0]
    state, edb = scheme.setup()

    # Bytes/record measured byte-exact from the EDB's own dicts at real corpus
    # density (b51d2cb): 51,675 for Tf plus 1,773 for Ti, stable to under 3%.
    # Not an RSS reading, which would also count the corpus and the allocator.
    _BYTES_PER_RECORD = 51_675 + 1_773
    _CORPUS_OVERHEAD = 2 * 2**30  # materialised corpus, roughly, on top

    def _ensure_built(n: int) -> None:
        if built_to[0] >= n:
            return
        # Refuse a point that cannot fit BEFORE spending an hour building it.
        # An OOM kill is SIGKILL: no traceback, no partial results, nothing in
        # the log. That is how the 2026-08-28 campaign died (rc=137, anon-rss
        # 15.67 GB) and the cause had to be reconstructed from instance metrics
        # afterwards. The index only ever grows -- nothing is evicted -- so the
        # projection for n is the steady-state ceiling, not a transient.
        crypto_config.assert_memory_for(
            n * _BYTES_PER_RECORD + _CORPUS_OVERHEAD, f"exp2 index at N={n:,}"
        )
        for rec in records[built_to[0]:n]:
            scheme.update(state, edb, "add", rec.rid, rec.kw)
        built_to[0] = n

    iteration_counter: Dict[int, int] = {n: 0 for n in actual_range}

    def runner(n: int) -> RunResult:
        _ensure_built(n)
        idx = iteration_counter[n]
        iteration_counter[n] += 1
        keywords = query_sets[idx % len(query_sets)]

        # `state` and `edb` are the single grown pair; at this point they hold
        # exactly records[:n].

        # Measure full search path — token gen through final result
        elapsed_ms, search_result = measure_ns(
            lambda: scheme.search(state, edb, keywords)
        )

        # Secondary metrics
        n_eff = (
            search_result.entries_traversed + search_result.forward_evals
        )
        single_count = search_result.single_keyword_result_count
        prune_ratio = (
            len(search_result.result_ids) / single_count
            if single_count > 0
            else 0.0
        )

        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "n_eff": n_eff,
                "entries_traversed": search_result.entries_traversed,
                "prune_ratio": round(prune_ratio, 6),
                # SVI Exp. 2 claims "query selectivity is kept constant",
                # and nothing in this repo recorded the quantity that claim is
                # about. `n_eff` means something DIFFERENT in every scheme --
                # matched entries here, traversal counters there -- so it could
                # not be used to check it. This is the match count, defined the
                # same way in all five schemes, so selectivity is finally
                # comparable across the shared axis of Fig. 2.
                "matched_records": len(search_result.result_ids),
            },
        )

    sweep_values = actual_range

    # Resolved BEFORE the sweep, not after, so the per-point flush below has
    # somewhere to write. The final write still happens at the end and is
    # authoritative; the flush only guarantees that an interruption leaves the
    # completed points on disk instead of losing them with the unfinished one.
    exp_dir = sweep.shard_dir(output_dir / "exp2_search_latency", points)

    def _flush(value: Any, done: List[RunResult]) -> None:
        """Persist every point completed so far. Called between points."""
        # Abort rather than measure the remaining points under parameters that
        # are no longer the ones the earlier points were measured under. The
        # config directory was emptied mid-session three times on 2026-08-30.
        crypto_config.assert_config_unchanged()
        write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, done,
                       SECONDARY_NAMES)
        write_results(exp_dir / "results.csv",
                      aggregate_results(done, SECONDARY_NAMES))
        # PARTIAL is the whole point of the marker: a reader that finds
        # raw_runs.csv without run_meta.json must be able to tell "still
        # running or died mid-sweep" from "finished". run_meta.json is written
        # ONLY on completion, so its absence is the incomplete signal, and this
        # file says how far it got.
        (exp_dir / "PARTIAL").write_text(
            f"in progress -- completed through variable_value={value}\n"
            f"{len(done)} retained runs so far\n"
            "run_meta.json is absent until the sweep finishes; if it is "
            "missing this directory is INCOMPLETE and not reportable.\n",
            encoding="utf-8",
        )
        print(f"  [flush] wrote partial results through N={value}", flush=True)

    results = run_experiment(
        sweep_values, runner, runs=runs, warmup=warmup,
        on_point_complete=_flush)

    # Write outputs
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    aggregated = aggregate_results(results, SECONDARY_NAMES)
    write_results(exp_dir / "results.csv", aggregated)
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
    # run_meta.json now exists, so the sweep is complete and the marker would
    # be a lie. Written last and cleared last, in that order: a crash between
    # the two leaves the marker standing, which errs toward "incomplete" --
    # the safe direction for a reportability check.
    (exp_dir / "PARTIAL").unlink(missing_ok=True)
