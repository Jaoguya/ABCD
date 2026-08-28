"""Exp. 4 — Verification Overhead. Ref[55] §VI-A, ``Verify``.

Variable:  records verified ``r`` = 10 -> 1000 (README §5)
Primary:   verification latency (ms)
Secondary: proof size (KB), entries combined (path length)

WHY THIS SCHEME IS IN EXP. 4 AT ALL
-----------------------------------
Exp. 4 previously had only two participants (``ma_lb_pq_vdse`` and
``guo_vdsse``). Ref[55] is the natural third: Peony++ has a genuine public
verification algorithm, and the paper benchmarks it *directly against Guo* —
its "[37]" is this repo's Ref[35] (see ``References/Ref[55]/Ref[55].md`` §7).
So this is not a slot filled by analogy; it is the comparison the paper itself
draws.

MEASUREMENT BOUNDARY
--------------------
The paper runs ``Verify`` inside a Solidity contract on Ganache. The benchmark
host runs no Ethereum node, and gas is not latency. What is measured here is the
**verification computation**: recombining the published per-batch digests,
folding in the deletion digest, hashing the returned result set, and comparing.
That is ordinary CPU work which runs identically on- or off-chain; only the
*transaction* is chain-bound.

This mirrors how README §5 already scopes Exp. 4 for the proposed scheme —
"client-side verification only: Merkle proof, ``Commit_i*`` recomputation, chain
consistency. IPFS fetch and decryption excluded."

It is explicitly **not** the Ref[36]/SGX situation that got that scheme dropped:
there the *search algorithm itself* ran inside an enclave, so simulating it would
have omitted enclave-transition and EPC-paging costs and flattered the baseline.
Here nothing about the digest algebra changes off-chain. The reasoning is
recorded in ``References/Ref[55]/Ref[55].md`` §6 so a reader can disagree with it
knowingly. The paper's own gas figures (Figs. 8-9) are cited as reported values
and never re-measured.

WHAT THE CURVE SHOULD SHOW
--------------------------
Peony++'s proof is a single 32-byte digest regardless of ``r``, because the
combination is XOR-based multiset hashing. So proof SIZE is flat, while
verification LATENCY grows linearly in ``r`` — one ``H(1, C_id)`` per returned
record. That split is the interesting result against a Merkle-path scheme, whose
proof size grows as ``log r``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Any, Dict, Sequence

from Dataset.corpus import Record

from ..src import peony_plus
from ..src.digest import DIGEST_BYTES
from ..src.harness import (
    RunResult,
    aggregate_results,
    measure_ns,
    run_experiment,
    write_raw_runs,
    write_results,
    write_run_meta,
)
from ..src.params import SchemeParams
from ..src.workload import build_workload, index_workload

from infra import sweep

EXPERIMENT_NAME = "exp4"
SECONDARY_NAMES = ["proof_size_kb", "entries_combined", "accepted"]

VARIABLE_RANGE = [10, 25, 50, 100, 250, 500, 1000]


def run(
    params: SchemeParams,
    records: Sequence[Record],
    manifest: Dict[str, Any],
    output_dir: Path,
    *,
    runs: int = 30,
    warmup: int = 5,
    seed: int = 20260828,
    points: Optional[str] = None,
    variant: str = "peony_plus",
) -> None:
    if variant != "peony_plus":
        raise ValueError(
            "Exp. 4 requires peony_plus: Peony (§V) has no verification "
            "algorithm. Public verification is introduced by Peony++ (§VI-A)."
        )

    # Pick the most frequent real keyword — it bounds how large an r we can
    # reach with genuine matches.
    probe = build_workload(records, params)
    candidates = [kw for kw, n in probe.keyword_freq.most_common(50) if n >= 10]
    if not candidates:
        raise RuntimeError("corpus produced no keyword with >= 10 matches")
    keyword = candidates[0]
    matching = [rec for rec in records if keyword in rec.kw]

    actual_range = [r for r in VARIABLE_RANGE if r <= len(matching)]
    if not actual_range:
        actual_range = [len(matching)]
    if actual_range != VARIABLE_RANGE:
        print(
            f"  NOTE: most frequent keyword {keyword!r} matches "
            f"{len(matching)} records; sweep truncated to {actual_range} "
            f"rather than verifying a subset of a result set the digest does "
            f"not commit to."
        )

    # ---- one real deployment per r. Untimed. ----
    #
    # r must be the size of a GENUINE result set, not a slice of a larger one.
    # Peony++'s prooflist entry commits to every file added at that level in
    # that batch (§VI-A), so verifying a truncated subset is *supposed* to fail
    # — the XOR would not cancel. Building an index that actually contains r
    # matching records is the only way to sweep r without breaking the algebra.
    built: Dict[int, Any] = {}
    for r in actual_range:
        subset_records = matching[:r]

        # SINGLE BATCH for Exp. 4 — deliberate, and worth stating.
        #
        # Verification is only well-defined when the querying level can actually
        # reach every batch the prooflist commits to. Ref[55] stores bottom in
        # T_c for any level absent from a batch (peony.list_gen's "ON X_w"
        # note), so with c > 1 a keyword whose files miss level l in some batch
        # produces a prooflist entry covering files the search cannot return —
        # and Verify then fails for a reason that is the construction's, not the
        # server's. That is a real property of the scheme, pinned by
        # test_sparse_level_batch_is_a_documented_limitation, but it is not what
        # Exp. 4 is measuring.
        #
        # Exp. 4's variable is result-set size r, so it is scoped to c = 1,
        # where the question is well-posed. Batch-count effects belong to
        # Exp. 2, whose sweep uses the configured c from crypto.yaml.
        wl = build_workload(subset_records, params, batch_count=1)
        state, index, prooflist = peony_plus.setup(params)
        index_workload(state, index, prooflist, wl, variant)

        # Query at the highest level actually present among these records: that
        # level is guaranteed a non-bottom entry, and being the maximum it sees
        # every file, so the result set is the full r and the prooflist at that
        # level commits to exactly the same set.
        present = {wl.level_of[rec.rid] for rec in subset_records}
        query_level = max(present)

        tok = peony_plus.token_gen(state, keyword, query_level, wl.batch_count)
        result_ids = sorted(
            peony_plus.search(state, tok, index, keyword).result_ids
        )
        if len(result_ids) != r:
            raise RuntimeError(
                f"r={r}: search returned {len(result_ids)} ids, expected {r} — "
                "the index does not contain what the sweep claims"
            )
        built[r] = {
            "state": state,
            "prooflist": prooflist,
            "result_ids": result_ids,
            "batch_ids": state.keyword_batches.get(keyword, []),
            "level": query_level,
        }
        print(f"  built r={r:>5}: {len(result_ids)} verified records "
              f"at level {query_level}, 1 batch")

    def runner(r: int) -> RunResult:
        ctx = built[r]

        def do_verify():
            return peony_plus.verify(
                ctx["state"], ctx["prooflist"], keyword, ctx["level"],
                ctx["result_ids"], ctx["batch_ids"],
            )

        elapsed_ms, outcome = measure_ns(do_verify)

        # The proof the verifier consumes: the combined digest plus the
        # per-batch prooflist entries it XORs together. Constant in r — that is
        # the multiset-hashing property, and the point of the comparison.
        proof_bytes = DIGEST_BYTES * (1 + outcome.entries_combined)

        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "proof_size_kb": round(proof_bytes / 1024.0, 6),
                "entries_combined": outcome.entries_combined,
                # Recorded per run: a 0 here means the digest algebra broke,
                # and it must never be silently averaged away.
                "accepted": 1 if outcome.accepted else 0,
            },
        )

    sweep_values = sweep.select(actual_range, points)

    results = run_experiment(

        sweep_values, runner, runs=runs, warmup=warmup)

    rejected = [r for r in results if r.secondary_metrics.get("accepted") == 0]
    if rejected:
        raise RuntimeError(
            f"{len(rejected)}/{len(results)} verifications REJECTED an honest "
            "result set. Verify must accept what Search returned; this is a "
            "correctness failure, not a slow path. Refusing to write results."
        )

    exp_dir = sweep.shard_dir(output_dir / "exp4_verification_overhead", points)
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    write_results(exp_dir / "results.csv",
                  aggregate_results(results, SECONDARY_NAMES))
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
