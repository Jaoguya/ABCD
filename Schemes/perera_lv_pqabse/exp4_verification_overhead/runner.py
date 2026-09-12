"""Exp. 4 — Verification Overhead. Ref[54] arm.

Variable:  returned records ``r`` = 10 -> 1000
Primary:   client-side verification latency (ms)
Secondary: proof size (KB), Merkle path length

WHY THIS ARM EXISTS AT ALL
--------------------------
Ref[54] was excluded from Exp. 4 by DECIDE-1 (2026-09-03) -- "on time, not on
capability". The capability was never in doubt: Algorithm 3 ``RetrieveVerify``
performs ML-DSA-65 signature verification, a Merkle inclusion check, and a
freshness check against the latest on-chain root. Two blockers were recorded,
and both are now cleared:

1. ``retrieve_verify`` rebuilt the WHOLE partition tree per call
   (``MerkleTree(leaves)``) plus a linear ``leaves.index(...)`` scan -- O(N)
   for an operation Table II claims is O(log N). Measuring that would have
   reported Ref[54] far worse than its published construction, an accidental
   strawman. ``finalize()`` now retains the tree it already builds and
   ``verify_record`` proves against it: measured flat at 0.777 ms/call from
   N=500 to N=4000, with the path length growing 9 -> 12, i.e. log2(N).

2. This repo's Exp. 4 boundary is defined against ma_lb_pq_vdse's verification
   path: "verification is client-side: Merkle proof check, Commit_i*
   recomputation, and blockchain-consistency check. IPFS fetch and decryption
   are EXCLUDED." Algorithm 3 as published does verification AND hybrid key
   reconstruction in one call, so timing it whole would charge Ref[54] for an
   ABE decrypt, an ML-KEM decapsulation and an AES-GCM open that no other arm's
   number contains. ``scheme.verify_record`` is Algorithm 3's verification half
   alone, and is what this runner times. The decryption half is not deleted --
   ``retrieve_verify`` still performs both, and is what the scheme's own tests
   exercise.

MEASUREMENT BOUNDARY
--------------------
Timed: for each of ``r`` returned records, the edge signature check, the Merkle
inclusion proof and its verification against the partition root, and the
freshness comparison against the latest root.

Untimed: Phases 2-3 (edge encryption, fog ingest, index construction, and the
``finalize()`` Merkle build). skill.md puts index construction offline, and
every other Exp. 4 arm draws the line in the same place.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from Dataset.corpus import Record
from Common.timing import measure_ns_quiesced

from ..src import scheme
from ..src.harness import (
    RunResult,
    aggregate_results,
    measure_ns,
    run_experiment,
    write_raw_runs,
    write_results,
    write_run_meta,
)
from ..src.hybrid_index import HybridIndex
from ..src.params import SchemeParams
from ..src.workload import epoch_of

from infra import sweep

EXPERIMENT_NAME = "exp4"
SECONDARY_NAMES = ["proof_size_kb", "path_length"]

#: global.yaml's exp4 block -- the published "10 to 1000" range.
VARIABLE_RANGE = [10, 50, 100, 500, 1000]

#: Records ingested to build the index being verified against. Only needs to
#: put >= max(VARIABLE_RANGE) records into ONE temporal partition: verification
#: proves inclusion against a per-epoch root, so the returned set must come from
#: a single epoch or the proofs would be checked against different roots. Kept
#: small deliberately -- Phase 3 ingest is dominated by the ML-DSA-65 sign +
#: verify pair per record, and this experiment measures verification, not
#: ingest.
DEFAULT_N = 20_000

#: A Merkle proof node is one SHA3-256 digest.
_DIGEST_BYTES = 32


def run(
    params: SchemeParams,
    records: Sequence[Record],
    manifest: Dict[str, Any],
    output_dir: Path,
    *,
    runs: int = 10,
    warmup: int = 5,
    seed: int = 20260904,
    points: Optional[str] = None,
) -> None:
    """Run Experiment 4 for Ref[54]: client-side verification overhead."""
    keys = scheme.setup(params, with_abe=False)
    node = scheme.FogNode(
        keys=keys, index=HybridIndex(ngram_size=params.ngram_size)
    )

    # keep_ciphertext=True, unlike Exp. 1-3: verification reads
    # `node.ciphertexts[rid]` for the provenance digest and edge signature, so
    # the ciphertexts this arm verifies must actually be retained.
    subset = list(records[: min(DEFAULT_N, len(records))])
    for record in subset:
        ct = scheme.edge_encrypt(
            keys, record.rid, record.ts.encode("utf-8"), (),
        )
        node.ingest(
            ct, record.kw, epoch=epoch_of(record), category=record.dom,
            fuzzy_terms=record.kw[:1], keep_ciphertext=True,
        )
    root = node.finalize()

    # One epoch, because inclusion is proved against a PER-PARTITION root. A
    # result set spanning epochs would verify against different roots, which is
    # a different (and larger) operation than the one Exp. 4 defines.
    epochs = Counter(epoch_of(rec) for rec in subset)
    epoch, available = epochs.most_common(1)[0]
    verifiable = [rec.rid for rec in subset if epoch_of(rec) == epoch]

    actual_range = [r for r in VARIABLE_RANGE if r <= len(verifiable)]
    if not actual_range:
        raise RuntimeError(
            f"largest epoch partition {epoch!r} holds {len(verifiable)} "
            f"records, fewer than the smallest sweep point "
            f"{min(VARIABLE_RANGE)}; raise DEFAULT_N"
        )
    if actual_range != VARIABLE_RANGE:
        # The denominator travels with the result rather than being quietly
        # normalised away -- the same rule Exp. 9's arms follow.
        print(
            f"  NOTE: epoch {epoch!r} holds {len(verifiable)} records at "
            f"N={len(subset)}; sweep truncated to {actual_range}. Points above "
            f"the partition size are NOT reported (skill.md)."
        )

    print(f"  built N={len(subset):,}: epoch {epoch!r} carries {available:,} "
          f"records, global root {root.hex()[:12]}")

    def runner(r: int) -> RunResult:
        rids = verifiable[:r]
        outcomes: List[scheme.VerifyOutcome] = []

        def verify_batch() -> None:
            outcomes.clear()
            for rid in rids:
                outcomes.append(
                    scheme.verify_record(keys, node, rid, epoch, root)
                )

        # GC-quiesced: see Common/timing.py. Exp. 4 only, not measure_ns itself.
        elapsed_ms, _ = measure_ns_quiesced(verify_batch)

        # A rejected record here is a failure of the harness, not a result:
        # nothing is tampered in Exp. 4, so every proof must check out or the
        # latency being reported is the latency of something else.
        rejected = [i for i, o in enumerate(outcomes) if not o.accepted]
        if rejected:
            raise RuntimeError(
                f"r={r}: {len(rejected)} of {len(rids)} untampered records "
                f"failed verification; the index, the epoch or the root is "
                f"wrong and no number from this run means anything"
            )

        # Each record carries its own inclusion proof: r proofs, each one
        # path_length digests plus the leaf hash. This GROWS with r, unlike
        # Guo's two constant-size XOR tags -- a real difference between the
        # constructions, so it is reported rather than summarised away.
        proof_nodes = sum(len(o.proof.path) for o in outcomes)
        proof_bytes = (proof_nodes + len(outcomes)) * _DIGEST_BYTES
        path_length = proof_nodes / len(outcomes) if outcomes else 0.0

        return RunResult(
            primary_metric=elapsed_ms,
            secondary_metrics={
                "proof_size_kb": round(proof_bytes / 1024, 6),
                "path_length": round(path_length, 6),
            },
        )

    sweep_values = sweep.select(actual_range, points)
    results = run_experiment(sweep_values, runner, runs=runs, warmup=warmup)

    exp_dir = sweep.shard_dir(
        output_dir / "exp4_verification_overhead", points
    )
    write_raw_runs(exp_dir / "raw_runs.csv", EXPERIMENT_NAME, results,
                   SECONDARY_NAMES)
    write_results(exp_dir / "results.csv",
                  aggregate_results(results, SECONDARY_NAMES))
    write_run_meta(exp_dir / "run_meta.json", manifest, EXPERIMENT_NAME)
