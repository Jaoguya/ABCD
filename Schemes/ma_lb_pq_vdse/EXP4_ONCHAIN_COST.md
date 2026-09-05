# Exp. 4 — the on-chain cost the figure had never shown

**Date:** 2026-09-04 · **Commit:** `d1cdf9c` · **Host:** m6i.xlarge, Fabric v2.5
· **Status:** measured, reportable, `tab:cost` and §V not yet updated

Two defects compounded to make Exp. 4 report a number that was neither what §V
describes nor comparable with the baselines it is plotted against. Both are now
fixed and re-measured. The corrected figure **moves the proposed scheme from
3rd of four to 4th by a wide margin**, and that is the honest position.

---

## 1. What was wrong

### 1.1 The ledger was a dict, not a blockchain

README §1 specifies Hyperledger Fabric v2.5 and README §5 puts *chain
consistency* inside Exp. 4's measurement boundary. The harness ran
`chain/ledger.py::InProcessLedger` — an in-memory hash chain — so the chain
check cost a hash-table lookup instead of a network round trip.
`provenance.reportability()` had refused to mark Exp. 4 reportable since
2026-08-28 for exactly this reason.

`infra/fabric/docker-compose.yaml` existed but **had never been run once**. Six
things blocked it, found in order:

| # | Defect |
|---|--------|
| 1 | Docker was not installed on the node at all |
| 2 | No MSP material was mounted — orderer and peer cannot boot without signcerts |
| 3 | `TLS off` is impossible: `CHANNELPARTICIPATION_ENABLED` makes a cluster-type node, and Fabric panics with *"TLS is required for running ordering nodes of cluster type"*. `OrdererType: solo` does not help — the requirement is on the node, not the channel |
| 4 | Peer TLS had to match the orderer or the peer cannot fetch blocks; every lifecycle transaction died with *"timed out waiting for txid on all peers"* |
| 5 | No chaincode, channel config or crypto config existed |
| 6 | `Endorser.ProcessProposal` endorses but does **not** write; the first adapter committed nothing and every run failed 10/10 with `NotFoundError` |

### 1.2 `r` counted index entries, not returned records

This is the more serious of the two, because it silently biased a comparison.

§V says *"the number of returned encrypted **records** r increases from 10 to
1000"* and the figure caption reads *"Returned search results"*.
`Exp4Verification.prepare` did neither. It sized the deployment as
`ceil(r / keywords_per_record)` and then took `r` **bundles** from it. With the
frozen corpus's `|W_i| ≈ 32`:

| x-axis `r` | records actually verified |
|---|---|
| 10 | **1** |
| 1000 | **32** |

Measured, not inferred: a counter around `FabricLedger._call` showed **2 Fabric
round trips per record** (`lookup_anchor` does `keys()` + `get()`), and one
Exp. 4 measurement made 2 calls at r=10 and 56 at r=1000 — tracking the record
count, not `r`.

**Every baseline sweeps `r` as records.** `perera` slices `verifiable[:r]`,
`yue_ge` returns `r` result ids, `guo` picks a keyword matching ~`r` documents.
So at x=1000, Scheme [54] verified 1000 signatures while the proposed scheme
checked 32 commitments and 32 anchors. Points on a shared axis were not
measuring the same quantity, and **the asymmetry ran in our favour**.

---

## 2. What changed

* `chain/fabric_ledger.py` — `Ledger` implemented against Fabric v2.5, talking
  to `Endorser.ProcessProposal` directly (no usable Python SDK exists for 2.5).
* `chain/select.py` — `ABCD_LEDGER` picks the backend, and `ledger_faithful` in
  `run_meta.json` now reads from that same switch instead of its `False`
  default. Nothing had ever passed it.
* `infra/fabric/` — crypto config, channel config, chaincode, `network.sh`.
* `harness/experiments.py` — `r` records now produce `r` bundles, one per
  returned ciphertext. Pinned by two tests.

---

## 3. Measured result

> **Superseded 2026-09-04 by `7994188`.** Everything in this section is the
> per-record-fetch measurement at `d1cdf9c`. The numbers below are still what
> that code did; §3.1 has what the code does now. The *conclusions* — O(r) in
> on-chain reads, 4th of four, `tab:cost` owes an `O(r)T_BC` term — all survive.


`ABCD_LEDGER=fabric`, 10 runs + 5 warm-ups, m6i.xlarge, commit `d1cdf9c`,
`reportable: true` with an empty blocker list — **the first reportable Exp. 4
this project has produced**.

| r | Proposed | [54] | [30] | [35] |
|---|---|---|---|---|
| 10 | **35.59 ms** | 2.20 | 0.14 | 0.07 |
| 50 | **181.17 ms** | 10.99 | 0.27 | 0.27 |
| 100 | **354.01 ms** | 21.98 | 0.94 | 0.55 |
| 500 | **1781.67 ms** | 110.34 | 4.52 | 2.71 |
| 1000 | **3578.13 ms** | 220.66 | 9.03 | 5.42 |

Now **slowest of the four**: 16× Scheme [54], 660× Scheme [35].

### The cost is exactly linear in `r`

| r | ms per record |
|---|---|
| 10 | 3.559 |
| 100 | 3.540 |
| 1000 | 3.578 |

Flat at **~3.57 ms/record** across two orders of magnitude. That is 2 on-chain
reads at ~1.67 ms plus the crypto, and it means **verification is O(r) in
blockchain round trips**, which dominates everything else in the row.

For scale, the same sweep against the in-process ledger is 15.04 ms at r=1000.
The chain is ~99% of the corrected cost. (At `7994188` it is 1632.63 ms against
the same 15.04 ms, so the chain is still ~99%.)

---

## 3.1 Re-measured after the batched fetch (`7994188`)

`e252cc9` replaced the per-record anchor fetch with `batched_chain_checker`,
which resolves every anchor in ONE namespace pass. Re-run on the same host
against the same live Fabric network, 10 runs + 5 warm-ups, `reportable: true`,
empty blocker list:

| r | `d1cdf9c` | `7994188` | gain | ms/record | [54] | vs [54] |
|---|---|---|---|---|---|---|
| 10 | 35.59 | **18.19 ms** | 1.96x | 1.819 | 2.20 | 8.3x |
| 50 | 181.17 | **85.32 ms** | 2.12x | 1.706 | 10.99 | 7.8x |
| 100 | 354.01 | **163.54 ms** | 2.16x | 1.635 | 21.98 | 7.4x |
| 500 | 1781.67 | **816.06 ms** | 2.18x | 1.632 | 110.34 | 7.4x |
| 1000 | 3578.13 | **1632.63 ms** | 2.19x | 1.633 | 220.66 | 7.4x |

**2.19x, not the 3.7x the dev host predicted.** That gap is the finding, not a
disappointment: the dev-host figure in `e252cc9` was measured against
`InProcessLedger`, where a namespace walk and a `get()` cost the same
microseconds. On real Fabric they do not.

**The cost is still exactly linear in `r`** — 1.633 ms/record at r=100, 500 and
1000, flat across an order of magnitude. `lookup_anchor` was `keys()` + `get()`,
**two** Fabric round trips per record. Batching removed the `keys()` walk and
left the `get()`, so verifying r records still costs r on-chain reads. Halving
the round trips halved the latency, and that is all it did:

| | on-chain reads per record | r=1000 |
|---|---|---|
| `d1cdf9c` | 2 (`keys()` + `get()`) | 3578.13 ms |
| `7994188` | **1** (`get()`) | **1632.63 ms** |
| one root over all records (§4, not scheduled) | **O(1) total** | not measured |

So **`e252cc9` removed the O(r^2) term but not the O(r) one.** Section 4 below
is unchanged and is still the only thing that reaches O(1).

**Ranking is unchanged: 4th of four, by 7.4x over Scheme [54].** Every
manuscript edit in §5 stands exactly as written — `tab:cost` still owes
`O(r)T_BC`, because the term is still there.

Data quality: 10/10 runs `ok` at every point, mean/median 1.00-1.02, worst
max/median 1.13.

---

## 3.2 Reproducibility: the same code, re-run, is 2-5% slower

Exp. 4 was re-run on 2026-09-05 at `4ebbcb6` to check §3.1. `Exp4Verification`
is untouched between the two commits -- `d558d63` and `4ebbcb6` edit only
`Exp9VerificationGranularity` -- so this measures IDENTICAL code on the same
instance, and any difference is environmental.

| r | `7994188` | `4ebbcb6` | delta | within the two CIs? |
|---|---|---|---|---|
| 10 | 18.186 ±0.222 | 18.722 ±0.137 | +2.9% | **no** |
| 50 | 85.320 ±2.621 | 87.134 ±1.111 | +2.1% | yes |
| 100 | 163.538 ±0.598 | 171.793 ±1.410 | +5.0% | **no** |
| 500 | 816.055 ±5.546 | 843.164 ±2.297 | +3.3% | **no** |
| 1000 | 1632.627 ±11.062 | 1675.341 ±9.564 | +2.6% | **no** |

**The offset is systematic, not noise: every point moved the same direction.**
At r=1000 the two runs differ by 42.7 ms while their intervals are ±11.1 and
±9.6, so they do not overlap.

**What this means for the error bars.** Within-run spread at r=1000 is ~0.7% of
the mean; between-run spread is ~2.6%. The published ±95% CI therefore describes
repetition noise INSIDE one process against one Fabric deployment. It does not
describe what a reader would get re-running the experiment, which is the thing a
reproducibility claim is about. Both runs are individually clean -- 10/10 `ok`,
mean/median 1.000-1.005, worst max/median 1.05.

**Most likely cause, NOT verified:** the network is torn down and rebuilt
between runs (`network.sh down` then `up` regenerates crypto material, restarts
the containers and starts LevelDB cold), so the second run met a different,
freshly-built ledger. That is real deployment variance rather than measurement
error, but it has not been isolated -- doing so needs several runs against ONE
bring-up, compared against several across separate bring-ups.

**Nothing downstream moves.** Still 4th of four, still ~7.4x Scheme [54]
(1675.3 against 220.7), still linear at ~1.68 ms/record, chain still ~99%. Every
manuscript edit in section 5 stands.

---

## 4. Why it is O(r), and whether it has to be

`commit_record(entries=…)` builds `Root_i` over **one record's** index entries,
and `anchor_key(cid, vid)` anchors **one record**. There is no tree spanning
records, so verifying `r` records needs `r` separate anchors.

A Merkle tree exists to prove many memberships against **one** root. Building it
per record gives that up:

| design | on-chain reads | hashing |
|---|---|---|
| current (root per record) | **O(r)** | O(r log w) |
| one root over all records | **O(1)** | O(r log n) |

**§V's stated benefit does not require per-record anchoring.** It argues that
*"a tampered result can be rejected individually without invalidating otherwise
valid results"* — but a Merkle path already gives per-record rejection. The
per-record anchor buys nothing that §V claims, and costs the dominant term.

Changing this is a **construction change, not a measurement fix**: it touches
Phase IV/V/VII, invalidates the `tab:cost` rows for Keyword Update and
Authorization Synchronization as well as Verification, and needs Exp. 4, 5, 6
and 9 re-run. Estimated 2–3 days plus manuscript work. Recorded here as the
strongest available improvement, not scheduled.

---

## 5. What the manuscript now needs

Reported as file + line; not edited by the assistant.

| Where | Says | Should say |
|---|---|---|
| `tab:cost` notation, ~1807 | — | add `$T_{\rm BC}$ & One blockchain state read (on-chain query) \\` |
| `tab:cost` Verification, 1918–1921 | `$O(r)T_{\rm MT}$ + $O(r)T_H$` | `… + $O(r)T_{\rm BC}$` |
| Summary prose, 1954–1955 | `$O(r)T_{\mathrm{MT}}+O(r)T_{H}$` | `… + $O(r)T_{\mathrm{BC}}$` |
| §V Exp. 4, 2186–2191 | *"dominant verification cost … grows with the number of returned results"* | name the dominant term: the on-chain lookup, ~99% of measured latency |

The proposed scheme is the only row that would carry an on-chain term. That is
correct — it is the only scheme whose verification consults a ledger.

§V's Exp. 4 narrative also needs rework beyond the table. *"The proposed
framework does not achieve the lowest verification latency"* is a considerable
understatement at 16× the nearest comparator.

One thing the correction **helps**: §V explains the higher latency partly by
*"blockchain-consistency checking"*. That was not an honest claim when the check
was a dict lookup. It is now the true explanation.

---

## 6. Disclosures the network forces

* **Single-consenter Raft.** One consenter runs the Raft path but reaches quorum
  with itself, so anchoring here is a **lower bound** on a multi-orderer
  deployment.
* **TLS is on.** The compose file's original *"TLS off, so the handshake is not
  measured as anchoring cost"* describes something Fabric refuses to do. It is
  off Exp. 4's timed path regardless: one persistent gRPC connection, so the
  handshake happens once at connect.
* **`BatchTimeout` is Fabric's default 1 s**, untuned deliberately. It governs
  setup only — Exp. 4 reads, it does not anchor.

---

## 7. Still open

* **`Record` has `encode()` but no `decode()`**, so a typed record cannot be
  rebuilt from bytes another process wrote — the gap `chain/ledger.py:105`
  names. `FabricLedger` caches what it wrote so a deployment can read back its
  own anchors; the round trip still happens and is still timed. **Cross-process
  `verify_chain()` remains unimplemented.** Exp. 4 does not reach it
  (`check_chain_integrity=False`).
* **`fleet.sh harvest` returns 0 directories** even when `OJCOMS_COMMIT` matches
  the commit in `run_meta.json` exactly. Results were copied with `scp`
  instead. A harvest that silently returns nothing is how banked data gets
  missed; this should be fixed before the next campaign.
* **`network.sh up` is not idempotent** — it regenerates crypto while old
  containers hold the previous certs, which breaks TLS trust. Run `down` first.
