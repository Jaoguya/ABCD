# System Configuration — everything about this experiment, from scratch

**Who this is for.** Someone who has never seen this project and needs to understand
what it measures, how it is set up, how to run it, and — most importantly — the
things that will quietly ruin a result if nobody tells you about them.

Read [§0 Flag points](#0-flag-points--read-this-before-you-touch-anything) first.
Everything else is reference.

**Related documents.** `README.md` was deleted on 2026-09-07; this file is now
both the specification and the *operator's guide* — what the experiments are, and
how the thing is actually configured and run. Its AWS and Fabric content was
rescued into §15 and §16 below before the deletion. `checkexp.md` tracks which
experiments have been audited and `needfix.md` what came out of it.
This file is the working agreement.
Git history is the record of every defect
found and what was done about it.

---

## 0. Flag points — read this before you touch anything

These are the things that are not obvious, that have already cost real time, and
that a newcomer cannot infer from the code.

**1. Nothing measured on a laptop counts.** Every reportable number must come from
one pinned AWS instance type (`m6i.xlarge`). This is checked at runtime against the
live EC2 metadata service, not asserted — `run_meta.json` records the host that
actually produced each number. A figure produced anywhere else would make the
paper's "all schemes on identical hardware" claim false.

**2. `run_meta.json` tells you whether a number is usable.** Every run writes one.
If `reportable: false`, the `not_reportable_because` list says exactly why. A run
still completes and still writes results — it is just not quotable. **Always read
this field before putting a number in the paper.**

**3. The corpus is frozen and pinned by hash.** `Dataset/derived/corpus.jsonl` is
git-ignored (it is hundreds of MB) but its SHA-256 is pinned in `dataset.yaml`.
Results from a different corpus are not comparable to each other. If you regenerate
the corpus, **every scheme must be re-run** — not just the one you were working on.

**4. `Dataset/dataset_manifest.json` is committed provenance. Do not overwrite it.**
`synthetic_generator.py`'s `--manifest` used to default to that path, so generating
a development corpus with only `--output` set would silently replace the campaign's
frozen pin with a 20,000-record dev manifest. It now refuses unless you pass
`--force`. If you ever see that file modified in `git status` and did not mean it,
`git checkout -- Dataset/dataset_manifest.json`.

**5. Index construction is untimed, but it is most of the wall-clock.** Every
experiment separates *setup* (build the encrypted index) from *measurement* (time
the search). Only the measurement is reported. But building a 10⁶-record index
takes hours, and that is where the campaign's time actually goes. A runtime
estimate that only counts measured operations will be wrong by an order of
magnitude.

**6. Two baselines cannot be developed on macOS.** `thingom_pq_abse` needs
`charm-crypto`, which is Linux-only, and there is no macOS wheel for the
`petrelic` fallback. Develop it on the Linux host. Everything else runs anywhere.

**7. One baseline claims something its own maths does not support.**
`thingom_pq_abse` (Ref[41]) describes itself as post-quantum while its construction
rests on DBDH, which Shor's algorithm breaks — and the same paper states elsewhere
that pairings are not post-quantum. It is implemented **exactly as published** and
the contradiction is reported as a finding. Do not "fix" it.

**8. Four of the five schemes needed parameters their papers never published.**
Those decisions are recorded in `Experiment Configuration/crypto.yaml` with a date
and a reason each. If a reviewer asks "where did n = 768 come from", the answer is
in that file, not in anyone's head.

**9. Exp. 4 understates its cost.** It runs against an in-process hash chain, not
the Hyperledger Fabric deployment the specification names. The run completes and
`run_meta.json` says so. The Fabric adapter is not written yet.

**Exp. 6 was gated alongside it until 2026-09-03 and should not have been.** Its
timed path never anchors: `sync/ias.py::synchronize` takes `ledger` as *optional*
and the Exp. 6 runner passes none, so Phase VII Step 7 is outside the boundary —
which is also where README §5 and `tab:cost`'s sync row put it. **Exp. 6 is
reportable without Fabric.** The general lesson is worth more than the fix: that
gate was justified by a *protocol step* rather than a *measurement boundary*, and
nobody checked the runner. When a gate blocks something, confirm its premise
against the code before accepting it.

**10. Never edit `README.md` casually.** It is the
specification's source of truth.

---

## 1. What this experiment actually is

The project evaluates a proposed **searchable encryption** scheme for
IoT-based electronic health records against four published baselines.

Searchable encryption lets a server hold encrypted records and answer keyword
queries over them **without ever decrypting**. The trade-offs are the interesting
part: how fast is a search, how much does verification cost, what happens when
someone's access is revoked, and does the security survive a quantum computer.

The proposed scheme is `ma_lb_pq_vdse` — **M**ulti-**A**uthority,
**L**oad-**B**alanced, **P**ost-**Q**uantum, **V**erifiable **D**ynamic
**S**earchable **E**ncryption. Its claims are that it (a) verifies results, (b)
propagates authorization changes incrementally rather than by rebuilding, and (c)
balances query load across fog nodes using an authorization-aware scheduler.

The benchmark exists to test those claims against real alternatives, on identical
hardware, over identical data.

---

## 2. The five schemes

| Folder | Ref | Paper | What it contributes |
|---|---|---|---|
| `ma_lb_pq_vdse` | ours | This work | The proposed framework |
| `guo_vdsse` | Ref[35] | Guo *et al.*, IEEE TDSC 2024 | Verifiable dynamic SSE |
| `thingom_pq_abse` | Ref[41] | Thingom *et al.*, IEEE TCE 2026 | Attribute-based SE |
| `perera_lv_pqabse` | Ref[54] | Perera & Fugkeaw, IEEE IoT-J 2026 | Lattice post-quantum ABSE |
| `yue_ge` | Ref[55] | Ge *et al.*, IEEE IoT-J 2024 | Verifiable multilevel DSSE |

**What each one rests on** — this is the axis that matters most:

- `guo_vdsse` and `yue_ge` are **symmetric only** (HMAC, AES, hashes). They make no
  post-quantum claim and need none: there is nothing for Shor's algorithm to break.
- `thingom_pq_abse` rests on a **Type-I pairing** under DBDH. See flag point 7.
- `perera_lv_pqabse` is **lattice-based end to end** (LWE + Kyber768 + Dilithium3).
  It is the only genuinely post-quantum baseline.
- `ma_lb_pq_vdse` (ours) is **partially** post-quantum: ML-KEM-768 covers session
  key establishment, but the pairing is still classical. Be precise about this in
  the paper — "post-quantum" unqualified would overstate it.

**Two schemes were dropped**, and the reasons matter:

- **Ref[36] (XB-Muse)** — runs part of its algorithm inside an Intel SGX enclave.
  The benchmark host has no SGX. Simulating it would omit enclave-transition
  overhead and make the baseline look *faster* than reality; moving it to an
  SGX-capable host would break hardware parity. Dropped, and §V must say the reason
  was hardware, not an unfavourable result.
- **Ref[52] (Zhuang)** — its Exp. 2 never built a real index; it encrypted one
  record and replayed the search N times to fake an N-record scan. Every other
  scheme builds a real index. Replaced by Ref[54].

There is also a **citation rule**: IEEE venues only. Ref[57] (an MDPI paper) was
added and removed the same day for this reason. See
`.claude/skills/reference-vetting`.

---

## 3. The eight experiments

Each varies exactly one thing and holds everything else at the defaults in §5.

| # | Measures | Variable | Range | Schemes |
|---|---|---|---|---|
| 1 | Trapdoor generation latency | keywords `q` | 1 → 20 | all 5 |
| 2 | Search latency | index size `N` | 10⁴ → 10⁶ | all 5 |
| 3 | Cross-domain scalability | domains `d` | 2 → 10 | all 5 |
| 4 | Verification overhead | results `r` | 10 → 1000 | ours, Ref[35], Ref[55] |
| 5 | Dynamic keyword update | pairs `k` | 10² → 10⁵ | ours, Ref[35], Ref[55] |
| 6 | Authorization sync | updates `δ` | 10² → 10⁵ | ours only |
| 7 | Search throughput | concurrency | 100 → 5000 | ours — ablation |
| 8 | Load balancing | concurrency | 100 → 5000 | ours — ablation |

**Measurement boundaries — what is inside the timer.** These decide what the
numbers *mean*, and getting one wrong silently produces a plausible, wrong figure.

- **Exp. 1** — online trapdoor generation only. ML-KEM encapsulation happens once
  per session, not per query, so it is **excluded** and reported separately.
- **Exp. 2** — the online search path only. Index construction is offline setup.
- **Exp. 3** — baselines have no native cross-domain search, so they run in
  "native mode": `d` independent trapdoors, `d` independent searches, aggregated on
  the client. Ours issues one trapdoor reused across domains. **Counting trapdoors
  issued is what makes that difference visible in the plot.**
- **Exp. 4** — client-side verification only. Fetching and decrypting the documents
  is excluded.
- **Exp. 5** — incremental update only. If a scheme rebuilds the whole index, that
  is a bug, not a slow update.
- **Exp. 6** — the incremental propagation path, until every affected node reports
  the new version. Blockchain anchoring (Phase VII Step 7) is **excluded** and
  reported separately, as ML-KEM encapsulation is for Exp. 1. Runs as a three-way
  ablation — `ias` / `broadcast` / `full_rebuild` — because `fsns_touched` alone is
  a constant 1 by construction and evidences nothing without `broadcast` to read it
  against.
- **Exp. 7–8** — the *same runs* produce both. Throughput alone can hide congestion:
  a scheduler can post good aggregate numbers while pinning one node at saturation,
  which is exactly what Exp. 8 exists to expose.

**One rule that governs Exp. 3 and Exp. 2 alike: the total amount of indexed data
is held constant while the swept variable changes.** This has been violated twice
and caught twice — once in `thingom_pq_abse`, once in `yue_ge` — and in both cases
the `d = 10` point indexed five times the data of `d = 2`, so the "scalability
curve" was mostly the growing corpus. If you add a scheme, check this first.

---

## 4. The dataset

**Synthea** — a synthetic but clinically realistic patient-record generator. Chosen
over MIMIC-IV because it has no size ceiling, needs no credentialing, is citable and
reproducible, and yields real keyword co-occurrence and real institutional domain
boundaries.

Frozen corpus **v4** (re-frozen 2026-08-28):

| | |
|---|---|
| Records | 1,143,792 |
| Keyword universe | 2,023 distinct |
| Keyword/document pairs | 36,263,865 |
| `\|W_i\|` min / median / mean | 5 / 29 / 31.70 |
| Zipf exponent | 2.741 |
| Domains | 10, at 114,379–114,380 each (0.001% imbalance) |
| SHA-256 | `e56ca2d1…f707d6a0` |

Two corpus types exist: `synthea` (reportable) and `synthetic` (from
`synthetic_generator.py` — a fitted Zipf law with no clinical structure,
**development only**). They have identical file formats; the manifest's
`corpus_type` is what distinguishes them, and the reportability gate refuses
anything that is not `synthea`.

> **A trap worth knowing.** The dev corpus has a very different *shape* from v4:
> ~13,000 keywords over ~11 pairs/record, versus v4's 2,023 over 31.70. Anything
> whose cost scales with the *keyword count* rather than the pair count will be
> badly mis-estimated if you extrapolate from a dev corpus. This produced a 6.5×
> memory over-estimate once already.

---

## 5. Defaults and environment

**Defaults** (`global.yaml`), held constant unless that experiment sweeps them:

```
keywords_per_query : 5        domains        : 4
fog_search_nodes   : 4        index_size     : 100,000
returned_results   : 100
```

**Environment** — pinned, and the pin is enforced:

```
instance_type : m6i.xlarge     vcpus  : 4      memory : 16 GiB
os            : ubuntu-22.04   python : 3.11   BLAS threads : 1
```

**Why BLAS threads are pinned to 1.** NumPy's BLAS claims every core by default,
which would make lattice latency depend on the host's core count and be
irreproducible even on identical hardware. It is read from `global.yaml`, not from
`nproc`, so the config is the single source of truth.

**Why the vCPU count is load-bearing.** `thingom_pq_abse` runs its search across
**2** processes, chosen because `m6i.xlarge`'s "4 vCPU" is 2 physical cores plus
hyperthreading — 4 processes measured *slower*. If you ever change the instance
type, that tuning has to be re-measured, and §V's disclosure updated.

**Measurement methodology**: 30 measured runs per point after 5 discarded warm-ups,
timed with `time.perf_counter_ns()`, reported as mean ± 95% CI from the
t-distribution. One experiment at a time per instance — no concurrent plotting or
preprocessing, because that contaminates latency.

---

## 6. What makes a number reportable

Every run writes `run_meta.json` with `reportable: true|false` and, when false, the
reasons. The conditions:

- Running on the pinned `m6i.xlarge`, verified against live EC2 metadata
- `corpus_type == "synthea"`
- Corpus SHA-256 matches `dataset.yaml`'s frozen pin
- A faithful cryptographic backend, not a development stand-in
  (a real Type-III pairing for ours; a real ML-KEM/ML-DSA backend for Ref[54])
- The ledger is the real Fabric deployment — **currently failing, but only for
  Exp. 4** (see flag point 9). Scoped to the experiments whose *measured path*
  touches the chain: it was a blanket blocker until `451df65`, then Exp. 4 + Exp. 6
  until 2026-09-03, and is now Exp. 4 alone.
- For ours: scheduler weights fixed (not `pending_sweep`), tokens scheme-keyed,
  fog nodes in independent processes

A run that fails these still executes and still writes results. That is deliberate:
seeing *why* a development run does not count matters as much as the runs that do.

---

## 7. How to run it

```bash
# 1. Provision a fresh instance (installs everything, gates on the primitive tests)
bash infra/provision.sh

# 2. Build the corpus (once — see §4; regenerating invalidates every result)
python3 Dataset/prepare_dataset.py --input <synthea>/output_full/csv \
    --output Dataset/derived --synthea-version 7e08387

# 3. Infrastructure — proposed scheme only
docker compose -f infra/fabric/docker-compose.yaml up -d
ipfs daemon &

# 4. Run the schemes
python3 -m Schemes.ma_lb_pq_vdse.src.main    --experiment all     --runs 10
python3 -m Schemes.guo_vdsse.src.main        --experiment 1,2,3,4,5 --runs 10
python3 -m Schemes.thingom_pq_abse.src.main  --experiment 1,2,3   --runs 10
python3 -m Schemes.perera_lv_pqabse.src.main --experiment all     --runs 10
python3 -m Schemes.yue_ge.src.main           --experiment 1,2,3,4,5 --runs 10

# 5. Figures
python3 Plots/generate_plots.py --input Schemes --output Plots/output
```

**Flags differ per scheme** — they were written at different times:

| Scheme | `--dataset` | `--points` | Output flag | Notable |
|---|---|---|---|---|
| `ma_lb_pq_vdse` | yes | yes | `--output` | `--smoke`, `--warmups` |
| `guo_vdsse` | **no** | yes | `--output-dir` | `--warmup` |
| `thingom_pq_abse` | yes | yes | `--output` | `--dev`, `--max-seconds-per-run` |
| `perera_lv_pqabse` | **no** | yes | `--output` | `--warmup` |
| `yue_ge` | **no** | yes | `--output-dir` | `--variant`, `--bloom-hashes` |

Schemes without `--dataset` read the corpus from its configured location.
`generate_plots.py` skips schemes with no results, so partial runs still plot.

**Development on a laptop.** Create the venv per `MacOS/SETUP.md`, then
`python -m pytest -q` should report ~651 passing. `thingom_pq_abse` will not run
(flag point 6).

---

## 7b. Restarting and updating the fleet

Use `infra/fleet.sh` rather than doing it by hand — the manual procedure has
already destroyed completed results.

```bash
./infra/fleet.sh status              # what is running, what is busy, burn rate
./infra/fleet.sh start               # start all, authorise your IP, wait for sshd
./infra/fleet.sh deploy              # archive results, update code, restore results
./infra/fleet.sh harvest ./out       # pull results, selected by provenance
./infra/fleet.sh stop                # stop all (STOP, not terminate)
```

`OJCOMS_BRANCH` picks the branch (default `main`); `OJCOMS_KEY` and `OJCOMS_SG`
override the key and security group.

**Why `deploy` is not just `git pull`.** Result files are **git-tracked**, so
`git reset --hard` restores the committed versions over fresh ones, silently.
That is how `guo_vdsse`'s completed Exp. 1, 2 and 4 were lost. `deploy`
archives `Schemes/` first, resets, then restores every result whose
`run_meta.json` says `corpus_type: synthea` — real results come back, stale
committed ones do not.

**Why `harvest` ignores timestamps.** A reset rewrites mtimes, so a stale file
can look newer than a real one. Selection is by `run_meta.json` provenance, never
by `find -newermt`.

**If every host times out at once**, it is almost certainly your egress IP
rotating, not dead nodes — it changed three times in one session. `start` and
`status` re-authorise the current address automatically; otherwise:

```bash
aws ec2 authorize-security-group-ingress --group-id sg-0dea7cf940668cddb \
  --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$(curl -s https://checkip.amazonaws.com)/32}]"
```

## 8. Running it in parallel

A campaign's wall-clock is bounded by its **largest indivisible unit of work**, not
by how many instances you own. Adding instances without splitting the work more
finely changes nothing.

Three granularities:

| Split by | Wall-clock | Notes |
|---|---|---|
| Scheme (one instance each) | ~25 h | bounded by `guo_vdsse`'s whole track |
| Experiment | ~21 h | bounded by `guo_vdsse` Exp. 2 |
| **Sweep point** (`--points`) | **~11 h** | bounded by guo's single N=10⁶ build |

`--points` selects which sweep values one process runs:

```bash
# two instances split Exp. 3's nine d-points between them
python3 -m Schemes.thingom_pq_abse.src.main --experiment 3 --points 2-5
python3 -m Schemes.thingom_pq_abse.src.main --experiment 3 --points 6-10

# then reassemble
python3 infra/merge_points.py Schemes/thingom_pq_abse/exp3_crossdomain_scalability
```

Each shard writes to its own `…__points-2_3_4_5` directory so instances cannot
overwrite each other. `merge_points.py` re-aggregates from `raw_runs.csv` (never by
averaging the shards' means — that is only valid at equal run counts, and a
confidence interval cannot be recovered from other confidence intervals), and it
**refuses** to merge shards that disagree on git commit, corpus hash, or config
hashes, or that contain the same sweep value twice.

A `--points` value the experiment does not sweep is an **error**, not a silent
no-op. A typo that quietly ran zero points would leave a hole in the campaign that
only surfaced when the figure was drawn.

**Not everything splits.** `guo_vdsse` and `perera_lv_pqabse` Exp. 2 grow *one*
index across the sweep — the points are nested prefixes (`records[:n]`), so
rebuilding per point costs 1.88× more — which makes them inherently sequential.
Sharding them is allowed but buys nothing.

---

## 9. Cost and runtime

| Track | Runtime | Index @ N=10⁶ |
|---|---|---|
| `guo_vdsse` | 25.0 h | 9.5 GB |
| `ma_lb_pq_vdse` | 17.8 h | 1.3 GB |
| `thingom_pq_abse` | 16.7 h | capped at N=10⁴ |
| `yue_ge` | 9.4 h | 11.2 GB |
| `perera_lv_pqabse` | 5.5 h | 0.6 GB |
| **Total compute** | **74.4 h** | |

At $0.19/hr for `m6i.xlarge` the whole campaign is **$14–36** of compute depending
on how promptly idle instances are terminated. **Cost is not the constraint here —
wall-clock is.** Note that the 240 GB of EBS attached to the stopped fleet bills
~$19/month regardless, which is more than the experiments themselves.

Peak memory per instance is roughly the largest index (11.2 GB) plus the
materialised corpus (~2 GB) plus the interpreter — about **13.7 GB against a
16 GiB host**. It fits, but with little headroom, and running near memory
saturation contaminates latency with GC and page-cache effects. Upgrading to a
32 GiB instance with the same 4 vCPU costs about $6 across the campaign and
removes that risk. Keep the vCPU count at 4 (see §5).

`.claude/skills/runtime-table` regenerates this table from
`Experiment Configuration/planning/runtime_estimates.csv`. Re-run it after
changing any measured code path — a stale row is worse than no row.

---

## 10. Decisions the papers did not make for us

Recorded in `crypto.yaml` with a date and a reason each. A reviewer asking "why
this value?" should be answered from that file.

| Scheme | Undetermined | Decided | Why |
|---|---|---|---|
| ours | AASS weights λ₁…λ₅ | (0.2, 0.4, 0.1, 0.2, 0.1) | 1,001-vector held-out sweep against independent-process nodes |
| `thingom_pq_abse` | attribute universe `u` | 10 | matched the then-current lattice baseline's published ℓ = 10 |
| `perera_lv_pqabse` | lattice `(n, q, σ)` | 768, 2²², 4.0 | Kyber768's security is module-LWE rank 3 over a degree-256 ring — effective dimension **768**. Taking 256 would name the right number for the wrong parameter |
| `perera_lv_pqabse` | attribute universe | 10 | matches `thingom_pq_abse`, so both ABSE schemes face the same policy size |
| `perera_lv_pqabse` | fuzzy `n`, `θ` | trigrams, 0.6 | paper names both and fixes neither |
| `yue_ge` | batch assignment | stratified round-robin within access level | keeps batches comparable in size *and* ensures every batch holds files at every level |
| `yue_ge` | access-level assignment | `pid_hash` | deterministic, uniform, and keeps one patient's records at one level |

**One decision is a measurement boundary rather than a parameter.**
`perera_lv_pqabse` sets `abe_on_measured_path: false`: Exp. 1 times PRF tokenisation
plus a signature, Exp. 2 times the fog index, Exp. 3 is `d` searches — **none of
them reads the lattice ciphertext**. Generating one per record costs a measured
758 ms (211 h at N=10⁶) and would change no reported number in either direction.
The full Phase 2 → Phase 5 path *including* that ciphertext is exercised by the
scheme's tests, which is what makes the omission honest rather than convenient.

---

## 11. What is not done

- **Fabric ledger adapter.** `infra/fabric/` brings the network up; nothing reads
  it. **Exp. 4** therefore understates chain cost, and every run says so. Exp. 6
  does not depend on it (flag point 9).
- **Exp. 6's ablation has never been run.** The `ias` / `broadcast` /
  `full_rebuild` variants landed 2026-09-03 and the existing
  `exp6_authorization_sync/` results are single-variant, so §5's "selective
  propagation is the claim" still has no measurement behind it. The 17 tests in
  `test_exp6_propagation_ablation.py` have also never executed — pytest is not
  installed on the dev host. Run `--experiment 6 --variant all` on a real host.
- **The campaign has not been run.** No `results.csv` in the repo is reportable yet.
- **`guo_vdsse`'s 25.0 h carries an unverified 1.5× derate** from a development
  host to the pinned instance. Confirm it on the real host before planning around it.
- **`perera_lv_pqabse` and `thingom_pq_abse` memory at N=10⁶** is estimated, not
  measured (both are small, so this is low risk).
- **Manuscript catch-up.** §V still names MIMIC-IV and `c6i.xlarge`; there is a
  duplicate `\bibitem{ref55}`; the Ref[41] cap and 2-process disclosure are not in
  the text yet.

---

## 12. Where things live

```
README.md                     specification — source of truth, do not edit casually
SystemConfiguration.md        this file — operator's guide

Common/crypto/                primitives every scheme shares, so all pay the same cost
                              hashes, PRF, AES-GCM, Merkle, Bloom, lattice, pairing,
                              ML-KEM, ML-DSA
Dataset/                      corpus generation + the committed manifest
                              derived/ is git-ignored
Experiment Configuration/     global.yaml, crypto.yaml, dataset.yaml, index.yaml,
                              scheduler.yaml, planning/runtime_estimates.csv
Schemes/<scheme>/             SCHEME.md + src/ + one folder per experiment
infra/                        provision.sh, fabric/, sweep.py, merge_points.py
Plots/                        generate_plots.py -> Plots/output/
References/                   the papers, and extracted text per reference
Overleaf/                     the manuscript
```

**`Common/` has a scope rule.** Primitives a paper *cites* (SHA-256, AES-GCM,
Merkle, Bloom, ML-KEM) live there so every scheme measures the same cost. Anything
a paper *contributes* stays in its own `src/`. If two schemes seem to need the same
construction, one of them is probably being implemented unfaithfully.

---

## 12b. The agent team

Three agents in `.claude/agents/`, split by what the work actually needs rather
than by convenience:

| Agent | Model | For |
|---|---|---|
| `bench-coder` | Opus | Writing and changing code — schemes, runners, harnesses, plots, infra |
| `bench-investigator` | Opus | Finding root cause — OOMs, crashes, wrong-looking numbers, cost surprises |
| `bench-hand` | **Sonnet** | Git, fleet start/stop/deploy/harvest, running tests, regenerating figures |

**Why the split.** The failures on this project were never syntax errors — they
were an estimate measured on the wrong data shape, a filter applied at the wrong
place, a `git reset` that ate results. That is judgement work, so coding and
diagnosis stay on Opus. The mechanical half — git, fleet ops, unpacking,
plotting — has known-correct recipes and runs on Sonnet, which is faster and
cheaper for exactly that.

Each carries the traps that have already cost this project time: `bench-coder`
knows results are git-tracked and that sweep filters belong at the range
definition; `bench-investigator` knows `ru_maxrss` is a high-water mark and that
the dev corpus has the wrong keyword density to extrapolate from; `bench-hand`
knows never to `git reset --hard` on a node and never to terminate an instance.

`bench-hand` is told to stop and escalate rather than improvise — a cheap model
guessing at an unfamiliar failure is how results get quietly destroyed.

Agent teams need `export CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`.

## 13. If you are about to change something

- **Changed a measured code path?** Re-derive its runtime rows and re-run
  `.claude/skills/runtime-table`. A stale estimate has already caused one campaign
  to be killed mid-run.
- **Adding a scheme?** Check the "total indexed data held constant" rule (§3), give
  it a `run_meta.json` with the same reportability conditions as everyone else (a
  baseline held to a weaker standard biases the comparison), and record every
  unpublished parameter you had to choose.
- **Optimising a baseline?** Implementation-level speedups are fine and sometimes
  necessary, but they must be disclosed, and if the proposed scheme gets an
  optimisation the baselines need it too or the comparison is confounded. An
  optimisation on the *measured* path needs a §V note; one on untimed setup does not.
- **Found a defect?** Say in the commit message: what changed, why, and what it
  means. That file is why the same bug has not been fixed twice.

## 14. Operational traps

Rescued 2026-09-07 from `infra/SESSION_HANDOFF.md` and `infra/CAMPAIGN_RESUME.md`
before both were deleted as stale. Everything else in those two files was a
snapshot of a campaign that has since been harvested, committed and superseded;
these six are not snapshots. Each one cost real time or real data once.

- **Never blanket-unpack a harvest tarball.** Each node's tarball carries stale
  copies of every *other* scheme's results. Unpacking several in alphabetical
  order silently overwrites fresh results with stale ones — and the overwrite
  leaves no trace, because the stale files are valid. Extract scoped, one scheme
  at a time, from the one node that produced it.
- **`run_meta.json` existing does NOT mean the point finished.** Restoring tracked
  files before a run recreates old `run_meta.json` files. Distinguish by
  `git_commit`, never by presence or mtime.
- **`python -u`, or the log is useless.** Without it a healthy run block-buffers
  stdout to a file and is indistinguishable from a hang. A 900 s "timeout" was
  once diagnosed off an empty log from a run that was fine.
- **Long runs go in `tmux` on the node.** Three separate incidents had the WORK
  survive an SSH drop while the RECORD of it died.
- **`pkill -f smoke.sh` does not kill `timeout`-wrapped children.** Orphans kept
  writing into a deleted output directory.
- **The egress IP rotates.** Every host times out at once and the fleet looks
  dead; it is the security group. Re-authorise and retry before diagnosing
  anything else.

One more, kept because it is load-bearing for reading git history: **a `-dirty`
suffix on a pre-`dfa7e69` `run_meta.json` is not evidence that code was
modified.** `git_commit()` ran `git status --porcelain` over the whole repo
including tracked result directories, so a run's own output tripped its own
marker. At the same commit `55aa3c8`, `exp7` and its five shards are clean while
`exp8`, its five shards, and `exp6` are dirty — same commit, same sweep, opposite
verdicts. That is write-order contamination. It equally cannot *rule out* a
modified tree; it simply carries no information either way.

---

## 15. AWS estate — hosts, AMIs, keys, recovery

Rescued from `README.md` on 2026-09-07 before that file was deleted. Every
concrete identifier below existed **only** there; none of it was in this file.
Verify against the live console before acting on any of it — instance state
moves, and the IDs are a record, not a guarantee.

### Instance type

`m6i.xlarge` (4 vCPU, 16 GiB, Xeon 8375C), Ubuntu 24.04 LTS, 30 GiB gp3.

Chosen over the originally specified `c6i.xlarge`: same CPU, 8 -> 16 GiB.
Ref[52] allocates a 381 MB lattice trapdoor per attribute, and running near
memory saturation contaminates latency with GC and page-cache effects.

* **Never `t3`/`t4g`** — CPU credits make latency non-reproducible.
* **Never Spot** — an interruption kills a trace.
* When launching from the console, plain Ubuntu no longer appears in Quick
  Start's abbreviated list (only the SQL Server bundle does). Use "Browse more
  AMIs". A previous host was accidentally launched as "Ubuntu Server 22.04 LTS
  **with SQL Server** 2022 Standard" and ran an unrelated `sqlservr` process.
* Launch **one** instance first, never all nine — `provision.sh` is a
  build-once-then-snapshot workflow, not nine independent provisions.

### AMIs

| AMI | Name | Status |
|-----|------|--------|
| `ami-0b2da6ed17be6c7a1` | `abcd-benchmark-2026-08-28b` | **Current — launch the fleet from this one** |
| `ami-0feb3b14b4ea27844` | `abcd-benchmark-2026-08-28` | Superseded, but see below — do not delete |

`ami-0b2da6ed17be6c7a1` carries corpus v4 (`e56ca2d1`, 10 domains), the Type-III
pairing backend, multi-process FSNs and the swept AASS weights. The older AMI
holds the superseded 4-domain corpus and fails the freeze check at startup.

**`ami-0feb3b14b4ea27844` is the single point of recovery for two things that
exist nowhere else:**

1. The frozen corpus `Dataset/derived/corpus.jsonl` (686 MB, git-ignored).
2. The from-source crypto build (PBC 0.5.14 + charm-crypto + liboqs).

It also carries ~11 GB of raw Synthea CSVs at `~/synthea/output_full/csv`. Keep
them: the corpus non-determinism came from Synthea *generating* patients across
threads, not from `prepare_dataset.py` extracting from fixed CSVs — so those
CSVs are what make the current corpus re-derivable.

### Keys and access

* Current key: `~/.ssh/ojcoms.pem` (host name `OJCOMS`).
* Retired key: `~/.ssh/ABCDE_key.pem` — old host `3.236.231.174`, terminated.
* **No Elastic IP.** The public IP changes on every stop/start and has already
  moved four times (`44.222.205.213` -> `98.91.21.219` -> `34.228.7.222` ->
  `54.172.21.174`). Never hardcode it; read the current one from the console.
* Each restart wipes `/tmp`, so long-running output belongs elsewhere.

### Instance IDs seen in the 2026-09-03 campaign

| Instance | Scheme | Last known outcome |
|----------|--------|--------------------|
| `i-0d9b2c6e1776c6f84` | proposed | complete, harvested, stopped |
| `i-0c376b61dae6fed24` | perera | complete, harvested, stopped |
| `i-0e5ae20e113bae9f7` | guo | Exp. 1-5 finished; **harvest was pending** |
| `i-025c809974bbf7511` | yue_ge | complete, harvested, stopped |
| `i-0b3030b5bd768536e` | thingom | complete, harvested, stopped |
| `i-007e491c10f5e7d62` | (experiment host `OJCOMS`) | build host |

### Recovering a node whose sshd will not answer

Observed on `i-0e5ae20e113bae9f7`: the box came back `running` with `ok/ok`
status checks and sshd never answered, on the same security group as nodes that
connect fine — so it was the host, not access.

```bash
aws ec2 stop-instances  --instance-ids <id>   # clean stop
aws ec2 start-instances --instance-ids <id>   # then retry ssh
# if sshd still refuses, take the console output before anything drastic:
aws ec2 get-console-output --instance-id <id> --output text | tail -50
scp -i ~/.ssh/ojcoms.pem "ubuntu@<ip>:results-<scheme>-*.bundle" /tmp/
```

**Stop, never terminate, a node holding unharvested results.** These volumes
carry `DeleteOnTermination: true` — a stop preserves every result, a terminate
destroys them.

### Getting results off a node

The nodes **cannot push**. The remote is `git@github.com:Jaoguya/ABCD` over SSH
and no node holds a private key; putting a personal key on a cloud instance was
deliberately not done. For real auto-push, add a per-node GitHub deploy key with
write access. Until then:

```bash
scp -i ~/.ssh/ojcoms.pem "ubuntu@<ip>:results-<scheme>-*.bundle" /tmp/
git fetch /tmp/results-<scheme>-*.bundle HEAD:refs/node/<scheme>
git checkout refs/node/<scheme> -- Schemes/<that-scheme-only>/
```

**That last line matters.** Each watchdog runs `git add -A Schemes/`, which is
too broad: perera's node commit also carried 39 stale `ma_lb_pq_vdse` files that
were dirty in its working tree, and merging that bundle would have overwritten
fresh proposed-scheme results with month-old data. Always check
`git diff --name-only <ref>~1 <ref>` and extract per-scheme paths rather than
merging. Narrowing that `git add` to the scheme the node actually ran is a
one-line fix worth making.

### Watchdog design

Each watchdog waits for the **driver** to exit, not a single python process. The
proposed scheme's run is two invocations (Exp. 1-6, then 7-8), so watching "is
the python alive" fires in the gap between them and stops the box with the
ablation unrun. On exit it commits results locally, writes
`~/results-<scheme>-<ts>.bundle`, attempts a push, then stops.

---

## 16. Fabric + IPFS on the experiment host

Rescued from `infra/fabric/README.md` on 2026-09-07 before that file was
deleted. Brings up the ledger and off-chain store §5 specifies (Hyperledger
Fabric v2.5, IPFS). Before 2026-08-28 this directory did not exist, so the
documented `docker compose` instruction was broken and every run silently fell
back to `chain/ledger.py`'s `InProcessLedger`.

```bash
docker compose -f infra/fabric/docker-compose.yaml up -d
docker compose -f infra/fabric/docker-compose.yaml ps
docker compose -f infra/fabric/docker-compose.yaml down -v   # -v also drops ledger state
```

### What this is, and what it is not

**Single organisation, solo orderer.** Not a production topology. What Exp. 4
and Exp. 6 measure is the cost of *anchoring a commitment and reading it back*
— ordering latency, block cut, endorsement round-trip — and this reproduces
those on one `m6i.xlarge` reproducibly.

**A solo orderer has no consensus round, so anchoring latency here is a LOWER
BOUND on a Raft deployment.** State that in §V rather than describing this as a
production network. It is the conservative direction for the proposed scheme —
it does not flatter our anchoring cost relative to a baseline that anchors less
often — but it is still a difference from the stated stack.

**TLS is disabled**, because a handshake would be measured as if it were
anchoring cost on a single-host private-VPC network. Never carry that setting
anywhere the traffic leaves the host.

**LevelDB, not CouchDB**: the scheme stores opaque commitments and issues no
rich queries, so CouchDB would add indexing cost the construction does not
incur.

### Before this clears the reportability blocker

`provenance.reportability()` blocks on `ledger_faithful` because an in-process
hash chain understates Exp. 4's chain-consistency cost. Bringing these
containers up is **necessary but not sufficient** — a `FabricLedger` adapter
implementing `chain/ledger.py`'s `Ledger` interface against this network still
has to exist and be passed `ledger_faithful=True`. That adapter is **not yet
written**; see `chain/ledger.py`'s note that a Fabric adapter "reading an entry
it did not write will need a canonical decoder".

So this directory makes the compose command executable and unblocks that work.
It does not by itself make Exp. 4 reportable, and no run should claim it does.

### Channel setup

`ORDERER_CHANNELPARTICIPATION_ENABLED=true` means the channel is created via the
admin API (osnadmin) rather than a genesis block baked into the image. The
adapter above should create the channel on first use so the network is
reproducible from the compose file alone, with no manual crypto material to
check in — checked-in MSP keys would be both a security problem and an
unreviewable binary blob.
