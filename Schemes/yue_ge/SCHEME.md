# Ge et al. Peony / Peony++ — Scheme Experiment Guide (Ref[55])

**Back to main README:** [README.md](../../README.md)
**Paper:** Y. Ge, Y. Gao, J. Ning, J. Ma, and X. Chen, "Verifiable Multilevel Dynamic Searchable Encryption With Forward and Backward Privacy in Cloud-Assisted IoT," *IEEE Internet of Things Journal*, vol. 11, no. 24, pp. 40861–40874, 15 Dec. 2024, doi: `10.1109/JIOT.2024.3457270`. Construction summary, published parameters, and legitimacy assessment: [References/Ref[55]/Ref[55].md](../../References/Ref[55]/Ref[55].md).

**Status (2026-08-28): IMPLEMENTED.** `src/` holds the full construction; all five experiment runners execute end to end. 20/20 correctness tests pass, including negative tests for every claimed security property.

---

## Why this scheme, and what it adds

Two symmetric-key constructions from one paper:

- **Peony** (§V) — forward-private multilevel DSSE. The fast one.
- **Peony++** (§VI) — Peony + MSRE, giving forward **and Type-II backward** privacy plus **public verification**. The paper's flagship, and this benchmark's default.

It fills a genuinely thin slot. **Exp. 4 previously had only two participants** (`ma_lb_pq_vdse` and `guo_vdsse`). Peony++ has a real verification algorithm, and the paper benchmarks it *directly against Guo* — its "[37]" is this repo's Ref[35]. So Ref[55] is not a baseline fitted to Exp. 4 by analogy; it is the comparison the paper itself draws.

**It is not a post-quantum scheme and must not be cited as one.** Everything is HMAC-SHA-256 / AES / keccak256 / GGM-PRF. There is no pairing and no lattice. Cite it for verifiability and forward/backward privacy. (This also means the Ref[41] failure mode — a "post-quantum" title over DBDH pairings — is structurally absent here.)

---

## Experiments (5 of 8)

| # | Experiment | Notes |
|---|-----------|-------|
| 1 | Trapdoor Generation Latency | **Native mode**: single-keyword scheme, so a `q`-keyword query is `q` independent tokens. Includes owner-side `MSRE.KLRev` assistance. |
| 2 | Search Latency | Real index built at every swept `N`. Constrained-PRF derivation + linked-list traversal + `MSRE.Dec`. |
| 3 | Cross-Domain Search Scalability | **Native mode**: `d` independent tokens + `d` independent searches, client-side aggregation. No cross-domain notion exists in the paper. |
| 4 | Verification Overhead | Scheme-native `Verify` (§VI-A). **Peony++ only.** |
| 5 | Dynamic Keyword Update | Native incremental `Add` (new batch appended, nothing rewritten) + local `Delete`. |

Does **not** participate in Exp. 6, 7, 8.

- **Exp. 6 (Authorization Sync)** — excluded deliberately. Peony++ has access *levels*, but no authorization-synchronization or propagation mechanism: level keys are fixed at `KeyGen` and there is no re-keying, no version counter, and no notion of propagating an authorization change to nodes. README §5 already scopes Exp. 6 as an ablation of the proposed scheme's IAS with no baseline. Claiming Ref[55] here would mean calling MSRE revocation "authorization sync", which it is not — it revokes a *file's* decryptability, not a *user's* authorization.
- **Exp. 7–8** — proposed-scheme scheduler ablation. Not applicable.

---

## Per-experiment notes

### Exp. 1 — the curve should rise, and that is the finding

Peony/Peony++ are **single-keyword**: `Search(k_α(u), w, c; I)` takes one `w`, and the paper never defines a conjunctive form. Per README §3's native-mode rule (the same treatment `thingom_pq_abse` uses for Ref[41]), a `q`-keyword query runs as `q` independent tokens with client-side intersection. Latency is therefore linear in `q`, unlike a scheme with native conjunctive trapdoors.

The measurement includes the **data owner's assistance** (`MSRE.KLRev`), because §VI-A puts the owner in the token path and §IX lists removing it as future work. The paper's headline 0.95 µs is the *data user's* share alone; ours is larger because it covers the whole path that must run before a query can be issued.

### Exp. 2 — a real index at every N

For each `N` the runner builds a genuine index over `records[:N]` once (untimed), then measures a real search. Same methodology as `guo_vdsse`, `thingom_pq_abse`, and `ma_lb_pq_vdse`. Sweep points above the corpus size are **not reported** rather than padded.

### Exp. 4 — measurement boundary, and why it is not the SGX case

The paper runs `Verify` inside a Solidity contract on Ganache. The benchmark host runs no Ethereum node, and gas is not latency. What is measured is the **verification computation**: recombining the published per-batch digests, folding in the deletion digest, hashing the returned result set, comparing. That is ordinary CPU work that runs identically on- or off-chain; only the *transaction* is chain-bound.

This mirrors README §5's existing Exp. 4 boundary for the proposed scheme ("client-side verification only … IPFS fetch and decryption excluded"). It is explicitly **not** the Ref[36]/SGX situation that got that scheme dropped: there the *search algorithm itself* ran in an enclave, so simulating it would have omitted enclave-transition and EPC-paging cost. Full reasoning in [Ref[55].md §6](../../References/Ref[55]/Ref[55].md).

The paper's gas figures (Figs. 8–9) are recorded as reported values and never re-measured.

Exp. 4 is scoped to a **single update batch** — see the limitation below.

### Exp. 5 — genuinely incremental

`Add` appends a new batch `I_c = (A_c, T_c)`; existing batches are never rewritten. That is what gives the scheme forward privacy, and it satisfies README §5's "a global rebuild means Phase VII is implemented wrong". Deletion cost is carried as a secondary metric because it is orders of magnitude cheaper (local Bloom insert, no round-trip) and reporting only that half would misrepresent the scheme.

---

## A limitation of the published construction

**A batch containing no file at level `l` serves level-`l` users nothing from that batch — even files below them they are entitled to.**

Update line 5 masks each node with its *own* level key, while Search line 5 has the user derive only `F3_{k_α(u)}`. So the entry node must sit at exactly the user's level; `X_w` has no entry for an absent level, and `T_c` stores ⊥ (Update lines 12–13).

The paper never states the "every level populated per batch" assumption. At its own scale (2.2M files, 3 levels) it holds overwhelmingly and the case never arises.

**Implemented as published, not repaired.** AGENT_RULES forbids strengthening a baseline past its published construction, and silently fixing this would credit Peony with recall it does not have. Instead:

- the condition is **counted** (`UpdateBatch.sparse_levels`) so a run that hits it reports the fact;
- `test_sparse_level_batch_is_a_documented_limitation` pins the behaviour so it cannot drift;
- batching is **stratified by level** (`workload.py`) so the benchmark stays in the same non-degenerate regime the paper's own scale guarantees — this changes only which batch a record lands in, never what is indexed, searched, or returned;
- **Exp. 4 uses `c = 1`**, because with `c > 1` a sparse (keyword, level) gap makes `Verify` fail for a reason that is the construction's rather than the server's — which is not what Exp. 4 measures.

---

## Benchmark decisions (the paper does not fix these)

All recorded in `crypto.yaml` under `yue_ge`, all listed in [Ref[55].md §5](../../References/Ref[55]/Ref[55].md).

| Decision | Value | Why |
|---|---|---|
| `security_parameter_lambda` | 128 | Never fixed numerically by the paper. Matched to `guo_vdsse` so the two verifiable baselines are compared at equal security. |
| `update_batches_c` | 4 | Paper says only "`c` is relatively small". Search is `O(c)`, so this is **results-affecting**. Matched to the repo's default domain count `d = 4`. |
| `bloom_filter.num_hashes` | 5 | Paper publishes **both** `h = 5` and `h = 13` with no declared default. `h = 5` is the setting Aura is compared against first in every table; `--bloom-hashes 13` runs the other without editing config. |
| `deletions_between_searches` | 1000 | Paper sweeps `d ∈ {10, 100, 1000, 10000}` and fixes no default; 1000 is the point its own Table VII singles out. |
| `level_assignment` | `pid_hash` | The corpus carries no access level and the paper never says how it assigned one to Wikipedia. Derived deterministically from the pseudonymous patient id: reproducible, balanced across levels, and patient-stable (sensitivity attaches to a patient, not to one observation). |
| GGM tree depth | derived | `ceil(log2(b))`. §IV-B fixes the t-punc-PRF domain as the Bloom index space `[b]` itself, so a fixed wider domain would inflate the punctured key past the paper's own §VII-B communication figures. |
| Deletion seeding share | ≤ 10% of a keyword's postings | The paper inserts **1,000,000 files for one keyword** then deletes `d`; at `d = 1000` that is a 0.1% share. Our corpus has hundreds of postings per keyword, so a literal `d = 1000` would delete every posting and collapse `prune_ratio` to zero. **The Bloom array is still sized at the published `d`** — only the number of bits actually set is scaled. |

### `C_id` substitution

§VI-A's digests commit to `C_id`, "a file encrypted using the AES algorithm". This repo's corpus carries record identifiers and keyword sets, not document bodies, so `C_id` is the AES-GCM encryption of the identifier. Exp. 4 is scoped to verification computation only, so no measured quantity depends on plaintext length — but the substitution is recorded rather than left implicit.

---

## Folder Structure

```
yue_ge/
├── SCHEME.md                          # This file
├── src/                               # Implementation of the published construction
│   ├── params.py                      #        parameters from crypto.yaml; derived b
│   ├── levels.py                      # §V-A   multilevel access policy
│   ├── digest.py                      # §VI-A  keccak256 + XOR multiset accumulator
│   ├── msre.py                        # §IV    multilevel symmetric revocable encryption
│   ├── index.py                       # §V-D   server-side (A_c, T_c) per batch
│   ├── peony.py                       # §V     forward-private MLDSSE
│   ├── peony_plus.py                  # §VI    + backward privacy + verification
│   ├── workload.py                    #        corpus -> batched workload
│   ├── harness.py                     #        measurement loop, CSV, run_meta
│   ├── main.py                        #        CLI entry point
│   ├── dev_runner.py                  #        local validation, NOT reportable
│   └── test_scheme.py                 #        20 correctness tests
├── exp1_trapdoor_generation/runner.py
├── exp2_search_latency/runner.py
├── exp3_crossdomain_scalability/runner.py
├── exp4_verification_overhead/runner.py
└── exp5_keyword_update/runner.py
```

---

## Running

### Linux

```bash
python3 -m Schemes.yue_ge.src.main \
    --experiment 1,2,3,4,5 \
    --runs 30
```

### Windows (PowerShell)

```powershell
python -m Schemes.yue_ge.src.main `
    --experiment 1,2,3,4,5 `
    --runs 30
```

### Variants

```bash
# Forward-only Peony (§V) — the paper's own fast/secure comparison.
python3 -m Schemes.yue_ge.src.main --experiment 1,2,3,5 --variant peony

# The other published Bloom setting.
python3 -m Schemes.yue_ge.src.main --experiment 1,2 --bloom-hashes 13
```

`--variant peony` with Exp. 4 is refused: Peony has no verification algorithm, and measuring something else under that name would be a mischaracterization.

### Tests

```bash
python3 -m Schemes.yue_ge.src.test_scheme          # 20 correctness tests
python3 -m Schemes.yue_ge.src.dev_runner \
    --experiment 1,2,3,4,5 --runs 3 --max-records 300
```

`dev_runner.py` bypasses the corpus pin for local validation and writes to `_dev_output/`. Its results are **not reportable**.

---

## Output

| File | Contents |
|------|----------|
| `raw_runs.csv` | One row per individual run |
| `results.csv` | Aggregated means with 95% CI |
| `run_meta.json` | Provenance |

See main [README.md](../../README.md) §9 for column format.

---

## Open items needing a team decision

1. **README §3 and §5 do not list this scheme.** `README.md` is source-of-truth and is not edited by agents (AGENT_RULES). Adding Ref[55] to the baseline table (§3) and to the Schemes column of the experiment matrix (§5, Exps. 1–5, and notably Exp. 4's "Ours, Ref[35]") needs an author edit.
2. **Exp. 3 domain ceiling.** The corpus carries 4 real domains against a `d = 2..10` sweep — the same open item README §14 already records for every scheme, not specific to this one.
3. **`h = 5` vs `h = 13`.** Both are published. If the manuscript reports only one, the choice should be stated; `--bloom-hashes` makes running both cheap.
