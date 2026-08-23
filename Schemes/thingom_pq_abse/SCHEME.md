# Thingom PQ-ABSE — Scheme Experiment Guide (Ref[41])

**Back to main README:** [README.md](../../README.md)
**Paper:** Thingom *et al.*, "Secure and Privacy-Preserving Post-Quantum Attribute-Based Searchable Encryption for Edge-Driven Transportation Systems", IEEE TCE, doi `10.1109/TCE.2025.3632071`. Extracted text: [References/Ref[41]/Ref[41].md](../../References/Ref[41]/Ref[41].md).

---

## Experiments (3 of 8)

| # | Experiment | Notes |
|---|-----------|-------|
| 1 | Trapdoor Generation Latency | **Native mode**: `q` independent trapdoors — the construction is single-keyword |
| 2 | Search Latency | Linear scan, `2u+1` pairings per entry. Not reachable at `N = 10⁶` — see Feasibility |
| 3 | Cross-Domain Search Scalability | **Native mode**: `d` independent trapdoors + `d` independent searches, client-side aggregation |

### Per-Experiment Notes

- **Exp. 1** — Online trapdoor generation only. Ref[41] uses no KEM, so nothing is excluded on that account. Secondary metrics: trapdoor size (bytes) and trapdoors issued.
- **Exp. 2** — Full online search path. Ref[41] has no authorization filter and no early termination, so `entries_traversed` equals `N` by construction. Index construction is offline and untimed (README §5).
- **Exp. 3** — Does not natively support cross-domain search. Runs `d` independent trapdoors and `d` independent searches, with client-side result aggregation.
- Does **not** participate in Exp. 4, 5, 6, 7, 8.

---

## Construction

Single-authority CP-ABSE over a **Type-I (symmetric) pairing**, secure under DBDH. Five phases: setup, key generation, encryption (offline/online), search, decryption.

The search relation was verified symbolically before implementation — the `O₂` terms cancel between the two pairings, leaving `e(i,i)^{γξηs}` by LSSS reconstruction, which matches `e(CS'_w, L₂)/CS_w`. Derivation is in the [`scheme.py`](src/scheme.py) module docstring.

**The paper self-refutes on post-quantum security.** `:83` asserts DBDH "forms the foundation of the post-quantum security claims in this work"; `:362` of the same paper states pairing-based cryptography "is not thought to be feasible in a post-quantum setting". Reproduced as published per README §13, reported as an observation.

**README §3 calls this "Multi-authority ABSE" — it is not.** A single TCC holds `MSCK = {γ, ξ}` and issues every attribute key. Worth resolving if it is serving as the multi-authority comparator.

---

## Decisions fixed for this baseline

Both are recorded in `crypto.yaml` so they are covered by the config hash in every `run_meta.json`, and both are logged in [debug_history.md](../../debug_history.md).

| Decision | Value | Why |
|---|---|---|
| Multi-keyword mode | `independent_trapdoors` | The trapdoor carries exactly one `O₃(w_w)` (`:328`) and search tests one keyword (`:344`). No conjunctive form exists in the paper. |
| Attribute count `u` | `10` | Not published for this evaluation. Ref[41] uses `u=30` for its own figure captions only (`:472`); manuscript §V declares `u`, `l`, `e` but never sets them. `10` matches `zhuang_lattice_mabse.attributes.l`, which *is* published. |

The multi-keyword reading diverges from the paper's **own** Table III (`:485`), which claims `(u+e)L_h + (u+e)L_m + L_e` — linear in `u+e`. No construction in the paper produces that. Per README §13 the published construction is implemented and the divergence reported.

---

## Feasibility

Search is a linear scan at `2u+1` pairings per entry with no filtering. At the Exp. 2 sweep top (`N=10⁶`, `u=10`, `q=5`) that is ~1.05×10⁸ pairings for **one** run, before 30 repetitions.

`--max-seconds-per-run` (default 1800 s) bounds each point. Over-budget points are written as `status=failed` with the estimate and budget in the status string, so the gap is visible in `raw_runs.csv`. The estimate decides only whether to *attempt* a point — any point attempted is measured end to end, never derived (README §13).

**Open:** cap Ref[41]'s Exp. 2 sweep and state the cap in §V, drop Ref[41] from Exp. 2, or accept a very long run.

---

## Folder Structure

```
thingom_pq_abse/
├── SCHEME.md                          # This file
├── src/
│   ├── scheme.py                      # The published construction
│   ├── lsss.py                        # LSSS matrix + reconstruction over F_w
│   ├── experiments.py                 # Exp. 1, 2, 3
│   ├── harness.py                     # Timing, 95% CI, CSV/meta output
│   └── main.py                        # CLI + reportability gating
├── exp1_trapdoor_generation/
├── exp2_search_latency/
└── exp3_crossdomain_scalability/
```

---

## Running

Reportable runs need **Linux** — `charm-crypto` supplies the published Type-I SS512 curve and is Linux-only. `pairing.py` refuses `petrelic` (Type-III) for reportable runs.

### Linux

```bash
python3 -m Schemes.thingom_pq_abse.src.main \
    --experiment 1,2,3 \
    --dataset Dataset/derived \
    --runs 30
```

### Windows — not possible for this scheme

Unlike the other baselines, Ref[41] has **no working Windows development path**. It pairs two elements of the same group everywhere (`e : I₁×I₁→I₂`), and the Type-III `petrelic` fallback in `crypto.yaml` has no such operation — the first pairing in `setup()` would fail. `main.py` refuses a Type-III backend up front with that explanation rather than letting it crash inside the library.

`charm-crypto` is required to run Ref[41] **at all**, not only to run reportably. Use the Linux host or WSL2.

`--dev` still exists, but it only relaxes the *corpus* gate (letting you run against `Dataset/derived/sample_v2_200records.jsonl`). It cannot substitute for the pairing library. Output is stamped `reportable: false` with the reasons.

`--config` is accepted but optional: `Experiment Configuration/global.yaml`, referenced by README §8, does not exist in this repository. `crypto.yaml` is read automatically.

---

## Output

| File | Contents |
|------|----------|
| `raw_runs.csv` | One row per individual run |
| `results.csv` | Aggregated means with 95% CI (Student-t, `n−1` df) |
| `run_meta.json` | Provenance + `reportable` flag and blockers |

See main [README.md](../../README.md) §9 for column format.

**Unit note:** Exp. 1's trapdoor size is reported in **bytes**, per README §5 ("trapdoor size (B)"). README §9 states sizes are in KB. The two disagree; §5 is the more specific statement and was followed. Needs reconciling before the figures are generated.
