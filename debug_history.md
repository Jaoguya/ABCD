# Debug History

This file is a chronological log of all debugging activity during experiment development and execution. **Append-only** — never delete or overwrite previous entries.

Each entry is marked *not fixed* until resolved, then updated to *fixed*.

---

<!-- Append new entries below this line. Do not modify entries above. -->

### Ref[52] SamplePre perturbation mode is an approximation
- **Date:** 2026-08-03
- **Status:** *not fixed* — needs user sign-off before any reportable Ref[52] run
- **Why it changed:** `Common/crypto/lattice.py` implements the MP12 gadget-trapdoor toolkit. The cryptographically exact MP12 preimage sampler requires a Cholesky factor of an `m x m` covariance matrix. At Ref[52]'s published `m = 13,812` that is ~1.5 GB in float64 with O(m^3) work per parameter set, which is not tractable in Python.
- **How it will improve:** `PerturbationMode.SPHERICAL` (the default) returns correct, short preimages satisfying `A e = u (mod q)` and pays the dominant cost — the `R @ z` product, ~47.7M multiply-adds. It is therefore a **lower bound** on the exact sampler's latency, not a substitute for it. `PerturbationMode.EXACT` raises `NotImplementedError` with the reason rather than silently degrading.
- **What changed:** Added `PerturbationMode` enum with `NONE` / `SPHERICAL` / `EXACT`; documented the caveat at module level in `lattice.py`. Any Exp. 1/2/5/6 figure for Ref[52] must state which mode produced it.

### MP12 chosen as the TrapGen instantiation for Ref[52]
- **Date:** 2026-08-03
- **Status:** *fixed* — resolved from the published parameters, no guess required
- **Why it changed:** Ref[52] states the `TrapGen(n, m, q, sigma)` interface (Ref[52].txt:104-117) but not its internals, so the instantiation had to be determined rather than assumed.
- **How it will improve:** The published `m` settles it. With `k = log2(q) = 24` the gadget block is `n*k = 6,816`, leaving `m - n*k = 13,812 - 6,816 = 6,996` for the uniform block — just above the `n*log(q) = 6,816` lower bound MP12 requires. That is the MP12 decomposition exactly; a classic Ajtai/GPV TrapGen would not yield `m = 13,812` for `n = 284`. MP12 is thus the algorithm the published parameters describe, not a substitution for it.
- **What changed:** Documented the argument at the top of `lattice.py` and in `crypto.yaml` under `zhuang_lattice_mabse.lattice`.

### ML-KEM-768 backend attribution in requirements.txt is unverified
- **Date:** 2026-08-03
- **Status:** *not fixed* — confirm on the AWS Ubuntu experiment host
- **Why it changed:** `requirements.txt` attributed ML-KEM-768 to `cryptography>=43.0.0`. ML-KEM landed in `cryptography` well after 43.0, so a host satisfying requirements.txt may have no ML-KEM at all, and the proposed scheme's session establishment would fail at setup.
- **How it will improve:** `Common/crypto/kem.py` probes three providers in order (`cryptography.asymmetric.mlkem`, `liboqs`, `kyber-py`), reports which is live via `available_backends()`, and records it in the environment report that feeds `run_meta.json`. A missing backend now produces an actionable error naming all three install options instead of an `ImportError`.
- **What changed:** Added backend abstraction in `kem.py`; corrected the attribution note in `requirements.txt`. Still to do: verify on the experiment host and pin the winner.

### MIMIC-IV v3.1 cannot reach the 10^6 record top of README §4
- **Date:** 2026-08-03
- **Status:** *not fixed* — needs a decision before Exp. 2 results are generated
- **Why it changed:** README §4 states a corpus range of 10^4-10^6 records and Exp. 2 sweeps searchable index size `N` over the same range. MIMIC-IV v3.1 holds on the order of 5x10^5 hospital admissions and far fewer ICU stays, so at one record per admission the top of the sweep cannot be populated.
- **How it will improve:** Options are (a) cap the Exp. 2 sweep at what the corpus supports, (b) use a finer record unit, or (c) read `N` as keyword/document pairs rather than records — 5x10^5 admissions at ~12 keywords each gives ~6x10^6 pairs, which does cover the range. Option (c) matches the phrase "searchable index size" but contradicts README §4's "Records | 10^4 - 10^6". The two README statements need reconciling either way.
- **What changed:** `prepare_dataset.py` reports the ceiling it actually found and prints an explicit warning when the corpus holds fewer than 10^6 records, rather than silently producing a short sweep.

### MIMIC-IV dropped; Synthea is now the sole corpus
- **Date:** 2026-08-03
- **Status:** *fixed* — supersedes "MIMIC-IV v3.1 cannot reach the 10^6 record top of README §4" above, which is now moot
- **Why it changed:** The MIMIC-IV record ceiling (546,028 hospitalizations, 94,458 ICU stays — confirmed from the PhysioNet v3.1 page) made README §4's 10^4-10^6 range unreachable, and credentialing (CITI + DUA) blocked all reportable work for days to weeks. Two further problems: MIMIC-IV is retrospective hospital EHR rather than IoMT data, and its DUA barred committing the derived corpus, so a reviewer could never reproduce the exact index.
- **How it will improve:** Synthea (MITRE, Apache 2.0) removes all four constraints — unbounded corpus size, no credentialing, redistributable derived corpus, and a real institutional domain split from `encounters.ORGANIZATION` instead of a hash of the patient ID. Critically it preserves the property Exp. 2 actually depends on: module-driven keyword co-occurrence, which drives posting-list overlap and hence `n_eff`. A fitted Zipf law cannot reproduce that, which is why `synthetic` remains non-reportable while `synthea` is reportable.
- **What changed:** `dataset.yaml` — `mimic` block removed, `synthea` block added. `prepare_dataset.py` — rewritten Synthea-only (encounter record unit, SNOMED/RxNorm keyword namespaces, ORGANIZATION domains). `corpus.py` — `corpus_type` is now `synthea` | `synthetic`; `mimic` rejected. `synthetic_generator.py --match-profile` now expects a Synthea manifest. `.gitignore` — corpus exclusion is now a size rule, not a DUA rule. README §4, §6, §7, §8, §11, §12, §14, §15 updated. **Manuscript §V still needs the matching rewrite, including the dataset citation — not done.**

### Ref[41] is pairing-based, contradicting its own post-quantum claim
- **Date:** 2026-08-03
- **Status:** *fixed* — implemented as published; reported as an observation, not corrected
- **Why it changed:** Ref[41] is positioned in README §3 as the multi-authority ABSE direction in a post-quantum benchmark, but Ref[41].txt:510-513 defines a Type-I pairing `e : I1 x I1 -> I2` with security resting on DBDH (Ref[41].txt:280-300) — which Shor breaks. Ref[41].txt:299 calls DBDH "the foundation of the post-quantum security claims in this work" while Ref[41].txt:919-927 of the same paper states pairings are not post-quantum.
- **How it will improve:** README §14 forbids strengthening a baseline beyond its published construction, so the contradiction is reproduced rather than fixed. Consequence for the environment: a pairing library is required to run a **baseline**, not only the proposed scheme — `requirements.txt` had it as proposed-only.
- **What changed:** `Common/crypto/pairing.py` implements Type-I via charm-crypto SS512 (faithful, Linux-only) with a Type-III petrelic fallback that `get_backend(reportable=True)` **refuses** to use, raising `UnfaithfulBackendError` rather than quietly producing a number from the wrong curve. `requirements.txt` corrected.

### No Python toolchain on the development machine
- **Date:** 2026-08-03
- **Status:** *not fixed* — expected to resolve on the AWS Ubuntu host
- **Why it changed:** The Windows development machine has no Python interpreter (only the Microsoft Store stub) and no WSL distribution installed, so nothing written on 2026-08-03 has been executed.
- **How it will improve:** All code targets Python 3.11 on Ubuntu, which is the stated experiment environment. Until it runs there, every module written so far is **unexecuted** and should be treated as such.
- **What changed:** Nothing yet. First action on the experiment host: `pip install -r requirements.txt`, then `python3 -c "from Common.crypto import environment_report; print(environment_report())"`, then a synthetic corpus generation as the first end-to-end smoke test.
