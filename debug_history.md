# Debug History

This file is a chronological log of all debugging activity during experiment development and execution. **Append-only** — never delete or overwrite previous entries.

Each entry is marked *not fixed* until resolved, then updated to *fixed*.

---

<!-- Append new entries below this line. Do not modify entries above. -->

### Committed `Dataset/dataset_manifest.json` is the superseded corpus v1 manifest
- **Date:** 2026-08-08
- **Status:** *not fixed* — needs the v2 manifest committed from the experiment host; found while cross-validating configs, not yet blocking Phase I
- **Why it changed:** Nothing changed it — it was never updated when corpus v2 was frozen on 2026-08-04. The manifest in git describes **v1**: `corpus_sha256 = d991c695...`, 1,206,159 records, 2,102 keywords, `per_domain_counts` 248,091 / 411,768 / 275,180 / 271,120, and `keywords_per_record.p50 = 4`, `min = 1`. Those are precisely the v1 properties the 2026-08-04 entry above records as superseded and archived ("it never produced results"). The frozen v2 corpus is `fd4b7654...`, 1,141,072 records, 2,006 keywords, domains 285,268 x 4 exactly, min `|W_i|` = 5, and that is what `dataset.yaml -> freeze.expected_corpus_sha256` pins.
- **How it will improve:** The guard layer behaves correctly and is the reason this is a stale artifact rather than a silent data swap: `Dataset/corpus.py::verify_against_pin` compares the manifest's `corpus_sha256` against the `dataset.yaml` pin and raises `CorpusMismatchError` on mismatch, so `load_verified_corpus()` **refuses to load anything** in the current tree rather than running a scheme against v1. The consequence is that no corpus-reading experiment can run until the v2 manifest is committed; Phase I-II do not read the corpus, so this does not block current work. Worth noting that the two-layer check (corpus-vs-manifest, then manifest-vs-pin) is what makes this detectable at all — the manifest alone would have verified against a v1 corpus happily.
- **What changed:** Nothing in `Dataset/` — the derived corpus and its real manifest are git-ignored and live on the experiment host, so regenerating the manifest here would fabricate provenance for a corpus this machine does not hold. Recorded instead, with two follow-ups for the user: (a) commit the v2 `dataset_manifest.json` from the experiment host; (b) note that `dataset.yaml -> corpus.domain_assignment` still reads `hash_of_patient_id` while `synthea.domain_assignment` reads `balanced_organizations` — the former looks like a leftover from the MIMIC-era config and disagrees with README §4 and with v2's exactly-equal domain counts. `Schemes/ma_lb_pq_vdse/src/config.py` gained `verify_corpus_reference()`, which compares `index.yaml`'s restated corpus facts against whatever manifest is actually loaded, so this class of drift fails loudly at run time instead of being read past.

### macOS development host had no runnable Python environment for the primitive layer
- **Date:** 2026-08-08
- **Status:** *fixed* (development host only — the AWS experiment host is unaffected)
- **Why it changed:** `python3 Common/crypto/tests/test_primitives.py` failed at import with `ModuleNotFoundError: No module named 'mmh3'` on the macOS development machine. Probing the interpreter showed only `numpy`, `matplotlib`, and `cryptography` present; `mmh3`, `bitarray`, `scipy`, `pyyaml`, `pandas`, `pycryptodome` and every ML-KEM backend were absent. The "Environment complete" entry of 2026-08-04 covers the Ubuntu AWS host, not this machine, so the crypto layer had never executed here.
- **How it will improve:** Phase I of the proposed scheme instantiates `P = {H, SHA-256, AES-256-GCM, HKDF, ML-KEM}` (manuscript Phase I Step 1), so an ML-KEM backend is a precondition for writing Phase I at all, not an optional extra. The suite now runs locally, giving a fast pre-commit check before work moves to the experiment host.
- **What changed:**
  - Created a project-local `.venv` (already git-ignored, `.gitignore:59`) and installed the global requirements: `mmh3`, `bitarray`, `scipy`, `pandas`, `pyyaml`, `pycryptodome`, `tqdm`, `psutil`, `numpy`, `matplotlib`, `cryptography`. **No repository file was modified.**
  - **ML-KEM** — `liboqs-python` installed but its bundled liboqs auto-build failed with `/bin/sh: cmake: command not found`. Resolved by installing the `cmake` **PyPI wheel into the venv** (cmake 4.4.2) rather than via Homebrew, keeping the toolchain inside the virtualenv and leaving the host system untouched. liboqs then built and installed to `~/_oqs`; `oqs.oqs_version()` reports **0.16.0 — the same version pinned on the AWS host**, so the dev and experiment hosts share one ML-KEM backend.
  - **Result:** `61 passed, 4 skipped, 0 failed out of 65`. The 4 skips are all pairing (`charm-crypto` is Linux-only, `petrelic` still does not build), which affects **Ref[41] only** — no primitive needed by `ma_lb_pq_vdse` is unverified on this host. See the separate blocker below: our own MA-CP-ABE also needs a pairing backend, and no curve is configured for it yet.

### Ref[36] recovered — and requires Intel SGX
- **Date:** 2026-08-05
- **Status:** *fixed* (corruption) / *not fixed* (SGX requirement — needs a decision)
- **Why it changed:** The original `References/Ref[36].pdf` had destroyed flate streams; two independent toolchains (the original extraction and poppler) recovered 0 bytes. A clean copy was obtained from IEEE Xplore. `pdftotext -layout` extracted 108,474 bytes across 1,030 lines, same DOI 10.1109/JIOT.2025.3561287. Corrupted originals archived under `References/corrupted_archive/`.
- **How it will improve:** The construction is now readable, which unblocks `xb_muse/`. XB-Muse builds on **SRE (Symmetric Revocable Encryption)**: a multi-puncturable PRF plus a Bloom filter holding revoked tags, with keyed PRFs `F`/`G` for address derivation and on-chain revocation status. `Common/crypto/prf.py` already provides a puncturable PRF that punctures at a *set* of points, and `bloom.py` provides BF(l,k) — so the shared primitive layer covers the SRE building blocks without new code.
- **What changed:** Reading the recovered text surfaced a hardware requirement that was invisible while the PDF was corrupted: **the scheme runs part of its algorithm inside an Intel SGX enclave** (`Ref[36].txt:341` — "the pseudo-codes in blue are run in the enclave created by intel SGX"; `:359` — the data owner uses SGX attestation to establish a secure channel and provision `sk` into the enclave). `m6i.xlarge` does not expose SGX; AWS offers Nitro Enclaves, which has a different trust and attestation model. Three options are recorded in README §14. Worth noting for whichever is chosen: a simulated enclave omits SGX's enclave-transition and EPC-paging overhead, so it would make Ref[36] appear *faster* than a real deployment — the direction that does not flatter the proposed scheme.

### Environment complete — all primitives verified on the experiment host
- **Date:** 2026-08-04
- **Status:** *fixed*
- **Why it changed:** Nothing in `Common/crypto/` had ever executed. Three dependencies were unresolved: the ML-KEM backend (requirements.txt wrongly attributed it to `cryptography>=43`), `charm-crypto` (needed for Ref[41]'s Type-I pairing), and the primitive test suite itself.
- **How it will improve:** The crypto layer is now verified before any scheme is built on it. **65 tests: 64 passed, 1 skipped, 0 failed.**
- **What changed:**
  - **ML-KEM** — `cryptography` 50.0.0 does *not* expose ML-KEM; the multi-backend probe in `kem.py` selected **liboqs 0.16.0**, which reports `ML-KEM-768 available: True`. FIPS 203 sizes and round-trip verified.
  - **charm-crypto** — failed with "requires the python development environment". Root cause: `configure.sh:526` runs `which python3-config`, and only `python3.11-config` exists on Ubuntu 22.04 with deadsnakes. Fixed by symlinking `/usr/local/bin/python3-config -> /usr/bin/python3.11-config` and passing `--python=$VENV/bin/python3`. PBC 0.5.14 built from source first as a prerequisite. SS512 verified: bilinearity holds, G1 element = 90 bytes.
  - **Note on SS512** — charm emits a DeprecationWarning that SS512 provides only ~80-bit security, below NIST's 128-bit recommendation. Ref[41] specifies a Type-I pairing but not a curve; SS512 is the standard symmetric choice. Charm's only stronger symmetric option is SS1024 (~112-bit). Switching would change measured pairing cost, so it is a decision to make once, before reportable runs, not a default to drift into.
  - `petrelic` still fails to build; it is the Type-III development fallback only and is not needed for reportable Ref[41] runs.

### Corpus v1 superseded — median |W_i| below the query size
- **Date:** 2026-08-04
- **Status:** *fixed*
- **Why it changed:** The first frozen corpus (SHA-256 `d991c695...`, 1,206,159 records) had a median `|W_i|` of 4 while the manuscript fixes `q=5` (§V, "each query contains five keywords"). A conjunctive q-keyword query only matches records with `|W_i| >= q`, so **55% of the corpus was structurally unmatchable** and contributed index weight that could never be returned — `n_eff` would have been produced by a minority of records. Its domains were also uneven (34/21/23/22) against §V's "uniformly distributed", which would have confounded Exp. 8's utilization-spread metric.
- **How it will improve:** Two changes, both grounded in the paper rather than chosen to flatter a result. `min_keywords_per_record: 5` is an inclusion criterion taken directly from the published `q`. `balance_domains()` packs whole organizations into domains largest-first, so domains stay real institutional boundaries while coming out equal.
- **What changed:** Regenerated at 38,000 patients (2,557,154 encounters, 48m40s). New corpus: **1,141,072 records**, min `|W_i|` = 5, median 29, mean 31.70, domains **285,268 x 4 exactly**, 36,172,487 pairs, 2,006 keywords, SHA-256 `fd4b7654e4c20186163f0b8c390c2c50b4bc4f908bdfbca585779b8d0792dc47`, pinned in `dataset.yaml`. v1 archived at `~/corpus_v1_archive/`; it never produced results.

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
