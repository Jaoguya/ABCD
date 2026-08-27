# macOS Development Host — Setup

The benchmark uses **two machines**, and this file covers the first:

| Role | Machine | Purpose |
|---|---|---|
| **Development host** | this Mac | Write code, run the 609 tests, smoke-test pipelines |
| **Experiment host** | AWS EC2 `m6i.xlarge` | Every reportable run, without exception |

Nothing measured on this Mac is reportable. README §1 pins the experiment host, and
§V will claim all schemes were measured on identical hardware — a figure produced
here would make that false. Develop here, measure there.

This is checked, not just asserted: `Common/crypto/config.verify_experiment_host()`
queries the live EC2 metadata service and compares it against `global.yaml`'s
`environment.instance_type`, so `run_meta.json`'s `environment.experiment_host`
records what host actually produced the numbers — this Mac, another machine, or the
pinned AWS instance — rather than echoing a value nobody verified. `ma_lb_pq_vdse`
and `thingom_pq_abse` already fail their `reportable` gate off this host; the other
schemes still carry the field for the record even though it isn't wired into their
gate yet.

---

## 1. Prerequisites

Python **3.11** (the version `global.yaml` specifies and the AWS venv runs — 3.11.15
as of the last host check). Apple Silicon and Intel both work.

```bash
python3.11 --version    # if missing:  brew install python@3.11
```

Do **not** use the system Python. Everything below lives in a virtualenv, matching
the `~/.venv-malbpq` convention `infra/provision.sh` uses on the server.

---

## 2. Virtualenv and dependencies

```bash
cd ~/path/to/abcd
python3.11 -m venv ~/.venv-malbpq
source ~/.venv-malbpq/bin/activate

pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
pip install pytest ruff          # not in requirements.txt; needed to run the suite
```

Add the activation to your shell profile — every command in this file assumes it:

```bash
echo 'source ~/.venv-malbpq/bin/activate' >> ~/.zshrc
```

---

## 3. ML-KEM (liboqs) — the one fiddly step

`cryptography` does **not** ship ML-KEM despite what `requirements.txt` implies, so
`Common/crypto/kem.py` probes `cryptography` → `liboqs` → `kyber-py` in that order.

Install liboqs, and match the server's version — the AWS host runs **liboqs 0.16.0**:

```bash
pip install cmake            # PyPI wheel, NOT Homebrew — see note below
pip install liboqs-python
python -c "import oqs; print(oqs.oqs_version())"     # expect 0.16.0
```

`liboqs-python` auto-builds its native library on first import and fails with
`/bin/sh: cmake: command not found` unless cmake is present. Installing the **cmake
PyPI wheel into the venv** keeps the toolchain self-contained and leaves the system
untouched — this is what was done originally (`debug_history.md` 2026-08-06) and it
puts liboqs in `~/_oqs`.

**Do not fall back to `kyber-py`.** It works, but `crypto.yaml` marks it
development-only, and it is a different implementation from the server's — so
ML-KEM timings and sizes would not correspond to the experiment host.

---

## 4. What cannot run here, and why that is fine

**`charm-crypto` is Linux-only.** It will not build on macOS, so:

- **Ref[41] (`thingom_pq_abse`) cannot run here at all** — it needs a Type-I SS512 pairing.
- All four pairing tests **skip** on this host (`PHASE_I_II_PLAN.md:223`).
- `CharmType3Backend` must be verified on AWS, never here.

This costs you nothing, because Ref[41] and the Type-III backend have to be validated
on the experiment host regardless of which laptop you develop on.

The other three schemes run here fine. `ma_lb_pq_vdse` runs with hash-based stand-ins
for group operations, which mark their output `faithful=False` → `not_reportable_because`
in `run_meta.json`. Its *measured* paths (`user/`, `fsn/`, `aim/`, `index/`, `shard/`,
`sync/`, `verify/`, `scheduler/`) contain **no group operations** — those live only in
`authority/` — so stub-based latency is representative even though it is not reportable.

---

## 5. Verify the install

```bash
pytest -q            # expect: 609 passed, 4 skipped
```

`pytest.ini` sets `--import-mode=importlib`. Do not remove it: all four schemes ship a
package literally named `src`, and the default import mode makes them collide, which
silently drops the entire `zhuang_lattice_mabse` suite from collection.

---

## 6. Development corpus

The frozen 1.14M-record corpus is git-ignored and lives on the experiment host only.
For local work, generate the seeded synthetic corpus:

```bash
python Dataset/synthetic_generator.py --records 10000 --domains 4 --seed 20260803
# sha256 -> ca1568367edc5f738f0ab6368d724652dc8fd778b88d0f8dbb2e83d099e746dd
```

That digest is reproducible byte-for-byte across macOS arm64, Linux x86-64 and
Windows — verified. If yours differs, the generator or its config changed.

Runs against it must pass `--no-require-reportable`; they print a `NOT REPORTABLE`
line and are excluded from the freeze-pin check.

To work against the real corpus locally (685 MB), copy it down:

```bash
scp -i <key>.pem ubuntu@<host>:~/abcd/Dataset/derived/corpus.jsonl Dataset/derived/
```

---

## 7. BLAS thread pinning

`global.yaml` sets `environment.blas_threads: 1`. numpy otherwise claims every core,
which would make Ref[52]'s lattice latency depend on core count — the exact thing the
pin exists to prevent. Export before any timing work:

```bash
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
       NUMEXPR_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1
```

`VECLIB_MAXIMUM_THREADS` matters specifically on macOS — numpy links Apple's
Accelerate framework, which ignores the other four.

`verify_thread_pinning(require=True)` enforces this on reportable runs.

---

## 8. Reaching the experiment host

```bash
chmod 600 <key>.pem
ssh -i <key>.pem ubuntu@<host-ip>
source ~/.venv-malbpq/bin/activate
```

Verified present on the server: charm (SS512, MNT159/201/224, BN254), numpy, scipy,
pyyaml, cryptography, bitarray, mmh3, liboqs. `pytest` is **not** installed there.

Two known gaps on the server, worth fixing before the campaign:

1. **`~/abcd` is not a git repository** — `git rev-parse HEAD` fails, so
   `provenance.git_commit()` records `"unknown"` in every `run_meta.json`. Clone it
   properly rather than copying files.
2. **`pytest` missing** — the 609 tests cannot be run there as-is.

---

## 9. Daily loop

```
edit on Mac  ->  pytest -q  ->  smoke-run at small N  ->  push  ->  pull on AWS  ->  measure
```

Keep reportable runs on AWS. Use this Mac for everything else — it is faster to
iterate on, and finding a bug here costs minutes instead of hours of instance time
mid-campaign.
