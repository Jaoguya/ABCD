# XB-Muse — Scheme Experiment Guide (Ref[36])

> **DROPPED — 2026-08-23. Do not implement.**
> This scheme is no longer part of the benchmark. It requires an Intel SGX enclave
> (`References/Ref[36]/Ref[36].md:341,359`) and the `m6i.xlarge` benchmark host exposes none,
> so it could only be run simulated (which flatters it) or on non-parity hardware.
> Removed from every sweep in `global.yaml`. See README §14 item 8 and §16.
> The rest of this file is retained for the record only.


**Back to main README:** [README.md](../../README.md)

---

## ⚠️ Critical: Corrupted Reference PDF

> `References/Ref[36].pdf` is corrupted — its text streams cannot be extracted. **Obtain a clean copy** from IEEE Xplore (doi: 10.1109/JIOT.2025.3561287) before implementing this scheme. Do **not** implement from the abstract or comparison table alone.

---

## Experiments (4 of 8)

| # | Experiment | Notes |
|---|-----------|-------|
| 1 | Trapdoor Generation Latency | Standard trapdoor generation |
| 2 | Search Latency | Standard search path |
| 3 | Cross-Domain Search Scalability | **Native mode**: `d` independent trapdoors + `d` independent searches, client-side result aggregation |
| 5 | Dynamic Keyword Update | Incremental keyword update |

### Per-Experiment Notes

- **Exp. 3** — Does not natively support cross-domain search. Run `d` independent trapdoors and `d` independent searches, with client-side result aggregation.
- Does **not** participate in Exp. 4, 6, 7, 8.

---

## Folder Structure

```
xb_muse/
├── SCHEME.md                          # This file
├── src/                               # Implementation of published construction
├── exp1_trapdoor_generation/
├── exp2_search_latency/
├── exp3_crossdomain_scalability/
└── exp5_keyword_update/
```

---

## Running

### Linux

```bash
python3 -m Schemes.xb_muse.src.main \
    --experiment 1,2,3,5 \
    --config "Experiment Configuration/global.yaml" \
    --dataset Dataset/derived \
    --runs 30
```

### Windows (PowerShell)

```powershell
python -m Schemes.xb_muse.src.main `
    --experiment 1,2,3,5 `
    --config "Experiment Configuration/global.yaml" `
    --dataset Dataset/derived `
    --runs 30
```

---

## Output

| File | Contents |
|------|----------|
| `raw_runs.csv` | One row per individual run |
| `results.csv` | Aggregated means with 95% CI |
| `run_meta.json` | Provenance |

See main [README.md](../../README.md) §9 for column format.
