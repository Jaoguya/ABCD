# Guo VDSSE — Scheme Experiment Guide (Ref[35])

**Back to the operator's guide:** [SystemConfiguration.md](../../SystemConfiguration.md)

---

## Experiments (5 of 8)

| # | Experiment | Notes |
|---|-----------|-------|
| 1 | Trapdoor Generation Latency | Standard trapdoor generation |
| 2 | Search Latency | Standard search path |
| 3 | Cross-Domain Search Scalability | **Native mode**: `d` independent trapdoors + `d` independent searches, client-side result aggregation |
| 4 | Verification Overhead | Scheme-native verification mechanism |
| 5 | Dynamic Keyword Update | Incremental keyword update |

### Per-Experiment Notes

- **Exp. 3** — Does not natively support cross-domain search. Run `d` independent trapdoors and `d` independent searches, with client-side result aggregation. This is the honest modeling per Table VI.
- **Exp. 4** — Use this scheme's own verification mechanism as published.
- Does **not** participate in Exp. 6, 7, 8.

---

## Folder Structure

```
guo_vdsse/
├── SCHEME.md                          # This file
├── src/                               # Implementation of published construction
├── exp1_trapdoor_generation/
├── exp2_search_latency/
├── exp3_crossdomain_scalability/
├── exp4_verification_overhead/
└── exp5_keyword_update/
```

---

## Running

### Linux

```bash
python3 -m Schemes.guo_vdsse.src.main \
    --experiment 1,2,3,4,5 \
    --config "Experiment Configuration/global.yaml" \
    --dataset Dataset/derived \
    --runs 10
```

### Windows (PowerShell)

```powershell
python -m Schemes.guo_vdsse.src.main `
    --experiment 1,2,3,4,5 `
    --config "Experiment Configuration/global.yaml" `
    --dataset Dataset/derived `
    --runs 10
```

---

## Output

| File | Contents |
|------|----------|
| `raw_runs.csv` | One row per individual run |
| `results.csv` | Aggregated means with 95% CI |
| `run_meta.json` | Provenance |

See [SystemConfiguration.md](../../SystemConfiguration.md) for column format.
