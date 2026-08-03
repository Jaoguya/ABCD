# Zhuang Lattice MA-BSE — Scheme Experiment Guide (Ref[52])

**Back to main README:** [README.md](../../README.md)

---

## Experiments (5 of 8)

| # | Experiment | Notes |
|---|-----------|-------|
| 1 | Trapdoor Generation Latency | Standard trapdoor generation |
| 2 | Search Latency | Standard search path |
| 3 | Cross-Domain Search Scalability | **Native mode**: `d` independent trapdoors + `d` independent searches, client-side result aggregation |
| 5 | Dynamic Keyword Update | Incremental keyword update |
| 6 | Authorization Synchronization | Scheme-native auth sync mechanism |

### Per-Experiment Notes

- **Exp. 3** — Does not natively support cross-domain search. Run `d` independent trapdoors and `d` independent searches, with client-side result aggregation.
- **Exp. 6** — Use this scheme's own authorization synchronization mechanism as published.
- Does **not** participate in Exp. 4, 7, 8.

---

## Folder Structure

```
zhuang_lattice_mabse/
├── SCHEME.md                          # This file
├── src/                               # Implementation of published construction
├── exp1_trapdoor_generation/
├── exp2_search_latency/
├── exp3_crossdomain_scalability/
├── exp5_keyword_update/
└── exp6_authorization_sync/
```

---

## Running

### Linux

```bash
python3 -m Schemes.zhuang_lattice_mabse.src.main \
    --experiment 1,2,3,5,6 \
    --config "Experiment Configuration/global.yaml" \
    --dataset Dataset/derived \
    --runs 30
```

### Windows (PowerShell)

```powershell
python -m Schemes.zhuang_lattice_mabse.src.main `
    --experiment 1,2,3,5,6 `
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
