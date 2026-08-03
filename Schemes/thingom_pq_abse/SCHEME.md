# Thingom PQ-ABSE — Scheme Experiment Guide (Ref[41])

**Back to main README:** [README.md](../../README.md)

---

## Experiments (3 of 8)

| # | Experiment | Notes |
|---|-----------|-------|
| 1 | Trapdoor Generation Latency | Standard trapdoor generation |
| 2 | Search Latency | Standard search path |
| 3 | Cross-Domain Search Scalability | **Native mode**: `d` independent trapdoors + `d` independent searches, client-side result aggregation |

### Per-Experiment Notes

- **Exp. 3** — Does not natively support cross-domain search. Run `d` independent trapdoors and `d` independent searches, with client-side result aggregation.
- Does **not** participate in Exp. 4, 5, 6, 7, 8.

---

## Folder Structure

```
thingom_pq_abse/
├── SCHEME.md                          # This file
├── src/                               # Implementation of published construction
├── exp1_trapdoor_generation/
├── exp2_search_latency/
└── exp3_crossdomain_scalability/
```

---

## Running

### Linux

```bash
python3 -m Schemes.thingom_pq_abse.src.main \
    --experiment 1,2,3 \
    --config "Experiment Configuration/global.yaml" \
    --dataset Dataset/derived \
    --runs 30
```

### Windows (PowerShell)

```powershell
python -m Schemes.thingom_pq_abse.src.main `
    --experiment 1,2,3 `
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
