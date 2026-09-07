# Experiment 1 — clarification

**Fig. 2 = token-generation latency vs `q`. Eight curves, five points each.**

- 4 baselines — Guo [35], Ge [30], Thingom [41], Perera [54]. One curve each:
  `|P_U|` is not a parameter of their trapdoors.
- 4 proposed — one per `|P_U| ∈ {1,2,4,8}`, same colour, different linestyle.
- `q ∈ {1,5,10,15,20}` — a set of five values, not the range 1–20.

Caption fixes the layout: latency on y, query scope on x, authorization scope as
the curves.

**Timed path:** `|P_U|` policy-state digests `PV_ℓ = H(Encode(V_{P_ℓ}))`, then
`q·|P_U|` tokens `T = H(w ‖ PID ‖ PV ‖ Dom)`. Nothing else — no index, no search,
no ledger. ML-KEM excluded (§VI: it happens at attribute-key delivery, not per
query).

`|T_Q| = q·|P_U|` is an equation supporting `tab:cost`'s `O(|T_Q|)T_H`. Not
plotted, and does not need to be.

`H` is keyed HMAC-SHA256 — required by §V's leakage model, which admits only
sizes and access patterns. Unkeyed, an FSN inverts every token against the
corpus's 2,023 keywords.

---

## Done

1.1 token formula · 1.2 identity asserted per sample · 1.3 both sweeps ·
1.4 ML-KEM excluded · 1.5 corpus-backed (was inventing `kw:00000` /
`hospital/pol0`) · 1.6 figure = 8 curves at 5 points

Also fixed: `build()` dropped `variant` on the corpus-backed path, so all four
arms would have been built at `|P_U| = 1`.

## Left

- **1.7 — paper.** §VI does not say why the proposed scheme has four curves and
  each baseline one. One sentence. Author's.
- **1.7b — paper.** §IV should say `H` is keyed; §V's leakage model requires it.
"this is author note 1.7 is pass"

- **1.8 — campaign-wide, not Exp. 1's.** BLAS pins never reach the experiment
  process, so `thread_pinning` is null in every banked run and today's gate
  fails them all. `fleet.sh` has no run command, so the fix belongs in-process
  (set the four vars from `global.yaml` before numpy imports), not in a script.
  when doing smoke test also ask that will it holds if we scale doing full experiment

## Confirm

```bash
pytest Schemes/ma_lb_pq_vdse/src/tests/test_psa_experiments.py -k exp1 -q

python3 -m Schemes.ma_lb_pq_vdse.src.main \
    --construction psa --experiment 1 --variant pu4 \
    --dataset Dataset/derived --smoke
```

Then in `psa_exp1_token_generation__pu4/`:

- `run_meta.json`: `corpus_type: synthea` (was `psa_in_process`),
  `thread_pinning` all `"1"`, `not_reportable_because: []`
- `results.csv`: `secondary_1_mean` = `4, 20, 40, 60, 80`

The smoke run is what closes both 1.5 and 1.8. Minutes, not the campaign.
