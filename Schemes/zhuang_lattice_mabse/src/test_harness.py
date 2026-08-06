"""Smoke test: verify the harness measurement loop, CSV output, and aggregation work."""
import tempfile, time, os, csv, json
from pathlib import Path
from Schemes.zhuang_lattice_mabse.src.harness import (
    RunResult, measure_latency_ns, aggregate_results,
    write_raw_runs, write_results, write_run_meta
)

print("=== HARNESS SMOKE TEST ===")
print()

# Test 1: measure_latency_ns works
print("Test 1: Measurement loop...")
def dummy_op():
    t0 = time.perf_counter_ns()
    total = sum(range(1000))
    elapsed_ms = (time.perf_counter_ns() - t0) / 1e6
    return (elapsed_ms, float(total))

runs = measure_latency_ns(dummy_op, warmup=2, runs=5, variable_value=42)
assert len(runs) == 5, f"Expected 5 runs, got {len(runs)}"
assert all(r.status == "ok" for r in runs), "Some runs failed"
assert all(r.primary_metric > 0 for r in runs), "Zero latency"
print(f"  5 runs OK, mean={sum(r.primary_metric for r in runs)/5:.4f} ms")

# Test 2: aggregate_results
print("Test 2: Aggregation...")
agg = aggregate_results(runs)
assert 42 in agg, "Missing variable value in aggregation"
row = agg[42]
assert "primary_mean" in row, "Missing primary_mean"
assert "primary_ci95" in row, "Missing primary_ci95"
assert row["n_runs"] == 5, f"Expected n_runs=5, got {row['n_runs']}"
print(f"  mean={row['primary_mean']:.4f} ms, ci95={row['primary_ci95']:.4f} ms, n={int(row['n_runs'])}")

# Test 3: CSV output
out_dir = Path("Schemes/zhuang_lattice_mabse/_test_output")
out_dir.mkdir(exist_ok=True)

print("Test 3: write_raw_runs...")
write_raw_runs(out_dir / "raw_runs.csv", "smoke_test", runs)
with open(out_dir / "raw_runs.csv") as f:
    reader = csv.reader(f)
    rows = list(reader)
assert len(rows) == 6, f"Expected 6 rows (header + 5), got {len(rows)}"
assert rows[0][0] == "scheme", f"Bad header: {rows[0]}"
print(f"  raw_runs.csv: {len(rows)-1} data rows, header={rows[0][:4]}")

print("Test 4: write_results...")
write_results(out_dir / "results.csv", agg)
with open(out_dir / "results.csv") as f:
    reader = csv.reader(f)
    rows = list(reader)
assert len(rows) == 2, f"Expected 2 rows (header + 1), got {len(rows)}"
print(f"  results.csv: {len(rows)-1} data rows")

print("Test 5: write_run_meta...")
write_run_meta(out_dir / "run_meta.json", "smoke_test", {"test": True})
with open(out_dir / "run_meta.json") as f:
    meta = json.load(f)
assert meta["scheme"] == "zhuang_lattice_mabse"
assert meta["experiment"] == "smoke_test"
assert "python_version" in meta
print(f"  run_meta.json: scheme={meta['scheme']}, python={meta['python_version']}")

# Cleanup
import shutil
shutil.rmtree(out_dir)
print()
print("=== ALL 5 HARNESS TESTS PASSED ===")
