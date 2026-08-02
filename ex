# PLOSHA-RMFR — Discrete-Event Simulation Benchmark

This repository contains the experimental implementation of the **PLOSHA-RMFR** framework: *Predictive Adaptive Hierarchical Slot Aggregation with Risk-Aware Multi-Layer Fault Recovery*.

This codebase is in the **experimental phase**. Its purpose is to benchmark and validate the cryptographic primitives and system workflows proposed in the PLOSHA-RMFR scheme through discrete-event simulation, verifying whether the theoretical design performs correctly and efficiently under real execution conditions.

## Hardware & Environment

| Component | Specification |
|-----------|--------------|
| **CPU** | Intel Core i5-10600 (Intel SGX capable) |
| **OS** | Ubuntu 22.04 LTS |
| **TEE Runtime** | Gramine (Library OS) |
| **Language** | C++ |
| **Libraries** | OpenSSL, GMP |

Gramine is integrated to allow unmodified C++ applications to run securely within Intel SGX enclaves without requiring custom EDL (Enclave Definition Language) files. Standard cryptographic libraries (OpenSSL for ECDSA, GMP for Paillier) are linked directly instead of using Intel SGX SDK cryptographic primitives.

## Cryptographic Primitives Under Evaluation

- **Paillier Cryptosystem** — Additively homomorphic encryption for privacy-preserving aggregation over encrypted sensor data.
- **Modified ECDSA with Batch Verification** — Efficient digital signature generation and batch verification for authentication and integrity, based on the scheme by Shang et al. (IEEE TII, 2024).

## Simulation Methodology

The evaluation is conducted through a **discrete-event simulation (DES)**. In this approach, all framework phases — initialization, EWMA prediction, PLOSHA aggregation, RMFR recovery, and AFLTO feedback — execute as a single unified pipeline within each simulation run. Individual experiments differ only in the independent variable being varied and the metrics being measured.

### On Expected Results

The performance figures presented in the original PLOSHA-RMFR paper represent **theoretical projections**, not empirical measurements from a running system. This benchmark aims to observe the **actual behavior** of the system under real execution conditions. There is no intention to artificially constrain or bias the empirical results to match the paper's projections. Outcomes that deviate from the theoretical baseline are equally valid and will be reported as observed.

## Repository Structure

```
PLOSHA-RMFR/
├── README.md
├── run_benchmark.sh                         # Automated benchmark runner
├── dataset/
│   └── plosha_dataset.csv                   # Shared input for all schemes
├── schemes/
│   ├── plosha_rmfr/                         # [ours] PLOSHA-RMFR
│   │   ├── src/                             # Core DES engine
│   │   ├── exp1_ablation_aggregation/
│   │   ├── exp2_scheduling_efficiency/
│   │   ├── exp3_failure_rate/
│   │   ├── exp4_loss_exposure/
│   │   ├── exp5_recovery_comm/
│   │   ├── exp6_aflto_ablation/
│   │   └── exp7_heterogeneity/
│   ├── robust_iiot/                         # Ref[24] — Shang et al.
│   │   ├── src/
│   │   └── exp4_loss_exposure/
│   ├── fed_dqn/                             # Ref[22] — Choppara & Mangalampalli
│   │   ├── src/
│   │   ├── exp2_scheduling_efficiency/
│   │   └── exp3_failure_rate/
│   ├── fault_tolerant_workflow/             # Ref[37] — Ren & Yao
│   │   ├── src/
│   │   ├── exp2_scheduling_efficiency/
│   │   ├── exp3_failure_rate/
│   │   ├── exp4_loss_exposure/
│   │   └── exp5_recovery_comm/
│   └── ft_serverless_edge/                  # Ref[38] — Xu et al.
│       ├── src/
│       ├── exp2_scheduling_efficiency/
│       ├── exp3_failure_rate/
│       ├── exp4_loss_exposure/
│       └── exp5_recovery_comm/
├── plots/
│   ├── generate_plots.py                    # Central plotting script
│   └── output/                              # Generated graphs
├── src/                                     # Shared crypto library
│   └── crypto/                              # Paillier, ECDSA implementations
├── References/                              # Paper PDF and markdown
├── docs/                                    # Implementation plans
└── archive/                                 # Legacy Python prototype (unused)
    └── python_prototype/
```

## Baseline Schemes

| Folder | Reference | Paper | Role in Comparison |
|--------|-----------|-------|-------------------|
| `plosha_rmfr/` | [ours] | This work | Proposed scheme |
| `robust_iiot/` | Ref[24] | Shang et al., IEEE TII 2024 | Privacy-preserving encrypted aggregation |
| `fed_dqn/` | Ref[22] | Choppara & Mangalampalli, IEEE Access 2025 | Learning-based adaptive scheduling |
| `fault_tolerant_workflow/` | Ref[37] | Ren & Yao, IEEE TSC 2026 | Hybrid fault-tolerant workflow scheduling |
| `ft_serverless_edge/` | Ref[38] | Xu et al., IEEE TSC 2026 | Fault-tolerant serverless edge stream processing |

## Experiment Definitions

Each experiment varies a single independent variable and measures specific metrics. Not every scheme participates in every experiment.

This table follows the numbering used in `References/plosha-rmfr.md` Section V ("Experimental Setup" onward) and the current `schemes/plosha_rmfr/exp<N>_*/` folder names. An earlier draft of this benchmark used a different 7-experiment design (Sensor Scalability / Fog Node Scalability as Exp1/Exp2); that design has been superseded and this table reflects the current one.

| # | Description | Independent Variable | Primary Metric | Secondary Metrics | Schemes |
|---|-------------|---------------------|---------------|-------------------|---------|
| 1 | Ablation of the PLOSHA Aggregation Architecture | Aggregation variant (Flat-Epoch / Fixed-Slot / Adaptive-Slot / Full PLOSHA) × number of sensors (500–5000) | Aggregation latency | Aggregation CPU time, loss exposure, recomputation overhead, reused micro-slot count | PLOSHA only (internal ablation) |
| 2 | Scheduling Efficiency | Number of fog nodes (5–50) | Workload imbalance (capacity-normalized $I_W$) | Scheduling latency | PLOSHA, FedDQN, FT-Workflow, FT-Serverless |
| 3 | Impact of Failure Rate | Fog-node failure rate (2%–20%) | Recovery latency | Aggregation completeness, system availability | PLOSHA, FedDQN, FT-Workflow, FT-Serverless |
| 4 | Aggregation-Loss Exposure | Number of micro-slots (1–20) | Loss exposure fraction | — | PLOSHA, Robust IIoT, FT-Workflow, FT-Serverless |
| 5 | Recovery Communication | Number of incomplete micro-slots | Communication overhead (KB) | — | PLOSHA, FT-Workflow, FT-Serverless |
| 6 | AFLTO Ablation | AFLTO enabled vs. disabled | Aggregation completeness | System availability | PLOSHA only |
| 7 | Workload Imbalance under Heterogeneous Capability | Fog-node heterogeneity ratio (1×–10×, strongest:weakest capacity) | Workload imbalance (capacity-normalized $I_W$) | Scheduling latency | PLOSHA only (internal: static assignment vs. capacity-aware scheduling) |

**Heterogeneous fog capability (Experiments 2 and 7).** The paper specifies that fog nodes differ in *processing capacity, queue occupancy, and communication latency*. Both experiments now model all three: per-node queue capacity is spread linearly so the strongest node is `r` times the weakest **while total system capacity is held constant** (a heterogeneous run must not simply have more or less aggregate capacity than a homogeneous one); processing-latency headroom scales inversely with capacity; and per-node communication latency is spread over the same ratio but indexed by a **deterministic permutation of the node id**, so it is *not* collinear with capacity — otherwise the fastest node would always also be the closest and the two dimensions could not be told apart. Communication latency is added to processing latency when forming $L_i$, so the existing scheduling utility $U_j$ consumes it with no change to its weights. Experiment 2 fixes `r = 4` (the paper states the condition but no ratio; 4× is our choice). Ref[22] and Ref[38] already randomise per-node capability, so all four schemes face heterogeneous nodes.

**What "scheduling efficiency" means (Experiment 2).** Efficiency is *how well* the scheduler distributes work across heterogeneous nodes, **not** how fast it makes a decision. The primary metric is therefore **workload imbalance** $I_W$: a scheduler that decides in nanoseconds but piles load onto the weakest node is not efficient. Imbalance is measured **capacity-normalized** — $W_i$ is a node's share of load divided by its share of capacity, so $I_W = 0$ means load allocated exactly in proportion to capability, and an equal split across *unequal* nodes is **not** balanced. Decision latency is reported as a secondary property. For the metric to mean anything the scheduler must actually route traffic, so Experiment 2 sets `apply_scheduling_decision = true`, applying PLOSHA's capacity-aware selection to sensor placement instead of computing and discarding it.

**Why Experiment 7 exists separately.** Experiment 2 fixes the heterogeneity ratio at 5× and varies the fleet size. Experiment 7 does the opposite: it fixes the fleet at 20 nodes and **sweeps the heterogeneity ratio from 1× to 10×**, isolating how the advantage scales with the degree of capability spread, and contrasting capacity-aware scheduling against a static-assignment control within PLOSHA.

A supplementary `exp3_workload_intensity/` sweep (sensor reporting rate vs. aggregation latency, queue utilization, recovery frequency) also exists for several schemes outside this paper-narrated set; it predates the current numbering and is not one of the six experiments described in the paper text.

## Rules

- **Input**: All schemes read IIoT task data from `dataset/plosha_dataset.csv (Kaggle Smart Manufacturing Dataset with Jitter)`.
- **Output**: Each experiment folder must produce a `results.csv` in a standardized format.
- **Plotting**: The central `plots/generate_plots.py` script collects `results.csv` files from all `schemes/*/exp<N>_*/` folders and generates comparison graphs into `plots/output/`.

### Output CSV Format

Every `results.csv` must follow this format so that the plotting script can automatically aggregate results across schemes:

```csv
variable_value,primary_metric,secondary_metric_1,secondary_metric_2
500,12.3,,
1000,18.7,,
2000,31.2,,
```

- `variable_value` — The independent variable for that experiment (e.g., number of sensors, failure rate percentage).
- `primary_metric` — The primary measured result (e.g., latency in ms, loss fraction, KB transferred).
- `secondary_metric_*` — Optional secondary metrics where applicable (e.g., queue utilization, availability). Leave blank if not measured.

## Collaboration Guide

This repository is designed for parallel teamwork. Each collaborator is responsible for one or more scheme folders.

1. **Clone the repo** and work only inside your assigned `schemes/<your_scheme>/` folder.
2. **Implement your scheme's simulation** inside your `src/` directory.
3. **Run each relevant experiment** and output a `results.csv` into the corresponding `exp<N>_*/` folder.
4. **Do not modify** `dataset/`, `plots/`, or other team members' scheme folders.
5. Once all schemes have produced their results, run the plotting script to generate the final comparison graphs.

## Critical Constraints — What NOT To Do

> These rules apply to all contributors, including AI coding agents.

### Do NOT bias or fabricate results
- **Do NOT hardcode, precompute, or fabricate benchmark results** to match the figures in the PLOSHA paper. The paper's experimental results are theoretical projections — not ground truth.
- **Do NOT adjust simulation parameters** (e.g., timing offsets, artificial delays, scaling factors) to force a specific scheme to appear faster or slower than it actually is.
- All `results.csv` files must contain **real measurements** from actual execution of the simulation code.

### Do NOT break the directory structure
- **Do NOT rename, move, or restructure** the `schemes/`, `dataset/`, or `plots/` directories. The plotting script depends on this exact layout.
- **Do NOT create experiment folders** that are not defined in the Experiment Definitions table above. If a scheme does not participate in an experiment, it should not have that `exp<N>_*/` folder.
- **Do NOT place source code** directly in experiment folders. Source code belongs in `src/`; experiment folders contain only configuration and output (`results.csv`).

### Do NOT cross-contaminate schemes
- **Do NOT copy implementation logic** from one scheme folder into another. Each scheme must be an independent, faithful implementation of the approach described in its reference paper.
- **Do NOT share runtime state or intermediate data** between scheme simulations. Each scheme reads only from `dataset/plosha_dataset.csv (Kaggle Smart Manufacturing Dataset with Jitter)` and writes only to its own `results.csv`.

### Do NOT modify shared resources without approval
- **Do NOT modify `dataset/plosha_dataset.csv (Kaggle Smart Manufacturing Dataset with Jitter)`** — this is the single source of truth for all schemes.
- **Do NOT modify `plots/generate_plots.py`** without explicit approval — changes affect every scheme's visualization.
- **Do NOT modify `README.md`** rules or experiment definitions without team consensus.

### Do NOT skip the simulation
- **Do NOT generate results analytically or mathematically** (e.g., computing expected latency from formulas in the paper) instead of running the discrete-event simulation. The entire purpose of this benchmark is to measure real execution behavior, not to recompute theoretical values.

## Running the Full Benchmark

To fully run the benchmark across all implemented schemes and generate the final comparison graphs, you can use the automated bash script, or run them manually.

### Using the Automated Runner (Recommended)

A central runner script is provided in the repository root to automate compiling, running all schemes (including setting up Gramine SGX for PLOSHA), and generating plots.

Make sure the script has executable permissions and run it:
```bash
chmod +x run_benchmark.sh
./run_benchmark.sh
```

### Running Manually

If you prefer to run the benchmark manually step-by-step:

#### 1. Execute Each Scheme
For each scheme, navigate to its `src/` directory, compile the code, and run all experiments. Ensure the `--dataset` path correctly points to the shared `dataset/plosha_dataset.csv (Kaggle Smart Manufacturing Dataset with Jitter)`.

**Example for PLOSHA-RMFR (runs inside real Intel SGX enclave):**
```bash
cd schemes/plosha_rmfr/src
make clean && make
gramine-manifest --no-check -Dlog_level=error \
  -Ddataset_dir="../../dataset" \
  -Doutput_dir=".." \
  plosha_rmfr.manifest.template plosha_rmfr.manifest
# Note: If you don't have an SGX key yet, run 'gramine-sgx-gen-private-key' first
gramine-sgx-sign --manifest plosha_rmfr.manifest --output plosha_rmfr.manifest.sgx
gramine-sgx plosha_rmfr --experiment all --epochs 10 --dataset /dataset/plosha_dataset.csv (Kaggle Smart Manufacturing Dataset with Jitter) --output /output
```

**Example for other baseline schemes (e.g., Ref[37]):**
```bash
cd schemes/fault_tolerant_workflow/src
make clean && make
./ftworkflow --experiment all --dataset ../../../dataset/plosha_dataset.csv (Kaggle Smart Manufacturing Dataset with Jitter)
```

*(Repeat this process for `robust_iiot`, `fed_dqn`, and `ft_serverless_edge` using their respective executable names).*

### 2. Generate the Plots
Once all schemes have successfully generated their `results.csv` files in their respective `exp<N>_*/` directories, you can generate the final visual comparison graphs.

First, ensure you have the required Python dependencies installed. If you encounter an `externally-managed-environment` error, you can safely use the `--break-system-packages` flag:
```bash
cd plots
pip install pandas matplotlib --break-system-packages
```

Then, run the plotting script:
```bash
python3 generate_plots.py
```

### 3. View the Results
The final graphs comparing all the executed schemes will be saved in the `plots/output/` directory as PNG files (e.g., `graph1_sensor_scalability_latency.png`).
