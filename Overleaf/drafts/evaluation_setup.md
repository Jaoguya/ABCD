### Experimental Setup

**Implementation and testbed.** The proposed framework and all baseline
schemes were implemented in Python 3.11 and evaluated on an Amazon EC2
`m6i.xlarge` instance (4 vCPUs, 16 GB RAM, Ubuntu 22.04) within a single
AWS Virtual Private Cloud and availability zone. Four Fog Search Nodes
(FSNs) and one cloud server were deployed as independent operating-system
processes, each FSN holding its own index shard, version identifier
$VID_j$, and request queue, with no runtime state shared between nodes.
Each FSN maintains authorization-aware searchable indexes and performs
encrypted search locally; the cloud server stores encrypted EHRs and
blockchain metadata. To prevent the linear-algebra workload of the
lattice baseline from acquiring an implicit multi-core advantage, BLAS
threading was pinned to a single thread (`OMP_NUM_THREADS`,
`OPENBLAS_NUM_THREADS`, `MKL_NUM_THREADS`, `NUMEXPR_NUM_THREADS`,
`VECLIB_MAXIMUM_THREADS`) for every scheme.

**Cryptographic instantiation.** The framework employs ML-KEM-768 for
post-quantum key establishment, AES-256-GCM for symmetric encryption,
SHA-256 for hashing and Merkle-tree construction, HMAC-SHA256 as the
keyword pseudorandom function, and a Type-III bilinear pairing
$e : \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T$ over
BN254 for the multi-authority CP-ABE layer. Authorization commitments
and audit records are maintained on Hyperledger Fabric v2.5. The
multi-authority topology comprises $N_{AA} = 4$ attribute authorities in
one-to-one correspondence with the four administrative domains, each
governing a disjoint universe of $|A_i| = 10$ attributes.

**Dataset.** Experiments use a corpus derived from Synthea (MITRE,
commit `7e08387`), an epidemiologically grounded synthetic patient
generator, instantiated with 38,000 patients under a fixed patient and
clinician seed. One derived record corresponds to one clinical
encounter. The frozen corpus contains 1,141,072 records over a
vocabulary of 2,006 distinct keywords, yielding 36,172,487
keyword–document pairs; per-record keyword-set sizes $|W_i|$ have
minimum, median, and mean of 5, 29, and 31.70 respectively, and the
fitted Zipf exponent is 2.7078. Records are partitioned into exactly
285,268 per administrative domain, satisfying the uniform cross-domain
distribution assumed throughout. A minimum of five keywords per record
is enforced so that no record is structurally unmatchable at the default
query size. The corpus is pinned by SHA-256 and verified at load, and
its digest is recorded in the provenance record of every run, so that
any figure in this paper can be traced to the exact corpus that produced
it.

Synthea was selected in preference to a de-identified clinical archive
for three reasons that bear directly on reproducibility. First, the
largest such archive available to us caps at 546,028 hospitalizations,
short of the $10^6$ index size the search-scalability experiment
requires. Second, it is retrospective inpatient EHR data rather than the
IoMT telemetry this framework targets. Third, its data use agreement
forbids redistributing the derived corpus, so no reviewer could
reconstruct the exact index underlying our measurements. A seeded
synthetic generator removes all three obstacles at the cost of clinical
provenance, which none of the measured quantities depend on.

**Default parameters.** Unless otherwise specified, each query contains
five keywords ($q = 5$), records are distributed across $d = 4$
administrative domains served by $m = 4$ FSNs, the searchable index
holds $N = 10^5$ records, and result verification is performed over 100
returned records. Each experiment varies exactly one parameter and holds
all others at these defaults. No parameter is tuned per scheme: every
scheme is measured under identical global defaults.

**Measurement methodology.** Each reported point is the mean of 30
independent runs with 95% confidence intervals. Five additional warm-up
runs precede each point and are discarded. Latency is measured with a
monotonic nanosecond clock (`perf_counter_ns`) and throughput with
elapsed wall-clock time; Experiments 1--6 are measured in a warm-cache
state, while Experiments 7--8 replay a recorded arrival trace after a
30-second ramp that is excluded from all reported metrics. Outliers are
retained rather than filtered; a run that fails is recorded as such and
re-executed to restore $n = 30$, and is never silently dropped. Every
run emits a provenance record capturing the source commit, the SHA-256
of each configuration file, the corpus digest, and the host environment.

**Baselines and fidelity.** The proposed framework is compared with
three representative schemes: Guo *et al.* [@ref35] (verifiable dynamic
searchable encryption), Thingom *et al.* [@ref41] (multi-authority
attribute-based searchable encryption over a Type-I SS512 pairing), and
Zhuang *et al.* [@ref52] (lattice-based post-quantum searchable
encryption with $n = 284$, $m = 13812$, $q = 2^{24}$, $\sigma = 4.0$,
and $l = 10$ attributes). Coverage differs by construction: Guo *et al.*
participates in Experiments 1--5, Thingom *et al.* in Experiments 1--3,
and Zhuang *et al.* in Experiments 1--3, 5, and 6. XB-Muse [@ref36] was
excluded because part of its algorithm executes inside an Intel SGX
enclave, which the benchmark instance does not expose; simulating the
enclave would omit enclave-transition and EPC-paging overhead and report
the baseline as faster than any real deployment, while relocating it to
SGX-capable hardware would break the requirement that every scheme is
measured on identical hardware. The exclusion reflects a hardware
constraint, not an unfavourable result.

Each baseline is implemented faithfully to its published construction,
and deliberately without optimizations that its own cost analysis does
not claim. In particular, batching the $2u$ pairings of Thingom *et al.*
into a multi-Miller product with a shared final exponentiation would
reduce its measured search cost by a substantial margin, but would
report that scheme as faster than its published operation counts; it is
therefore not applied. Symmetrically, no baseline is charged for work
its paper does not specify.
