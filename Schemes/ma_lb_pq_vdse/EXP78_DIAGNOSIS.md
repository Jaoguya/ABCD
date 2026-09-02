# Exp. 7-8 scheduler ablation — diagnosis (2026-08-30)

**Status: the four-way ablation as it stands does not test the §V claim.** The
numbers harvested on 2026-08-29 (`exp{6,7,8}_*__{no_lb,round_robin,least_loaded,aass}/`)
should not be plotted or reported. The claim is not refuted — it is untested.

Reproduce with `diagnostics/exp78_scheduling_path.py` and
`diagnostics/exp78_select_cost.py` (run under `~/.venv-malbpq`, from the repo root).
Both are diagnosis-only: they run on the Mac dev host and nothing they print is reportable.

## What was harvested

Exp. 7 throughput (q/s, higher better) / Exp. 8 utilization stddev (lower better):

| concurrency | no_lb | round_robin | least_loaded | aass |
|---|---|---|---|---|
| 100  | 6880 / 0.147 | 7993 / 0.022 | 8642 / 0.126 | 8892 / 0.078 |
| 1000 | 8570 / 0.167 | 11145 / 0.019 | 11771 / 0.126 | 11277 / 0.060 |
| 5000 | 8823 / 0.130 | 11377 / 0.016 | 12255 / 0.126 | 11816 / 0.061 |

Read naively: `least_loaded` beats AASS on throughput at 4 of 5 concurrencies and
`round_robin` is ~3.7x better on load balance at every point.

## Why those numbers are artifacts

### 1. The queue feedback loop is never populated (measured)

`FogSearchNode.enqueue()` / `.dequeue()` are called **only** from `src/tests/`.
Nothing in the Exp. 7/8 replay path enqueues anything. Measured over 200 requests
across 4 nodes:

```
distinct node.queue_length seen : [0]
distinct node.queue_wait_ns seen: [0]
raw C_queue spread across nodes : [0.0]
normalized C_queue values       : [0.0]
```

Consequences:

- **AASS's fifth published term is dead.** `C_j^queue` is identical on every node,
  so `normalize()` correctly maps it to the degenerate value 0. `lambda_5 = 0.1`
  is applied to a constant zero in every number we have. Four of the five
  published terms are doing all the work.
- **`least_loaded` is not a least-loaded arm.** Its key is
  `(node.queue_length, node.node_id)`; with `queue_length` permanently 0 it
  collapses to "always the lowest node_id". Measured selection histogram at
  concurrency 500:

```
no_lb         {'FSN1': 500}                                    1 distinct node
round_robin   {'FSN1': 125,'FSN2': 125,'FSN3': 125,'FSN4': 125} 4 distinct nodes
least_loaded  {'FSN1': 500}                                    1 distinct node
aass          {'FSN1': 375,'FSN2': 125}                        2 distinct nodes
```

`no_lb` and `least_loaded` make **byte-identical decisions**. They are one arm
reported twice.

### 2. The process boundary severs the loop anyway

`_replay_multiprocess` (`src/harness/experiments.py:1114`) calls
`scheduler.select(deployment.nodes, ...)` on the **parent's** node objects, while
`record_service()` accrues inside the forked workers. Even with `enqueue` wired
into the dispatch path, the parent could never observe worker load. Any real fix
has to send load back from the workers, not just enqueue locally.

### 3. The scheduler costs more than the search it schedules (measured)

Per query, over 4 candidate nodes:

```
C_index  (bitmap union + popcount)     1.97 us
C_verify (shortest posting list)       0.75 us
C_sync   (vid_for_domains)             3.79 us   <- largest single term
C_queue  (always 0)                    0.21 us
estimate_costs (all five)             10.88 us
full select()                         23.21 us
execute_search                         5.10 us
```

**`select()` is ~4.6x the cost of the `execute_search()` it is choosing a node
for.** This is precisely the ceiling `src/scheduler/aass.py`'s module docstring
sets out to respect ("A scheduler that searched in order to decide where to
search would cost as much as the search it was scheduling, and Exp. 7's
throughput would measure the scheduler"). Exp. 7's throughput *is* measuring the
scheduler. Roughly half the cost is outside `estimate_costs` — `normalize()` plus
one `CostVector`/`NodeCost` dataclass allocation per node per query.

Note the shard here is tiny (`entry_count=48`, 1024-bit bitmap) because
`prepare()` builds the deployment with `records=32`. On the real corpus `C_index`
is O(shard) and grows; the other terms do not. So the ratio above is a *floor*.

### 4. Nothing is ever saturated

Peak `max_node_utilization` across all arms is 0.30 (`no_lb`) and 0.18
(`round_robin`) — nodes are 70-90% idle. A load balancer cannot be ranked on a
system that is never loaded.

### 5. `cross_node_forwards` measures the wrong thing

`if not selection.node.serves_domain(request.domains[0])` compares the chosen
node against the **alphabetically first** authorized domain — an arbitrary
reference, not a forwarding event. Every request here is authorized for all four
domains (`request.domains == ('dom0','dom1','dom2','dom3')`), so the metric just
asks "did you pick the dom0 node?". That is why the harvested values are exactly
`0` for the two single-node arms, exactly `0.75 * N` for round_robin, and exactly
`N` for aass on the AWS corpus.

### 6. Exp. 6's four variant directories are one run repeated four times

`Exp6AuthorizationSync` has no `variant` field, so `build_experiment` drops the
argument — deliberately, per its own docstring (the scheduler plays no part in
propagating an authorization change). The observed spread across "variants"
(35.1-36.5 ms) is *larger* than each one's own CI (+/-0.4%), i.e. host drift that
would be plotted as a scheduling effect. Delete these four directories.

## Open question, needs the AWS host

Locally `no_lb` and `least_loaded` select identically (FSN1 x500), yet their
harvested distributions at concurrency 5000 are fully disjoint
(no_lb 7491-9807, least_loaded 10226-12629; n=30 each). Two candidate causes,
not distinguishable from the dev host:

- **(a)** On the real corpus `assign_domains_to_fsns` orders `deployment.nodes`
  differently from node_id order, so `candidates[0]` (no_lb) and
  `min(node_id)` (least_loaded) land on different-sized shards. Then the gap is
  shard size, still not scheduling.
- **(b)** They do select identically there too, and the 39% gap is host/pool
  state between the two runs — which would put Exp. 7's noise floor at ~39% and
  make the entire 8.8k-12.3k spread across all four arms meaningless.

Resolve by logging the selection histogram on the pinned m6i.xlarge before any
rerun. **(b) would be the more serious finding of the two.**

## What a fix has to do

1. Wire `enqueue`/`dequeue` into the dispatch path **and** report worker load back
   to the parent across the process boundary — otherwise `least_loaded` and
   `lambda_5` stay inert.
2. Offer enough load to actually saturate 4 FSNs (target max utilization near 1.0),
   or Exp. 8 has nothing to measure.
3. Get `select()` below the cost of `execute_search()` — cache the per-node
   `C_index` popcount and drop the per-query dataclass allocation — or Exp. 7
   keeps measuring the scheduler.
4. Replace `cross_node_forwards` with a real forwarding count, or drop the metric.
5. Delete the four `exp6_authorization_sync__*` directories.
6. Re-run the lambda sweep *after* 1-3. The current `weights.status: fixed`
   vector (0.2/0.4/0.1/0.2/0.1, determined 2026-08-28) was selected on this
   substrate, so `lambda_4` and `lambda_5` were chosen against a partly-dead signal.
