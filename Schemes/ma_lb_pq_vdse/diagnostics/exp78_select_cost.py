import sys, time, statistics
sys.path.insert(0, '/Users/puumax/ABCD')
from Schemes.ma_lb_pq_vdse.src.harness import experiments as E
from Schemes.ma_lb_pq_vdse.src import config as C
from Schemes.ma_lb_pq_vdse.src.scheduler import aass as A

cfg = C.load()
exp = E.Exp7Throughput(config=cfg, source=E.SyntheticRecordSource())
prepared = exp.prepare(500)
dep, reqs = prepared['deployment'], prepared['requests']
rs = [A.SearchRequest(tokens=t.tokens, authorized=d.authorized_shards, vid_u=t.vid_u) for t, d in reqs]

def bench(fn, label, n=len(rs)):
    t = time.perf_counter_ns()
    for r in rs: fn(r)
    per = (time.perf_counter_ns() - t) / n / 1000
    print(f"  {label:<34} {per:7.2f} us/query")
    return per

print("cost breakdown of one scheduler.select() over 4 nodes:")
bench(lambda r: [A.estimate_candidate_count(n, r) for n in dep.nodes], "C_index  (bitmap union + popcount)")
bench(lambda r: [A.estimate_result_count(n, r) for n in dep.nodes],    "C_verify (shortest posting list)")
bench(lambda r: [A.synchronized_version(n, r) for n in dep.nodes],     "C_sync   (vid_for_domains)")
bench(lambda r: [n.queue_wait_ns() for n in dep.nodes],                "C_queue  (always 0)")
bench(lambda r: [A.estimate_costs(n, r) for n in dep.nodes],           "estimate_costs (all five)")
sched = A.Scheduler('aass', config=cfg, reportable=False)
bench(lambda r: sched.select(dep.nodes, r),                            "full select()")

# shard size, to show C_index is O(shard) not O(1)
n0 = dep.nodes[0]
print(f"\nshard size on FSN1: entry_count={n0.entry_count}, "
      f"authorized_bitmap len={len(n0.index.authorized_bitmap(rs[0].authorized))} bits")
