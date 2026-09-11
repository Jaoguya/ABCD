"""Instrument the Exp.7/8 scheduling path. Diagnosis only -- nothing here is reportable."""
import sys, time, collections, statistics
sys.path.insert(0, '/Users/puumax/OJCOMS')

from Schemes.ma_lb_pq_vdse.src.harness import experiments as E
from Schemes.ma_lb_pq_vdse.src import config as C
from Schemes.ma_lb_pq_vdse.src.scheduler import aass as A

cfg = C.load()
exp = E.Exp7Throughput(config=cfg, source=E.SyntheticRecordSource())
CONC = 500
prepared = exp.prepare(CONC)
dep, reqs = prepared['deployment'], prepared['requests']

print(f"nodes (in deployment order): {[ (n.node_id, sorted(n.domains)) for n in dep.nodes ]}")
print(f"requests materialised: {len(reqs)} (concurrency={CONC})")

first_tok, first_dec = reqs[0]
r0 = A.SearchRequest(tokens=first_tok.tokens, authorized=first_dec.authorized_shards, vid_u=first_tok.vid_u)
print(f"request.domains       = {r0.domains}")
print(f"request.domains[0]    = {r0.domains[0]!r}   <- the 'forward' reference point")
print(f"candidates per request= {len([n for n in dep.nodes if set(r0.domains) & set(n.domains)])}")

# ---- A: is the queue ever non-empty, and is C_queue degenerate? ----------
print("\n--- A. queue state observed by the scheduler ---")
qlens, qwaits, queue_raw_spreads = set(), set(), set()
for tok, dec in reqs[:200]:
    req = A.SearchRequest(tokens=tok.tokens, authorized=dec.authorized_shards, vid_u=tok.vid_u)
    for n in dep.nodes:
        qlens.add(n.queue_length); qwaits.add(n.queue_wait_ns())
    raw = [A.estimate_costs(n, req) for n in dep.nodes]
    queue_raw_spreads.add(round(max(v.queue for v in raw) - min(v.queue for v in raw), 9))
    norm = A.normalize(raw, degenerate_value=cfg.scheduler.degenerate_term_value,
                       epsilon=cfg.scheduler.epsilon)
    queue_norm = {round(v.queue, 9) for v in norm}
print(f"distinct node.queue_length seen : {sorted(qlens)}")
print(f"distinct node.queue_wait_ns seen: {sorted(qwaits)}")
print(f"raw C_queue spread across nodes : {sorted(queue_raw_spreads)}")
print(f"normalized C_queue values       : {sorted(queue_norm)}  -> lambda_5 weight {cfg.scheduler.weights.queue} applies to this")

# ---- B: which node does each variant actually pick? ---------------------
print("\n--- B. node-selection histogram per variant ---")
for variant in A.VARIANTS:
    sched = A.Scheduler(variant, config=cfg, reportable=False)
    hist = collections.Counter()
    fwd = 0
    for tok, dec in reqs:
        req = A.SearchRequest(tokens=tok.tokens, authorized=dec.authorized_shards, vid_u=tok.vid_u)
        sel = sched.select(dep.nodes, req)
        hist[sel.node.node_id] += 1
        if not sel.node.serves_domain(req.domains[0]):
            fwd += 1
    spread = f"{len(hist)} distinct node(s)"
    print(f"{variant:<13} {dict(sorted(hist.items()))}   {spread:<18} cross_node_forwards={fwd} ({fwd/len(reqs):.0%})")

# ---- C: parent dispatch cost vs worker service cost --------------------
print("\n--- C. where the wall clock goes ---")
sched = A.Scheduler('aass', config=cfg, reportable=False)
t0 = time.perf_counter_ns()
sels = []
for tok, dec in reqs:
    req = A.SearchRequest(tokens=tok.tokens, authorized=dec.authorized_shards, vid_u=tok.vid_u)
    sels.append(sched.select(dep.nodes, req))
sched_ns = time.perf_counter_ns() - t0

from Schemes.ma_lb_pq_vdse.src.fsn import search as S
svc = []
for (tok, dec), sel in zip(reqs, sels):
    t = time.perf_counter_ns()
    try:
        S.execute_search(sel.node, tok.tokens, dec.authorized_shards, record_service=False)
    except S.SearchRejected:
        continue
    svc.append(time.perf_counter_ns() - t)
print(f"scheduler.select      : {sched_ns/len(reqs)/1000:8.1f} us/query")
print(f"execute_search        : {statistics.mean(svc)/1000:8.1f} us/query (p95 {sorted(svc)[int(len(svc)*.95)]/1000:.1f} us)")
print(f"ratio select:search   : {sched_ns/sum(svc):8.2f}x")
