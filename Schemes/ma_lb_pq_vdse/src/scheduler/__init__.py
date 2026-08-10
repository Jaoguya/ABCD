"""Phase VI — Adaptive Authorization-Aware Search Scheduling (AASS).

``aass.py`` implements Step 3's cost model and Alg. 1's selection rule, plus the
three authorization-oblivious variants Exp. 7-8 ablates against.

The scheduler is implementable, but Exp. 7-8 cannot be *reported* until
lambda_1..lambda_5 are fixed by the documented hold-out sweep: a Scheduler built
with ``reportable=True`` raises while ``scheduler.yaml`` says ``pending_sweep``
(README §14 issue #5).
"""
