"""Authorization Index Manager — the off-chain authorization registry.

Phase II Step 4 synchronizes ``Meta_i = (Dom_i, VID_i, C_i^auth)`` across the
cloud--fog infrastructure. The AIM also filters unauthorized index shards before
search (Phase VI Step 2) and drives incremental synchronization (Phase VII
Steps 5-6), so the registry built here is what those phases read.
"""
