"""Dataset preparation for the MA-LB-PQ-VDSE benchmark.

``prepare_dataset.py`` derives the searchable corpus from a Synthea CSV
export (the reportable corpus); ``synthetic_generator.py`` produces a
statistically-matched development corpus for pipeline smoke tests, which is
NOT reportable. Both emit the same format via ``corpus.py``, so no scheme
can tell which one it is reading — the manifest's ``corpus_type`` is what
distinguishes them.
"""
