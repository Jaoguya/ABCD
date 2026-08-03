"""Dataset preparation for the MA-LB-PQ-VDSE benchmark.

``prepare_dataset.py`` derives the searchable corpus from a local MIMIC-IV
v3.1 copy; ``synthetic_generator.py`` produces a statistically-matched
development corpus for collaborators without credentials. Both emit the same
format via ``corpus.py``, so no scheme can tell which one it is reading.

Nothing in ``derived/`` may be committed (README §14).
"""
