"""Phase I (System Initialization) and Phase II (Multi-Authority Registration).

``initializer.py`` holds the system-wide steps — Phase I Step 1 (the primitive
set P and the bilinear group) and Step 3 (assembling and publishing PP).
``authority.py`` will hold the per-authority steps: Phase I Step 2's
``Setup(1^lambda)`` and Phase II Steps 1-3, ending in the authorization-state
commitment ``C_i^auth``.
"""
