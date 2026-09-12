"""Multilevel access (MLA) policy — Scheme 30 §V-A.

    "Our MLA policy requires that a user with access level a(u) is authorized
     to get only for files with level a(id) <= a(u), where a is an access
     level mapping function."

Levels are 1-based, matching the paper: level ``|L|`` is the HIGHEST (sees
everything), level 1 the lowest. Scheme 30 §VII-A: "We classified data users and
files into three levels, where level 3 is the highest and level 1 is the
lowest."

WHY THIS FILE EXISTS AT ALL
---------------------------
The paper never says how it assigned access levels to its Wikipedia corpus
(``References/Ref[55]/Ref[55].md`` §5 item 4 records this gap). Our Synthea
corpus carries no level attribute either — ``Record`` has rid/pid/vid/dom/ts/kw
and nothing about sensitivity. So the mapping ``a(id)`` is a benchmark decision,
declared in crypto.yaml as ``yue_ge.level_assignment: pid_hash``.

The choice: derive the level deterministically from the record's pseudonymous
patient identifier. Three properties matter, and this is the cheapest thing that
has all three.

  1. **Deterministic** — the same record gets the same level on every run and on
     every machine, so results are reproducible without storing a level map.
  2. **Balanced** — SHA-256 output is uniform, so the three levels get ~1/3 of
     records each. An unbalanced split would silently change search cost, since
     Peony's search returns everything at or below the querying level.
  3. **Patient-stable** — keying on ``pid`` rather than ``rid`` puts all of one
     patient's records at one level. That is the realistic shape for an EHR
     (sensitivity attaches to the patient, not to the individual observation),
     and it means a level-1 user sees whole patients rather than a random third
     of every patient's chart.

This is NOT a claim about what Ge et al. did. It is a documented, reproducible
stand-in for something the paper leaves undefined.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence

from Common.crypto.hashes import sha256


def assign_level(pid: str, access_levels: int) -> int:
    """Map a pseudonymous patient id to an access level in ``[1, access_levels]``.

    Deterministic and uniform. Level ``access_levels`` is the highest.
    """
    if access_levels <= 0:
        raise ValueError(f"access_levels must be positive, got {access_levels}")
    digest = sha256(pid.encode("utf-8"), domain=b"yue_ge/level")
    return (int.from_bytes(digest[:8], "big") % access_levels) + 1


def user_can_access(user_level: int, file_level: int) -> bool:
    """MLA policy: ``a(id) <= a(u)`` — Scheme 30 §V-A."""
    return file_level <= user_level


def visible_levels(user_level: int) -> List[int]:
    """Every file level a user at ``user_level`` may retrieve."""
    return list(range(1, user_level + 1))


def levels_to_update_on_delete(file_level: int, access_levels: int) -> List[int]:
    """Levels whose Bloom filter must be touched when deleting a file.

    Scheme 30 §IV-B (MSRE.Comp): "the entries of B_{R_xi} (level xi > level l)
    indexed by H_i(t_j) ... are also need to be set to 1".

    And §VII-B, concretely: "when deleting level 1 files for keyword w, it is
    necessary to simultaneously update the level 1 array B_{w,1}, the level 2
    array B_{w,2}, and the level 3 array B_{w,3}."

    So deletion propagates UPWARD: a file at level ``l`` is visible to every
    user at level ``l`` or above, and each of those users holds their own
    revocation filter, so all of them must learn about the deletion. This is
    exactly why the paper's Table VII shows deleting level-1 files costing the
    most (3 filters) and level-3 files the least (1 filter).
    """
    return list(range(file_level, access_levels + 1))


def level_histogram(pids: Iterable[str], access_levels: int) -> Dict[int, int]:
    """Count records per level — used by the runners to report corpus balance."""
    hist: Dict[int, int] = {lvl: 0 for lvl in range(1, access_levels + 1)}
    for pid in pids:
        hist[assign_level(pid, access_levels)] += 1
    return hist


def sort_descending_by_level(
    entries: Sequence[tuple], level_of: Dict[int, int]
) -> List[tuple]:
    """Sort ``(id, op)`` entries in DESCENDING access-level order.

    Scheme 30 Algorithm 1, ListGen line 3: "Sort id_j in D_w in descending order
    using a(id_j)". The order is load-bearing, not cosmetic — the linked list
    is walked from the highest level downward, so a user entering at their own
    level reaches exactly the files at or below it and stops. Ties are broken by
    id so the list is deterministic.
    """
    return sorted(entries, key=lambda e: (-level_of[e[0]], e[0]))
