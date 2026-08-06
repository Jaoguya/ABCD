"""AND/OR gate access tree — Ref[52] §II.B.

The access structure τ is a tree whose leaf nodes correspond to attributes
and whose internal nodes are AND or OR gates.  During encryption the root
receives a value ``r`` and shares are assigned top-down:

    AND gate:  children receive additive shares summing to ``r`` (mod q).
    OR  gate:  every child receives ``r`` itself.

Default experiment policy: AND-only over all ``l`` attributes, matching the
computation-cost formula in Table VI ("when τ is constructed by only AND
gates").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

import numpy as np


class GateType(Enum):
    AND = "AND"
    OR = "OR"


@dataclass
class TreeNode:
    """One node in the access tree.

    Leaves have ``attribute`` set and ``gate=None``.
    Internal nodes have ``gate`` set and children populated.
    ``value`` is assigned during share distribution (Encrypt step 5).
    """

    gate: Optional[GateType] = None
    attribute: Optional[int] = None
    children: List["TreeNode"] = field(default_factory=list)
    value: int = 0


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------
def make_and_policy(attribute_ids: List[int]) -> TreeNode:
    """Create an AND-gate root over the given attributes.

    All attributes are required — the standard benchmark policy.
    """
    root = TreeNode(gate=GateType.AND)
    for attr_id in sorted(attribute_ids):
        root.children.append(TreeNode(attribute=attr_id))
    return root


def make_or_policy(attribute_ids: List[int]) -> TreeNode:
    """Create an OR-gate root — any one attribute suffices."""
    root = TreeNode(gate=GateType.OR)
    for attr_id in sorted(attribute_ids):
        root.children.append(TreeNode(attribute=attr_id))
    return root


# ---------------------------------------------------------------------------
# Share assignment — §III.F step 5
# ---------------------------------------------------------------------------
def assign_shares(
    tree: TreeNode,
    root_value: int,
    q: int,
    *,
    rng: Optional[np.random.Generator] = None,
) -> None:
    """Assign shares top-down from ``root_value`` through the tree.

    Modifies ``tree.value`` (and children recursively) in place.
    """
    rng = rng or np.random.default_rng()
    tree.value = int(root_value) % q

    if tree.gate is None:
        # Leaf — nothing to propagate.
        return

    if tree.gate == GateType.AND:
        # Additive shares: r_1, ..., r_{t-1} random, r_t = r - Σ r_i.
        n_children = len(tree.children)
        random_shares = rng.integers(0, q, size=n_children - 1, dtype=np.int64)
        last_share = (tree.value - int(np.sum(random_shares))) % q
        shares = list(random_shares) + [last_share]
        for child, share in zip(tree.children, shares):
            assign_shares(child, int(share), q, rng=rng)

    elif tree.gate == GateType.OR:
        # Every child receives the full value.
        for child in tree.children:
            assign_shares(child, tree.value, q, rng=rng)


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------
def get_leaf_shares(tree: TreeNode) -> Dict[int, int]:
    """Return ``{attribute_id: share_value}`` for all leaves."""
    result: Dict[int, int] = {}
    if tree.gate is None:
        if tree.attribute is not None:
            result[tree.attribute] = tree.value
    else:
        for child in tree.children:
            result.update(get_leaf_shares(child))
    return result


def get_attributes(tree: TreeNode) -> Set[int]:
    """Return the set of all attribute IDs referenced by the tree."""
    if tree.gate is None:
        return {tree.attribute} if tree.attribute is not None else set()
    attrs: Set[int] = set()
    for child in tree.children:
        attrs |= get_attributes(child)
    return attrs


def check_satisfaction(tree: TreeNode, user_attributes: Set[int]) -> bool:
    """Check whether ``user_attributes`` satisfy the access policy."""
    if tree.gate is None:
        return tree.attribute in user_attributes
    if tree.gate == GateType.AND:
        return all(check_satisfaction(c, user_attributes) for c in tree.children)
    # OR
    return any(check_satisfaction(c, user_attributes) for c in tree.children)
