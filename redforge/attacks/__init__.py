"""RedForge Multi-Turn Attack Orchestration.

Implements advanced multi-turn attack strategies inspired by:
- PyRIT (Microsoft): Crescendo, Skeleton Key
- PAIR (Chao et al.): Prompt Automatic Iterative Refinement
- AutoDAN / GCG: Gradient-based and generative attack strategies

These attacks use iterative conversation to gradually escalate attacks
that would fail in a single turn.
"""

from __future__ import annotations

from redforge.attacks.crescendo import CrescendoAttack
from redforge.attacks.multi_turn import ConversationTurn, MultiTurnOrchestrator
from redforge.attacks.pair import PAIR_GOALS, PAIRAttack, run_pair_attack
from redforge.attacks.skeleton_key import SkeletonKeyAttack

__all__ = [
    "CrescendoAttack",
    "SkeletonKeyAttack",
    "MultiTurnOrchestrator",
    "ConversationTurn",
    "PAIRAttack",
    "run_pair_attack",
    "PAIR_GOALS",
]
