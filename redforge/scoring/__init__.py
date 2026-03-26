"""RedForge Scoring Module.

Provides two types of scoring beyond basic probe logic:

1. Composable Scorers (scorers.py)
   Building blocks for probe.score() methods:
   - RefusalScorer  — fires on model refusal signals
   - KeywordScorer  — fires on explicit success marker keywords
   - RegexScorer    — fires on regex pattern match
   - LengthScorer   — fires based on response length
   - NotScorer      — inverts another scorer
   - ScorerChain    — first-match or weighted-average composition

2. LLM-as-Judge (judge.py)
   Uses a second LLM to evaluate whether a response is harmful:
   - LLMJudgeScorer — async judge evaluation with structured rubric
   - JudgeVerdict   — verdict dataclass (score, rationale, confidence)
"""

from __future__ import annotations

from redforge.scoring.judge import JudgeVerdict, LLMJudgeScorer
from redforge.scoring.scorers import (
    BaseScorer,
    KeywordScorer,
    LengthScorer,
    NotScorer,
    RefusalScorer,
    RegexScorer,
    ScorerChain,
    ScoreResult,
    build_scorer_from_config,
)

__all__ = [
    # Judge
    "LLMJudgeScorer",
    "JudgeVerdict",
    # Composable scorers
    "ScoreResult",
    "BaseScorer",
    "RefusalScorer",
    "KeywordScorer",
    "RegexScorer",
    "LengthScorer",
    "NotScorer",
    "ScorerChain",
    "build_scorer_from_config",
]
