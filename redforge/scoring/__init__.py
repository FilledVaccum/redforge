"""RedForge Scoring Module.

Provides scoring mechanisms beyond the built-in probe score() method:
- LLMJudgeScorer: use a second LLM to evaluate response harmfulness
- RubricScorer: evaluate against a defined rubric
"""

from __future__ import annotations

from redforge.scoring.judge import JudgeVerdict, LLMJudgeScorer

__all__ = ["LLMJudgeScorer", "JudgeVerdict"]
