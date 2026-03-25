"""RedForge Attack Mutation Engine.

Generates mutated variants of attack payloads to increase coverage and
bypass pattern-matching defenses.  Inspired by FuzzyAI's mutation approach.

Mutation strategies:
- Encoding (base64, hex, ROT13, URL encoding)
- Case variation (upper, lower, mixed, leet-speak)
- Whitespace injection (zero-width chars, extra spaces)
- Synonym substitution (replace key words with synonyms)
- Reframing (add fictional/academic/hypothetical wrapper)
- Typo injection (intentional misspellings)
- Character substitution (homoglyphs, lookalikes)
"""

from __future__ import annotations

from redforge.mutations.engine import MutationEngine, MutationResult, MutationStrategy

__all__ = ["MutationEngine", "MutationResult", "MutationStrategy"]
