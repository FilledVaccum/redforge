"""Multi-turn conversation attack base infrastructure.

Provides the base classes and orchestration logic for running multi-turn
attacks against LLM systems.  Single-turn probes test one payload at a time;
multi-turn attacks build up context across multiple exchanges to gradually
overcome safety filters.
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.adapters.base import BaseAdapter


@dataclass
class ConversationTurn:
    """A single turn in a multi-turn attack conversation."""

    role: str          # "user" or "assistant"
    content: str
    turn_number: int
    attack_phase: str  # e.g. "warmup", "escalation", "extraction"


@dataclass
class MultiTurnResult:
    """Result of a complete multi-turn attack sequence."""

    attack_name: str
    goal: str
    turns: list[ConversationTurn] = field(default_factory=list)
    succeeded: bool = False
    final_score: float = 0.0
    evidence: str = ""
    total_turns: int = 0

    @property
    def conversation_history(self) -> list[dict[str, str]]:
        """Return turns as a list of role/content dicts."""
        return [{"role": t.role, "content": t.content} for t in self.turns]


class MultiTurnOrchestrator:
    """Orchestrates multi-turn attacks against an LLM adapter.

    Usage:
        orchestrator = MultiTurnOrchestrator(adapter)
        attack = CrescendoAttack(goal="explain how to pick a lock")
        result = await orchestrator.run(attack)
    """

    def __init__(
        self,
        adapter: BaseAdapter,
        max_turns: int = 10,
        success_threshold: float = 0.7,
    ) -> None:
        self.adapter = adapter
        self.max_turns = max_turns
        self.success_threshold = success_threshold

    async def run(self, attack: BaseMultiTurnAttack) -> MultiTurnResult:
        """Execute a multi-turn attack and return the result."""
        result = MultiTurnResult(
            attack_name=attack.name,
            goal=attack.goal,
        )
        history: list[dict[str, str]] = []
        turn_number = 0

        for phase, user_message in attack.generate_turns(history):
            turn_number += 1
            if turn_number > self.max_turns:
                break

            # Record user turn
            result.turns.append(ConversationTurn(
                role="user",
                content=user_message,
                turn_number=turn_number,
                attack_phase=phase,
            ))

            history.append({"role": "user", "content": user_message})

            # Send to model
            try:
                response = await self.adapter.send(history)
                assistant_content = response.content
            except Exception as exc:  # noqa: BLE001
                result.evidence = f"Adapter error at turn {turn_number}: {exc}"
                break

            history.append({"role": "assistant", "content": assistant_content})

            # Record assistant turn
            result.turns.append(ConversationTurn(
                role="assistant",
                content=assistant_content,
                turn_number=turn_number,
                attack_phase=phase,
            ))

            # Let the attack evaluate this response
            score, succeeded, evidence = attack.evaluate_response(
                assistant_content, phase, history
            )

            if succeeded or score >= self.success_threshold:
                result.succeeded = True
                result.final_score = score
                result.evidence = evidence
                result.total_turns = turn_number
                return result

        result.total_turns = turn_number
        if not result.succeeded:
            result.evidence = attack.summarize_failure(history)

        return result


class BaseMultiTurnAttack:
    """Abstract base for multi-turn attacks."""

    name: str = "base"
    goal: str = ""

    def generate_turns(
        self,
        history: list[dict[str, str]],
    ) -> Generator[tuple[str, str], None, None]:
        """Yield (phase, message) pairs for each attack turn.

        Implementations should be generators that use the history to
        adapt their next message based on the model's previous responses.
        """
        raise NotImplementedError

    def evaluate_response(
        self,
        response: str,
        phase: str,
        history: list[dict[str, str]],
    ) -> tuple[float, bool, str]:
        """Evaluate a model response.

        Returns:
            (score 0-1, succeeded bool, evidence string)
        """
        raise NotImplementedError

    def summarize_failure(self, history: list[dict[str, str]]) -> str:
        """Summarize why the attack failed after all turns exhausted."""
        return f"Attack '{self.name}' did not achieve goal after {len(history) // 2} turns."
