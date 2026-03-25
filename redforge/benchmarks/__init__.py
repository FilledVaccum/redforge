"""RedForge Benchmark Evaluation Suite.

Evaluates LLMs against standard red-teaming benchmarks:
- AdvBench (Zou et al., 2023) — 520 harmful behaviors
- HarmBench (Mazeika et al., 2024) — 400 standardized behaviors
- ToxicChat (Lin et al., 2023) — real jailbreak attempts
- WildGuard (Han et al., 2024) — safety/refusal evaluation
- JailbreakBench (Chao et al., 2024) — 100 behaviors + artifacts

Provides standardized Attack Success Rate (ASR) metrics comparable
across tools (garak, promptfoo, Giskard).
"""

from __future__ import annotations

from redforge.benchmarks.runner import (
    BenchmarkEntry,
    BenchmarkResult,
    BenchmarkRunner,
    BenchmarkSuite,
    run_benchmark,
)

__all__ = [
    "BenchmarkRunner",
    "BenchmarkSuite",
    "BenchmarkEntry",
    "BenchmarkResult",
    "run_benchmark",
]
