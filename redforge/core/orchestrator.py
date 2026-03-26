"""Scan orchestrator — the central engine of RedForge.

Coordinates: probes → adapter → scoring → session → results.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable

from redforge.adapters.base import BaseAdapter
from redforge.core.scorer import ScanScore, score_results
from redforge.core.session import ScanSession
from redforge.probes.base import BaseProbe, ProbeResult

logger = logging.getLogger(__name__)


class ScanConfig:
    """Configuration for a single scan run."""

    def __init__(
        self,
        probes: list[str] | None = None,
        system_prompt: str | None = None,
        max_tokens: int = 512,
        temperature: float = 0.7,
        timeout: float = 30.0,
        concurrency: int = 3,
        store_results: bool = True,
        dry_run: bool = False,
        enable_mutations: bool = False,
        mutation_strategies: list[str] | None = None,
        max_payloads_per_probe: int | None = None,
    ) -> None:
        self.probes = probes  # None = all probes
        self.system_prompt = system_prompt
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self.concurrency = concurrency
        self.store_results = store_results
        self.dry_run = dry_run
        self.enable_mutations = enable_mutations
        self.mutation_strategies = mutation_strategies  # None = engine default set
        self.max_payloads_per_probe = max_payloads_per_probe


class ScanReport:
    """Completed scan report with all results and scoring."""

    def __init__(self, session: ScanSession) -> None:
        self.session = session
        self.results = session.results
        self.score: ScanScore = session.score  # type: ignore[assignment]

    @property
    def session_id(self) -> str:
        return self.session.session_id

    @property
    def passed(self) -> bool:
        return self.score.failed == 0

    def __repr__(self) -> str:
        return f"ScanReport(session={self.session_id[:8]}, {self.score.summary})"


class Orchestrator:
    """Coordinates a full scan: load probes → run against adapter → score → save."""

    def __init__(self, adapter: BaseAdapter, config: ScanConfig | None = None) -> None:
        self.adapter = adapter
        self.config = config or ScanConfig()

    async def run(
        self,
        probes: list[BaseProbe],
        session: ScanSession,
        on_result: Callable[[ProbeResult], None] | None = None,
    ) -> ScanReport:
        """Execute all probes against the adapter and return a ScanReport.

        Args:
            probes: List of probe instances to run.
            session: Active scan session.
            on_result: Optional callback invoked after each probe result.

        Returns:
            Completed ScanReport.
        """
        if self.config.dry_run:
            logger.info("DRY RUN — probes will be listed but not executed")
            for probe in probes:
                logger.info("  [dry-run] %s (%s)", probe.id, probe.owasp_id)
            score = score_results([])
            session.finish(score)
            return ScanReport(session)

        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def run_probe(probe: BaseProbe) -> list[ProbeResult]:
            async with semaphore:
                return await self._run_single_probe(probe, session)

        tasks = [run_probe(probe) for probe in probes]
        all_result_groups = await asyncio.gather(*tasks, return_exceptions=True)

        for result_group in all_result_groups:
            if isinstance(result_group, Exception):
                logger.error("Probe execution error: %s", result_group)
                continue
            for result in result_group:  # type: ignore[union-attr]
                session.add_result(result)
                if on_result:
                    on_result(result)

        score = score_results(session.results)
        session.finish(score)
        session.save()

        report = ScanReport(session)
        _save_auto_reports(report)
        return report

    async def _run_single_probe(
        self, probe: BaseProbe, session: ScanSession
    ) -> list[ProbeResult]:
        """Run one probe: send each payload, collect responses, score each."""
        results: list[ProbeResult] = []
        payloads = probe.payloads()

        if self.config.enable_mutations:
            try:
                from redforge.mutations.engine import MutationEngine, MutationStrategy
                engine = MutationEngine()
                strategies = None
                if self.config.mutation_strategies:
                    strategies = [
                        MutationStrategy(s) for s in self.config.mutation_strategies
                        if s in MutationStrategy._value2member_map_  # noqa: SLF001
                    ]
                payloads = engine.generate_variants(
                    payloads,
                    strategies,
                    max_variants=self.config.max_payloads_per_probe,
                )
            except Exception as exc:
                logger.warning("Mutation expansion failed for %s: %s", probe.id, exc)

        if self.config.max_payloads_per_probe:
            payloads = payloads[: self.config.max_payloads_per_probe]

        logger.debug("Running probe %s (%d payloads)", probe.id, len(payloads))

        for payload in payloads:
            try:
                messages = [{"role": "user", "content": payload}]
                response = await self.adapter.send(
                    messages=messages,
                    system_prompt=self.config.system_prompt,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    timeout=self.config.timeout,
                )
                # SECURITY: response.content is untrusted — passed only to probe.score()
                # which treats it as a plain string. Never eval() or exec() it.
                result = probe.score(response.content, payload)
                results.append(result)

                status = "FAIL" if not result.passed else "PASS"
                logger.info(
                    "[%s] %s | score=%.2f | %s",
                    status, probe.id, result.score, result.evidence[:80]
                )

            except Exception as exc:
                logger.warning("Probe %s payload failed: %s", probe.id, str(exc)[:100])

        return results

    async def stream(
        self, probes: list[BaseProbe], session: ScanSession
    ) -> AsyncIterator[ProbeResult]:
        """Stream probe results as they complete (for real-time API responses)."""
        semaphore = asyncio.Semaphore(self.config.concurrency)

        async def run_and_yield(probe: BaseProbe) -> list[ProbeResult]:
            async with semaphore:
                return await self._run_single_probe(probe, session)

        tasks = [asyncio.create_task(run_and_yield(probe)) for probe in probes]

        for task in asyncio.as_completed(tasks):
            result_group = await task
            for result in result_group:
                session.add_result(result)
                yield result


def _save_auto_reports(report: ScanReport) -> None:
    """Always emit audit log + failures file alongside every scan.

    These two files are generated unconditionally — the user never needs to
    pass a flag. They land in the same output_dir as the session JSON.

    Files written:
      {output_dir}/{sid}_audit.jsonl   — full audit: every probe, payload, response
      {output_dir}/{sid}_failures.json — failed probes only, structured for guardrail work
    """
    from redforge.reporters.audit_reporter import AuditReporter
    from redforge.reporters.failures_reporter import FailuresReporter

    if not report.session.store_results:
        return

    session = report.session
    output_dir = session.output_dir
    ts = session.started_at.strftime("%Y%m%d_%H%M%S") if session.started_at else "unknown"
    sid = session.session_id[:8]
    stem = f"redforge_{sid}_{ts}"

    try:
        audit_path = output_dir / f"{stem}_audit.jsonl"
        AuditReporter().save(report, audit_path)
        logger.info("[audit]    %s", audit_path)
    except Exception as exc:
        logger.warning("Failed to write audit log: %s", exc)

    failures = [r for r in report.results if not r.passed]
    if failures:
        try:
            failures_path = output_dir / f"{stem}_failures.json"
            FailuresReporter().save(report, failures_path)
            logger.info("[failures] %s", failures_path)
        except Exception as exc:
            logger.warning("Failed to write failures report: %s", exc)
    else:
        logger.info("[failures] No failures — skipping failures.json")
