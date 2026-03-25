"""RedForge — LLM Red Teaming & Vulnerability Scanning Platform.

Quick start:
    from redforge import Scanner, ScanConfig

    scanner = Scanner(provider="ollama", model="llama3")
    report = await scanner.scan(authorization="owned")
    print(report.score.summary)
"""

from typing import Any

from redforge.adapters import get_adapter
from redforge.core.orchestrator import ScanConfig, ScanReport
from redforge.core.session import ScanSession


class Scanner:
    """High-level Python SDK entry point for RedForge.

    Example:
        scanner = Scanner(provider="openai", model="gpt-4o")
        report = asyncio.run(scanner.scan(authorization="owned"))
    """

    def __init__(
        self,
        provider: str,
        model: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        adapter_config = config or {}
        if model:
            adapter_config["model"] = model
        self._adapter = get_adapter(provider, adapter_config)
        self._provider = provider
        self._model = model or adapter_config.get("model", "unknown")

    async def scan(
        self,
        authorization: str,
        probes: list[str] | None = None,
        system_prompt: str | None = None,
        dry_run: bool = False,
        store_results: bool = True,
    ) -> "ScanReport":
        """Run a full vulnerability scan.

        Args:
            authorization: Must be 'owned', 'authorized', or 'research'.
                           Required to confirm you have permission to test this model.
            probes: Specific probe IDs to run. None = all probes.
            system_prompt: Optional system prompt for the target model.
            dry_run: List probes without executing them.
            store_results: Persist results to disk (0600 perms).

        Returns:
            ScanReport with all findings and risk score.
        """
        if authorization not in ("owned", "authorized", "research"):
            raise ValueError(
                "authorization must be 'owned', 'authorized', or 'research'. "
                "You must confirm you have permission to scan this model."
            )

        from redforge.core.orchestrator import Orchestrator, ScanConfig
        from redforge.probes import get_all_probes, get_probe

        scan_config = ScanConfig(
            probes=probes,
            system_prompt=system_prompt,
            dry_run=dry_run,
            store_results=store_results,
        )
        session = ScanSession(
            target=f"{self._provider}/{self._model}",
            provider=self._provider,
            model=self._model,
            store_results=store_results,
        )
        all_probes = [get_probe(p) for p in probes] if probes else get_all_probes()
        orchestrator = Orchestrator(self._adapter, scan_config)
        return await orchestrator.run(all_probes, session)


__all__ = ["Scanner", "ScanConfig", "ScanReport"]
__version__ = "0.1.0"
