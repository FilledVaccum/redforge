"""RedForge CLI — Typer-based command interface.

Commands:
  redforge scan        — Run a vulnerability scan
  redforge list-probes — List all available probes
  redforge report      — Render a saved scan result
  redforge serve       — Start the REST API server
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from redforge.core.constants import AUTHORIZATION_CHOICES, SEVERITY_RICH, VERSION

app = typer.Typer(
    name="redforge",
    help="RedForge — LLM Red Teaming & Vulnerability Scanner",
    add_completion=False,
)
console = Console()

BANNER = f"""[bold red]
██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝█████╗  ██║  ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██║  ██║███████╗██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
[/bold red]
[dim]LLM Red Teaming & Vulnerability Scanner — v{VERSION} — Apache 2.0[/dim]
[yellow]⚠  For authorized use only. Scan only systems you own or have written permission to test.[/yellow]
"""


def _provider_help() -> str:
    """Build provider help string dynamically from the adapter registry."""
    try:
        from redforge.adapters.factory import _BUILTIN_REGISTRY
        providers = sorted(_BUILTIN_REGISTRY.keys())
        return "Model provider: " + ", ".join(providers)
    except Exception:  # noqa: BLE001
        return "Model provider (e.g. openai, anthropic, ollama, bedrock)"


def _format_help(context: str = "Output") -> str:
    """Build format help string dynamically from the reporter registry."""
    try:
        from redforge.reporters import available_formats
        fmts = available_formats()
        return f"{context} format: " + " | ".join(fmts)
    except Exception:  # noqa: BLE001
        return f"{context} format: json | sarif | html | markdown"


@app.command()
def scan(
    provider: str = typer.Option(..., "--provider", "-p", help=_provider_help()),
    model: str | None = typer.Option(None, "--model", "-m", help="Model name/ID"),
    authorization: str = typer.Option(..., "--authorization", "-a",
                                      help=f"Authorization: {' | '.join(AUTHORIZATION_CHOICES)}"),
    probes: str | None = typer.Option(None, "--probes",
                                      help="Comma-separated probe IDs. Default: all probes"),
    system_prompt: str | None = typer.Option(None, "--system-prompt",
                                             help="System prompt for the target model"),
    format: str = typer.Option("markdown", "--format", "-f", help=_format_help()),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save report to file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="List probes without executing"),
    no_store: bool = typer.Option(False, "--no-store",
                                  help="Do not persist scan results to disk"),
    concurrency: int = typer.Option(3, "--concurrency",
                                    help="Number of concurrent probe executions"),
) -> None:
    """Run a vulnerability scan against a target LLM."""
    console.print(BANNER)

    if authorization not in AUTHORIZATION_CHOICES:
        console.print(
            f"[red]Error: --authorization must be one of: {', '.join(AUTHORIZATION_CHOICES)}[/red]"
        )
        raise typer.Exit(1)

    probe_list = [p.strip() for p in probes.split(",")] if probes else None

    from redforge.core.orchestrator import Orchestrator, ScanConfig
    from redforge.core.session import ScanSession
    from redforge.probes import get_all_probes, get_probe
    from redforge.reporters import get_reporter

    with console.status(
        f"[bold green]Scanning {provider}/{model or 'default'} "
        f"with {len(probe_list) if probe_list else 'all'} probes..."
    ):
        adapter_config: dict[str, str] = {}
        if model:
            adapter_config["model"] = model

        from redforge.adapters import get_adapter
        try:
            adapter = get_adapter(provider, adapter_config)
        except (ImportError, ValueError) as e:
            console.print(f"[red]Adapter error: {e}[/red]")
            raise typer.Exit(1) from None

        scan_config = ScanConfig(
            probes=probe_list,
            system_prompt=system_prompt,
            concurrency=concurrency,
            store_results=not no_store,
            dry_run=dry_run,
        )
        session = ScanSession(
            target=f"{provider}/{model or 'default'}",
            provider=provider,
            model=model or "default",
            store_results=not no_store,
        )
        all_probes = [get_probe(p) for p in probe_list] if probe_list else get_all_probes()

        def on_result(result: object) -> None:
            from redforge.probes.base import ProbeResult
            if isinstance(result, ProbeResult):
                status = "[red]FAIL[/red]" if not result.passed else "[green]PASS[/green]"
                console.print(f"  {status} {result.probe_id} (score={result.score:.2f})")

        orchestrator = Orchestrator(adapter, scan_config)
        report = asyncio.run(orchestrator.run(all_probes, session, on_result=on_result))

    # Print summary
    s = report.score
    console.print("\n[bold]Scan Complete[/bold]")
    risk_color = "red" if s.risk_level in ("CRITICAL", "HIGH") else "yellow"
    console.print(f"Risk Level: [{risk_color}]{s.risk_level}[/{risk_color}] ({s.risk_score:.1f}/10)")
    console.print(f"Probes: {s.passed}/{s.total_probes} passed ({s.pass_rate*100:.0f}%)")

    reporter = get_reporter(format)
    rendered = reporter.render(report)

    if output:
        reporter.save(report, output)
        console.print(f"\nReport saved to: [cyan]{output}[/cyan]")
    else:
        console.print("\n" + rendered)

    # Exit with non-zero for CI/CD pipelines if critical/high findings exist
    if s.critical_findings > 0 or s.high_findings > 0:
        raise typer.Exit(1)


@app.command(name="list-probes")
def list_probes() -> None:
    """List all available attack probes."""
    from redforge.probes import get_all_probes

    probes = get_all_probes()
    table = Table(
        title="RedForge Attack Probes",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("ID", style="bold")
    table.add_column("OWASP")
    table.add_column("MITRE ATLAS")
    table.add_column("Severity", justify="center")
    table.add_column("Payloads", justify="right")
    table.add_column("Description")

    for probe in sorted(probes, key=lambda p: p.owasp_id):
        # SEVERITY_RICH from constants — any severity gets a color, unknown → "white"
        color = SEVERITY_RICH.get(probe.severity, "white")
        table.add_row(
            probe.id,
            probe.owasp_id,
            probe.mitre_atlas,
            f"[{color}]{probe.severity.upper()}[/{color}]",
            str(len(probe.payloads())),
            probe.description[:60] + "…" if len(probe.description) > 60 else probe.description,
        )

    console.print(BANNER)
    console.print(table)
    console.print(f"\n[dim]Total: {len(probes)} probes[/dim]")


@app.command(name="list-providers")
def list_providers() -> None:
    """List all registered model providers and available formats."""
    from redforge.adapters.factory import _BUILTIN_REGISTRY, AdapterFactory
    from redforge.reporters import REPORTERS, available_formats

    # Providers
    ptable = Table(title="Registered Providers", show_header=True, header_style="bold cyan")
    ptable.add_column("Provider")
    ptable.add_column("Adapter Module")
    all_providers = {**_BUILTIN_REGISTRY, **dict.fromkeys(AdapterFactory._custom_registry, "custom")}
    for name in sorted(all_providers):
        ptable.add_row(name, all_providers[name])
    console.print(ptable)

    # Formats
    ftable = Table(title="Registered Report Formats", show_header=True, header_style="bold cyan")
    ftable.add_column("Format")
    ftable.add_column("Reporter Class")
    seen: set[type] = set()
    for fmt in sorted(REPORTERS):
        cls = REPORTERS[fmt]
        alias_marker = " (alias)" if cls in seen else ""
        ftable.add_row(fmt, cls.__name__ + alias_marker)
        seen.add(cls)
    console.print(ftable)
    console.print(f"\n[dim]Primary formats: {', '.join(available_formats())}[/dim]")


@app.command()
def report(
    input_file: Path = typer.Argument(..., help="Path to a saved scan result JSON file"),
    format: str = typer.Option("html", "--format", "-f", help=_format_help()),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save report to file"),
) -> None:
    """Render a saved scan result in a different format."""
    import json

    if not input_file.exists():
        console.print(f"[red]File not found: {input_file}[/red]")
        raise typer.Exit(1)

    data = json.loads(input_file.read_text())

    console.print(f"[dim]Re-rendering {input_file} as {format}...[/dim]")

    if format == "json":
        rendered = json.dumps(data, indent=2)
    else:
        rendered = (
            f"# Report: {data.get('session_id','?')}\n\n"
            f"Risk: {data.get('score',{}).get('risk_level','?')}\n\n"
            "> Re-render from saved JSON. Run a live scan for a full report.\n"
        )

    if output:
        output.write_text(rendered)
        console.print(f"Report saved to: [cyan]{output}[/cyan]")
    else:
        console.print(rendered)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev only)"),
) -> None:
    """Start the RedForge REST API server."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn not installed. Run: pip install redforge[/red]")
        raise typer.Exit(1) from None

    console.print(BANNER)
    console.print(f"[green]Starting RedForge API server on http://{host}:{port}[/green]")
    console.print(f"[dim]API docs: http://{host}:{port}/docs[/dim]")
    console.print("[dim]Auth: Set REDFORGE_API_KEY env var[/dim]")
    console.print("[yellow]⚠  Ensure REDFORGE_API_KEY is set before exposing to a network[/yellow]\n")

    uvicorn.run(
        "redforge.api.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
    )


if __name__ == "__main__":
    app()
