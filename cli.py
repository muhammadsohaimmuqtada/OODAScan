"""
cli.py
------
Command-line interface for the Advanced BB Toolkit.

Usage examples::

    python cli.py scan --target https://example.com
    python cli.py scan -t https://example.com -c 30 --use-crawler -o report.json
    python cli.py scan -t https://example.com --token-user-a "Bearer eyJ..." --output report.json
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import print as rprint

app = typer.Typer(
    name="bb-toolkit",
    help="Advanced Bug Bounty Toolkit — self-driving OODA pentesting engine.",
    add_completion=False,
)

console = Console()


@app.command()
def scan(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target URL to scan (e.g. https://example.com).",
    ),
    concurrency: int = typer.Option(
        20,
        "--concurrency",
        "-c",
        help="Maximum number of simultaneous HTTP requests.",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        help="Per-request timeout in seconds.",
    ),
    use_crawler: bool = typer.Option(
        False,
        "--use-crawler",
        is_flag=True,
        help="Enable the headless Playwright crawler to discover endpoints before scanning.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional file path to save the JSON report (e.g. report.json).",
    ),
    token_user_a: Optional[str] = typer.Option(
        None,
        "--token-user-a",
        help='Auth token for User A (e.g. "Bearer eyJ...").',
    ),
    token_user_b: Optional[str] = typer.Option(
        None,
        "--token-user-b",
        help='Auth token for User B (e.g. "Bearer eyJ...").',
    ),
    token_admin: Optional[str] = typer.Option(
        None,
        "--token-admin",
        help='Auth token for the Admin role (e.g. "Bearer eyJ...").',
    ),
) -> None:
    """Run a fully autonomous OODA scan against TARGET."""

    console.rule("[bold cyan]Advanced BB Toolkit[/bold cyan]")
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Concurrency:[/bold] {concurrency}  |  [bold]Timeout:[/bold] {timeout}s")
    if use_crawler:
        console.print("[bold]Crawler:[/bold] [green]enabled[/green]")
    if output:
        console.print(f"[bold]Report output:[/bold] {output}")
    console.print()

    async def _run() -> dict:
        from core.orchestrator import Orchestrator

        orch = Orchestrator(target=target, concurrency=concurrency)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Running OODA scan…", total=None)
            report = await orch.run_autonomous(
                use_crawler=use_crawler,
                token_user_a=token_user_a,
                token_user_b=token_user_b,
                token_admin=token_admin,
            )

        return report

    try:
        report = asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        raise typer.Exit(code=1)
    except Exception as exc:  # pylint: disable=broad-except
        console.print_exception(show_locals=False)
        console.print(f"[bold red]Scan failed:[/bold red] {exc}")
        raise typer.Exit(code=2)

    # ── Save JSON report ────────────────────────────────────────────────
    if output:
        try:
            output.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            console.print(f"[green]✔[/green] Report saved to [bold]{output}[/bold]")
        except OSError as exc:
            console.print(f"[bold red]Could not write report:[/bold red] {exc}")

    # ── Print findings summary table ────────────────────────────────────
    findings = report.get("findings", [])
    console.print()
    console.rule("[bold cyan]Scan Results[/bold cyan]")

    endpoints_discovered = report.get("endpoints_discovered", [])
    console.print(
        f"Endpoints discovered: [bold]{len(endpoints_discovered)}[/bold]  |  "
        f"Findings: [bold]{len(findings)}[/bold]"
    )

    if findings:
        table = Table(title="Findings", show_lines=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Type", style="cyan")
        table.add_column("Severity", style="magenta")
        table.add_column("URL", style="green", no_wrap=False)

        severity_colours = {
            "critical": "[bold red]",
            "high": "[red]",
            "medium": "[yellow]",
            "low": "[blue]",
            "info": "[dim]",
        }

        for idx, finding in enumerate(findings, start=1):
            finding_type = finding.get("type") or finding.get("issue") or "unknown"
            severity_raw = str(finding.get("severity", "info")).lower()
            colour = severity_colours.get(severity_raw, "")
            severity_display = f"{colour}{severity_raw}[/]" if colour else severity_raw
            url = str(finding.get("url", report.get("target", "-")))
            table.add_row(str(idx), finding_type, severity_display, url)

        console.print(table)
    else:
        console.print("[dim]No findings to display.[/dim]")

    console.print()


if __name__ == "__main__":
    app()
