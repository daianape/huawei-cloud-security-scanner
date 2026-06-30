"""
Huawei Cloud Security Scanner - Main Entry Point

Usage:
    python main.py scan --config config/config.yaml
    python main.py scan --mode single --region la-south-2
    python main.py scan --output ./output --format html,json,csv
"""

import sys
import logging
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.config_loader import load_config
from core.auth import HuaweiCloudAuth, ScanTarget
from core.models import ScanResult, ScanSummary, Severity, Status
from scanners import AVAILABLE_SCANNERS
from reports.html_report import HTMLReportGenerator
from reports.json_report import JSONReportGenerator
from reports.csv_report import CSVReportGenerator

console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version="1.0.0", prog_name="Huawei Cloud Security Scanner")
def cli():
    """Huawei Cloud Security Scanner - Assess your cloud security posture."""
    pass


@cli.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=False),
    default=None,
    help="Path to configuration YAML file.",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default="./output",
    help="Output directory for reports.",
)
@click.option(
    "--format", "-f",
    "output_formats",
    type=str,
    default="html,json",
    help="Output formats (comma-separated): html, json, csv.",
)
@click.option(
    "--scanners", "-s",
    "scanner_list",
    type=str,
    default=None,
    help="Scanners to run (comma-separated): iam, vpc, ecs, obs, cts, elb. Default: all.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging.",
)
def scan(config, output, output_formats, scanner_list, verbose):
    """Run security assessment scan against Huawei Cloud account(s)."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.print(Panel.fit(
        "[bold red]Huawei Cloud Security Scanner[/bold red]\n"
        "[dim]Security Assessment Tool v1.0.0[/dim]",
        border_style="red",
    ))
    console.print()

    # Load configuration
    try:
        cfg = load_config(config)
        console.print("[green]✓[/green] Configuration loaded successfully")
    except Exception as e:
        console.print(f"[red]✗ Configuration error:[/red] {e}")
        sys.exit(1)

    # Authenticate
    try:
        auth = HuaweiCloudAuth(cfg)
        targets = auth.authenticate()
        mode = cfg.get("mode", "single")
        console.print(
            f"[green]✓[/green] Authenticated ({mode} mode) - "
            f"{len(targets)} account(s) to scan"
        )
    except Exception as e:
        console.print(f"[red]✗ Authentication failed:[/red] {e}")
        sys.exit(1)

    # Determine which scanners to run
    if scanner_list:
        scanners_to_run = [s.strip().lower() for s in scanner_list.split(",")]
    else:
        scanners_cfg = cfg.get("scanners", {})
        scanners_to_run = [
            name for name, enabled in scanners_cfg.items()
            if enabled and name in AVAILABLE_SCANNERS
        ]
        # If no config, run all
        if not scanners_to_run:
            scanners_to_run = list(AVAILABLE_SCANNERS.keys())

    console.print(
        f"[green]✓[/green] Scanners: {', '.join(s.upper() for s in scanners_to_run)}"
    )
    console.print()

    # Run scans
    all_results: list[ScanResult] = []

    for target in targets:
        console.print(
            f"[bold]Scanning account: {target.account_name}[/bold] "
            f"(region: {target.region})"
        )

        account_findings = []
        scan_start = datetime.utcnow().isoformat()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for scanner_name in scanners_to_run:
                if scanner_name not in AVAILABLE_SCANNERS:
                    console.print(
                        f"  [yellow]⚠ Unknown scanner: {scanner_name}[/yellow]"
                    )
                    continue

                task = progress.add_task(
                    f"  Scanning {scanner_name.upper()}...", total=None
                )

                scanner_class = AVAILABLE_SCANNERS[scanner_name]
                scanner = scanner_class(target)
                findings = scanner.run()
                account_findings.extend(findings)

                failed = sum(1 for f in findings if f.status == Status.FAIL)
                progress.update(task, completed=True)
                progress.remove_task(task)
                console.print(
                    f"  [{'red' if failed > 0 else 'green'}]"
                    f"  {scanner_name.upper()}: "
                    f"{len(findings)} checks, {failed} failed[/]"
                )

        # Build summary
        scan_end = datetime.utcnow().isoformat()
        summary = ScanSummary(
            account_name=target.account_name,
            account_id=target.domain_id or target.project_id,
            region=target.region,
            scan_start=scan_start,
            scan_end=scan_end,
        )
        summary.calculate_from_findings(account_findings)

        result = ScanResult(summary=summary, findings=account_findings)
        all_results.append(result)
        console.print()

    # Generate reports
    console.print("[bold]Generating reports...[/bold]")
    formats = [f.strip().lower() for f in output_formats.split(",")]

    generated_files = []

    if "html" in formats:
        html_gen = HTMLReportGenerator(output_dir=output)
        html_path = html_gen.generate(all_results)
        generated_files.append(("HTML Dashboard", html_path))
        console.print(f"  [green]✓[/green] HTML Dashboard: {html_path}")

    if "json" in formats:
        json_gen = JSONReportGenerator(output_dir=output)
        json_path = json_gen.generate(all_results)
        generated_files.append(("JSON Report", json_path))
        console.print(f"  [green]✓[/green] JSON Report: {json_path}")

    if "csv" in formats:
        csv_gen = CSVReportGenerator(output_dir=output)
        csv_path = csv_gen.generate(all_results)
        generated_files.append(("CSV Report", csv_path))
        console.print(f"  [green]✓[/green] CSV Report: {csv_path}")

    # Print summary table
    console.print()
    _print_summary_table(all_results)

    console.print()
    console.print("[bold green]Scan complete![/bold green]")
    if generated_files:
        console.print(
            f"Open [bold]{generated_files[0][1]}[/bold] in your browser "
            f"to view the dashboard."
        )


def _print_summary_table(results: list[ScanResult]) -> None:
    """Print a rich summary table of scan results."""
    table = Table(title="Scan Results Summary", show_header=True, header_style="bold")
    table.add_column("Account", style="cyan")
    table.add_column("Region")
    table.add_column("Total", justify="right")
    table.add_column("Passed", justify="right", style="green")
    table.add_column("Failed", justify="right", style="red")
    table.add_column("Critical", justify="right", style="bold red")
    table.add_column("High", justify="right", style="red")
    table.add_column("Medium", justify="right", style="yellow")
    table.add_column("Low", justify="right")

    for result in results:
        s = result.summary
        table.add_row(
            s.account_name,
            s.region,
            str(s.total_checks),
            str(s.passed),
            str(s.failed),
            str(s.critical_count),
            str(s.high_count),
            str(s.medium_count),
            str(s.low_count),
        )

    console.print(table)


@cli.command()
def list_scanners():
    """List all available scanners and their checks."""
    console.print(Panel.fit(
        "[bold]Available Scanners[/bold]",
        border_style="blue",
    ))
    console.print()

    for name, scanner_class in AVAILABLE_SCANNERS.items():
        console.print(f"  [bold cyan]{name.upper()}[/bold cyan] - {scanner_class.__doc__.strip().splitlines()[0] if scanner_class.__doc__ else 'No description'}")

    console.print()
    console.print(
        "Use [bold]--scanners iam,vpc[/bold] to run specific scanners only."
    )


@cli.command()
@click.option("--config", "-c", type=click.Path(exists=False), default=None)
def validate(config):
    """Validate configuration file without running a scan."""
    try:
        cfg = load_config(config)
        console.print("[green]✓ Configuration is valid![/green]")
        console.print(f"  Mode: {cfg.get('mode', 'single')}")
        console.print(f"  Region: {cfg.get('region', 'not set')}")

        scanners_cfg = cfg.get("scanners", {})
        enabled = [k for k, v in scanners_cfg.items() if v]
        console.print(f"  Scanners: {', '.join(enabled) if enabled else 'all'}")

    except Exception as e:
        console.print(f"[red]✗ Configuration error:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
