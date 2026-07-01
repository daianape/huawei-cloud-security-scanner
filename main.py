"""
Huawei Cloud Security Scanner - Main Entry Point

Usage:
    python main.py scan --config config/config.yaml
    python main.py scan --regions la-south-2,ap-southeast-1
    python main.py scan --regions all
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
from core.regions import ALL_REGION_CODES, get_region_name, HUAWEI_CLOUD_REGIONS
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
    "--regions", "-r",
    "regions_list",
    type=str,
    default=None,
    help="Regions to scan (comma-separated, or 'all' for all regions). Default: from config.",
)
@click.option(
    "--interactive", "-i",
    is_flag=True,
    default=False,
    help="Prompt for credentials interactively (more secure, nothing saved to disk).",
)
@click.option(
    "--no-verify-ssl",
    is_flag=True,
    default=False,
    help="Disable SSL certificate verification (use behind corporate proxies).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging.",
)
def scan(config, output, output_formats, scanner_list, regions_list, interactive, no_verify_ssl, verbose):
    """Run security assessment scan against Huawei Cloud account(s)."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    console.print(Panel.fit(
        "[bold red]Huawei Cloud Security Scanner[/bold red]\n"
        "[dim]Security Assessment Tool v1.0.0[/dim]",
        border_style="red",
    ))
    console.print()

    # Interactive mode: prompt for credentials
    if interactive:
        cfg = _prompt_credentials(no_verify_ssl)
    else:
        # Load configuration from file
        try:
            cfg = load_config(config)
            console.print("[green]✓[/green] Configuration loaded successfully")
        except Exception as e:
            console.print(f"[red]✗ Configuration error:[/red] {e}")
            console.print()
            console.print(
                "[dim]Tip: Use --interactive (-i) to enter credentials "
                "without a config file.[/dim]"
            )
            sys.exit(1)

    # Apply SSL verification setting
    if no_verify_ssl:
        cfg["verify_ssl"] = False
        console.print("[yellow]⚠ SSL verification disabled[/yellow]")

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

    # Determine regions to scan
    regions_to_scan = _resolve_regions(regions_list, cfg)

    # Auto-discover project IDs if scanning multiple regions and not already discovered
    if len(regions_to_scan) > 1 and "_discovered_projects" not in cfg:
        creds_config = cfg.get("credentials", {})
        ak = creds_config.get("access_key")
        sk = creds_config.get("secret_key")
        if ak and sk:
            console.print("  [dim]Discovering project IDs for all regions...[/dim]")
            discovered = HuaweiCloudAuth.discover_projects(ak, sk, verify_ssl=cfg.get("verify_ssl", True))
            if discovered:
                cfg["_discovered_projects"] = discovered
                console.print(
                    f"  [green]✓[/green] Auto-discovered {len(discovered)} region project IDs"
                )
                # Filter regions to only those we have project IDs for
                available_regions = [r for r in regions_to_scan if r in discovered]
                if available_regions:
                    regions_to_scan = available_regions

    console.print(
        f"[green]✓[/green] Regions: {', '.join(regions_to_scan)}"
    )

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

    # Run scans (per account, per region)
    all_results: list[ScanResult] = []

    for target in targets:
        for region in regions_to_scan:
            # Create a region-specific target
            region_target = _create_region_target(target, region, cfg)
            if region_target is None:
                continue

            region_name = get_region_name(region)
            console.print(
                f"[bold]Scanning account: {region_target.account_name}[/bold] "
                f"(region: {region} - {region_name})"
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
                    scanner = scanner_class(region_target)
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
                account_name=region_target.account_name,
                account_id=region_target.domain_id or region_target.project_id,
                region=region,
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


def _prompt_credentials(no_verify_ssl: bool = False) -> dict:
    """
    Prompt user for credentials interactively.
    Credentials are only held in memory during execution.
    """
    console.print("[bold]Interactive mode[/bold] - credentials will NOT be saved to disk.")
    console.print()

    access_key = click.prompt("  Access Key (AK)", type=str)
    secret_key = click.prompt("  Secret Key (SK)", type=str, hide_input=True)
    console.print()
    console.print("  [dim](Project ID: Huawei Console > My Credentials > API Credentials)[/dim]")
    project_id = click.prompt("  Project ID", type=str)
    region = click.prompt("  Region", type=str, default="la-south-2")
    domain_id = click.prompt("  Domain ID (Account ID, para IAM checks)", type=str, default="")

    console.print()
    console.print("[green]✓[/green] Credentials received (in-memory only)")

    cfg = {
        "mode": "single",
        "region": region,
        "project_id": project_id,
        "cloud_domain": "myhuaweicloud.com",
        "credentials": {
            "access_key": access_key,
            "secret_key": secret_key,
            "domain_id": domain_id,
        },
        "scanners": {
            "iam": True,
            "vpc": True,
            "ecs": True,
            "obs": True,
            "cts": True,
            "elb": True,
        },
        "output": {
            "directory": "./output",
            "formats": ["html", "json"],
        },
    }

    return cfg


def _resolve_regions(regions_list: str | None, cfg: dict) -> list[str]:
    """
    Resolve which regions to scan based on CLI arg and config.
    Priority: CLI --regions > config.regions > config.region (single)
    """
    if regions_list:
        if regions_list.strip().lower() == "all":
            return ALL_REGION_CODES
        return [r.strip() for r in regions_list.split(",")]

    # Check config for regions list
    regions_cfg = cfg.get("regions", [])
    if regions_cfg:
        return [r["region"] for r in regions_cfg if "region" in r]

    # Fallback to single region
    return [cfg.get("region", "la-south-2")]


def _create_region_target(target: ScanTarget, region: str, cfg: dict) -> ScanTarget | None:
    """
    Create a new ScanTarget adjusted for a specific region.
    Uses region-specific project_id if configured or auto-discovered.
    """
    from core.auth import AccountCredentials

    # Try to find region-specific project_id from multiple sources
    project_id = target.project_id

    # 1. Check auto-discovered projects
    discovered = cfg.get("_discovered_projects", {})
    if region in discovered:
        project_id = discovered[region]

    # 2. Check explicit regions config (overrides discovery)
    regions_cfg = cfg.get("regions", [])
    for r in regions_cfg:
        if r.get("region") == region:
            project_id = r.get("project_id", project_id)
            break

    # 3. For multi-account targets, use the target's own config
    if cfg.get("mode") == "multi":
        multi_cfg = cfg.get("multi_account", {})
        for acct in multi_cfg.get("target_accounts", []):
            if acct.get("account_name") == target.account_name:
                if acct.get("region") == region:
                    project_id = acct.get("project_id", project_id)
                break

    if not project_id:
        logger.warning(f"No project_id found for region {region}, skipping")
        return None

    # Create new target with the correct region
    new_target = ScanTarget(
        account_name=target.account_name,
        credentials=target.credentials,
        region=region,
        project_id=project_id,
        domain_id=target.domain_id,
        verify_ssl=getattr(target, 'verify_ssl', cfg.get("verify_ssl", True)),
        cloud_domain=getattr(target, 'cloud_domain', cfg.get("cloud_domain", "myhuaweicloud.com")),
    )
    return new_target


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
def list_regions():
    """List all available Huawei Cloud regions."""
    console.print(Panel.fit(
        "[bold]Available Regions[/bold]",
        border_style="blue",
    ))
    console.print()

    table = Table(show_header=True, header_style="bold")
    table.add_column("Region Code", style="cyan")
    table.add_column("Name")

    for r in HUAWEI_CLOUD_REGIONS:
        table.add_row(r["region"], r["name"])

    console.print(table)
    console.print()
    console.print(
        "Use [bold]--regions la-south-2,ap-southeast-1[/bold] to scan specific regions."
    )
    console.print(
        "Use [bold]--regions all[/bold] to scan all regions."
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

        regions_cfg = cfg.get("regions", [])
        if regions_cfg:
            region_list = [r["region"] for r in regions_cfg]
            console.print(f"  Multi-region: {', '.join(region_list)}")

        scanners_cfg = cfg.get("scanners", {})
        enabled = [k for k, v in scanners_cfg.items() if v]
        console.print(f"  Scanners: {', '.join(enabled) if enabled else 'all'}")

    except Exception as e:
        console.print(f"[red]✗ Configuration error:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
