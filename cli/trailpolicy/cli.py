"""Click CLI for trailpolicy — generate least-privilege IAM policies."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import MAX_LOOKBACK_DAYS, MAX_POLICY_SIZE, detect_partition
from .core.action_mapper import ActionMapper
from .core.cloudtrail import fetch_events
from .core.event_parser import parse_events
from .core.policy_builder import build_policy
from .core.resource_extractor import extract_resources
from .output.diff_reporter import compute_diff, format_diff_text
from .output.json_formatter import format_policy_json
from .output.terraform_formatter import format_policy_terraform

console = Console(stderr=True)
logger = logging.getLogger("trailpolicy")


def _configure_logging(verbose: bool) -> None:
    """Set up logging to stderr."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )


@click.group()
@click.version_option(version=__version__, prog_name="trailpolicy")
def main():
    """trailpolicy — Generate least-privilege IAM policies from CloudTrail activity."""


@main.command()
@click.option("--role-arn", required=True, help="IAM role ARN to analyze")
@click.option(
    "--days",
    default=30,
    type=click.IntRange(1, MAX_LOOKBACK_DAYS),
    help=f"Lookback period in days (1-{MAX_LOOKBACK_DAYS})",
)
@click.option("--start-date", help="Start date (YYYY-MM-DD), overrides --days")
@click.option("--end-date", help="End date (YYYY-MM-DD), default: today")
@click.option("--region", help="AWS region (auto-detected if not set)")
@click.option("--partition", help="AWS partition (auto-detected from credentials)")
@click.option(
    "--source",
    type=click.Choice(["api", "athena"]),
    default="api",
    help="Event data source",
)
@click.option("--athena-db", help="Athena database (required if source=athena)")
@click.option("--athena-table", help="Athena table (required if source=athena)")
@click.option("--athena-workgroup", help="Athena workgroup (required if source=athena)")
@click.option(
    "--include-advisor/--no-advisor",
    default=True,
    help="Include IAM Access Advisor data",
)
@click.option(
    "--output-format",
    "-f",
    type=click.Choice(["json", "tf"]),
    default="json",
    help="Output format",
)
@click.option("--output-file", "-o", type=click.Path(), help="Write output to file")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def generate(
    role_arn: str,
    days: int,
    start_date: str | None,
    end_date: str | None,
    region: str | None,
    partition: str | None,
    source: str,
    athena_db: str | None,
    athena_table: str | None,
    athena_workgroup: str | None,
    include_advisor: bool,
    output_format: str,
    output_file: str | None,
    verbose: bool,
) -> None:
    """Generate a least-privilege IAM policy from CloudTrail activity."""
    _configure_logging(verbose)

    # Parse date overrides
    parsed_start = _parse_date(start_date) if start_date else None
    parsed_end = _parse_date(end_date) if end_date else None

    # Auto-detect partition
    if not partition:
        try:
            partition = detect_partition(region)
        except Exception as e:
            partition = "aws"
            console.print(
                f"[yellow]WARNING: Could not detect AWS partition ({e}). "
                f"Defaulting to '{partition}'. Use --partition to override.[/yellow]"
            )

    # Validate Athena options
    if source == "athena":
        if not all([athena_db, athena_table, athena_workgroup]):
            raise click.UsageError(
                "--athena-db, --athena-table, and --athena-workgroup "
                "are required when --source=athena"
            )

    role_name = role_arn.split("/")[-1]
    if parsed_start or parsed_end:
        effective_end_display = (parsed_end or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
        effective_start_display = (parsed_start or (datetime.now(timezone.utc) - timedelta(days=days))).strftime("%Y-%m-%d")
        lookback_display = f"{effective_start_display} to {effective_end_display}"
    else:
        lookback_display = f"{days} days"
    console.print(
        Panel(
            f"[bold]Analyzing role:[/bold] {role_name}\n"
            f"[bold]Source:[/bold] {source}\n"
            f"[bold]Lookback:[/bold] {lookback_display}",
            title="trailpolicy",
        )
    )

    # 1. Fetch events
    with console.status("[bold green]Fetching CloudTrail events..."):
        if source == "athena":
            from .core.athena import fetch_events_athena

            effective_end = parsed_end or datetime.now(timezone.utc)
            effective_start = parsed_start or (effective_end - timedelta(days=days))
            raw_events = fetch_events_athena(
                role_arn=role_arn,
                database=athena_db,
                table=athena_table,
                workgroup=athena_workgroup,
                start_date=effective_start.strftime("%Y-%m-%d"),
                end_date=effective_end.strftime("%Y-%m-%d"),
                region=region,
            )
        else:
            raw_events = fetch_events(
                role_arn=role_arn,
                days=days,
                start_date=parsed_start,
                end_date=parsed_end,
                region=region,
            )
    console.print(f"  Found [bold]{len(raw_events)}[/bold] events")

    if not raw_events:
        console.print("[yellow]No events found. Cannot generate policy.[/yellow]")
        raise SystemExit(1)

    # 2. Parse events
    with console.status("[bold green]Parsing events..."):
        parsed = parse_events(raw_events)
    console.print(f"  Parsed [bold]{len(parsed)}[/bold] valid events")

    # 3. Map actions
    mapper = ActionMapper()
    for event in parsed:
        event.iam_action = mapper.resolve(event.event_source, event.event_name)

    # 4. Extract resources
    with console.status("[bold green]Extracting resource ARNs..."):
        enriched = extract_resources(parsed, partition=partition)

    # 5. Access Advisor (optional)
    advisor_services = None
    if include_advisor:
        try:
            with console.status("[bold green]Querying Access Advisor..."):
                from .core.access_advisor import get_last_accessed

                accessed = get_last_accessed(role_arn, region=region)
                advisor_services = [s.service_namespace for s in accessed]
            console.print(
                f"  Access Advisor: [bold]{len(advisor_services)}[/bold] services accessed"
            )
        except Exception as e:
            console.print(f"[yellow]Access Advisor unavailable: {e}[/yellow]")

    # 6. Build policy
    with console.status("[bold green]Building policy..."):
        policy, metadata = build_policy(enriched, advisor_services=advisor_services)

    # 7. Display summary
    _print_summary(metadata)

    # 8. Format output
    if output_format == "tf":
        output = format_policy_terraform(policy)
    else:
        output = format_policy_json(policy, pretty=True)

    # 9. Write output
    if output_file:
        Path(output_file).write_text(output)
        console.print(f"\n[green]Policy written to {output_file}[/green]")
    else:
        # Policy goes to stdout so it can be piped
        click.echo(output)


@main.command()
@click.option("--role-arn", required=True, help="IAM role ARN to analyze")
@click.option(
    "--days",
    default=60,
    type=click.IntRange(1, MAX_LOOKBACK_DAYS),
    help=f"Lookback period in days (1-{MAX_LOOKBACK_DAYS})",
)
@click.option("--region", help="AWS region")
@click.option("--partition", help="AWS partition (auto-detected from credentials)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def diff(
    role_arn: str,
    days: int,
    region: str | None,
    partition: str | None,
    verbose: bool,
) -> None:
    """Compare existing role policies against CloudTrail-observed activity."""
    _configure_logging(verbose)

    if not partition:
        try:
            partition = detect_partition(region)
        except Exception as e:
            partition = "aws"
            console.print(
                f"[yellow]WARNING: Could not detect AWS partition ({e}). "
                f"Defaulting to '{partition}'. Use --partition to override.[/yellow]"
            )

    role_name = role_arn.split("/")[-1]
    console.print(
        Panel(
            f"[bold]Diffing role:[/bold] {role_name}\n"
            f"[bold]Lookback:[/bold] {days} days",
            title="trailpolicy diff",
        )
    )

    # 1. Fetch events and build generated policy
    with console.status("[bold green]Fetching CloudTrail events..."):
        raw_events = fetch_events(role_arn=role_arn, days=days, region=region)
    console.print(f"  Found [bold]{len(raw_events)}[/bold] events")

    if not raw_events:
        console.print("[yellow]No events found. Cannot compute diff.[/yellow]")
        raise SystemExit(1)

    parsed = parse_events(raw_events)
    mapper = ActionMapper()
    for event in parsed:
        event.iam_action = mapper.resolve(event.event_source, event.event_name)
    enriched = extract_resources(parsed, partition=partition)
    policy, _metadata = build_policy(enriched)

    # 2. Compute diff
    with console.status("[bold green]Fetching current policies and computing diff..."):
        diff_result = compute_diff(role_arn, policy, region=region)

    # 3. Display results
    _print_diff_table(diff_result)

    # 4. Text report to stdout
    click.echo(format_diff_text(diff_result))


@main.command()
@click.option(
    "--policy-file",
    required=True,
    type=click.Path(exists=True),
    help="Path to a JSON policy file to validate",
)
def validate(policy_file: str) -> None:
    """Validate a generated policy file (JSON syntax, size, action format)."""
    errors: list[str] = []
    warnings: list[str] = []

    # 1. Parse JSON
    try:
        content = Path(policy_file).read_text()
        policy = json.loads(content)
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON:[/red] {e}")
        raise SystemExit(1)

    # 2. Check structure
    if "Statement" not in policy:
        # Might be wrapped in PolicyDocument envelope
        if "PolicyDocument" in policy:
            policy = policy["PolicyDocument"]
        else:
            errors.append("Missing 'Statement' key in policy document")

    if "Version" not in policy:
        warnings.append("Missing 'Version' key — recommended value: '2012-10-17'")

    # 3. Check size
    compact = json.dumps(policy, separators=(",", ":"))
    size = len(compact)
    if size > MAX_POLICY_SIZE:
        errors.append(
            f"Policy size ({size:,} chars) exceeds IAM limit ({MAX_POLICY_SIZE:,} chars)"
        )

    # 4. Validate statements
    for i, stmt in enumerate(policy.get("Statement", [])):
        stmt_id = stmt.get("Sid", f"Statement[{i}]")

        if "Effect" not in stmt:
            errors.append(f"{stmt_id}: Missing 'Effect'")
        elif stmt["Effect"] not in ("Allow", "Deny"):
            errors.append(f"{stmt_id}: Invalid Effect '{stmt['Effect']}'")

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not actions:
            errors.append(f"{stmt_id}: No 'Action' specified")
        for action in actions:
            if ":" not in action and action != "*":
                errors.append(f"{stmt_id}: Invalid action format '{action}' (missing ':')")

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if not resources:
            errors.append(f"{stmt_id}: No 'Resource' specified")

    # 5. Display results
    table = Table(title=f"Validation: {policy_file}")
    table.add_column("Check", style="bold")
    table.add_column("Result")

    table.add_row("JSON syntax", "[green]OK[/green]")
    table.add_row("Policy size", f"{size:,} / {MAX_POLICY_SIZE:,} chars")
    table.add_row(
        "Statements",
        str(len(policy.get("Statement", []))),
    )

    console.print(table)

    if warnings:
        for w in warnings:
            console.print(f"[yellow]WARNING:[/yellow] {w}")
    if errors:
        for e in errors:
            console.print(f"[red]ERROR:[/red] {e}")
        raise SystemExit(1)
    else:
        console.print("[green]Policy is valid.[/green]")


def _parse_date(date_str: str) -> datetime:
    """Parse a YYYY-MM-DD date string to a timezone-aware datetime."""
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        raise click.BadParameter(
            f"Invalid date format: {date_str}. Use YYYY-MM-DD."
        )


def _print_summary(metadata) -> None:
    """Print a Rich summary of the generated policy metadata."""
    table = Table(title="Policy Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Total actions", str(metadata.total_actions))
    table.add_row("Total services", str(metadata.total_services))
    table.add_row("Policy size", f"{metadata.policy_size:,} chars")

    if metadata.wildcard_actions:
        table.add_row("Wildcard actions", str(len(metadata.wildcard_actions)))
    if metadata.advisor_only_services:
        table.add_row(
            "Advisor-only services",
            ", ".join(sorted(metadata.advisor_only_services)),
        )

    console.print(table)

    for warning in metadata.warnings:
        console.print(f"[yellow]WARNING:[/yellow] {warning}")


def _print_diff_table(diff_result) -> None:
    """Print a Rich table summarizing the diff result."""
    table = Table(title="Policy Diff Summary")
    table.add_column("Category", style="bold")
    table.add_column("Count")
    table.add_column("Details")

    table.add_row(
        "[green]Matched[/green]",
        str(len(diff_result.matched)),
        "Actions in both policy and CloudTrail",
    )
    table.add_row(
        "[yellow]Unused[/yellow]",
        str(len(diff_result.unused)),
        "In policy but not in CloudTrail (removable)",
    )
    table.add_row(
        "[red]Missing[/red]",
        str(len(diff_result.missing)),
        "In CloudTrail but not in policy",
    )

    console.print(table)
    console.print(
        f"\n  Coverage: [bold]{diff_result.coverage_pct}%[/bold] of "
        f"granted permissions observed in CloudTrail\n"
    )
