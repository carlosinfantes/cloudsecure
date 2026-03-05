"""CloudSecure CLI - Main entry point."""

import os
import sys
import time
import webbrowser

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .api import CloudSecureAPI
from .config import resolve_api_endpoint

console = Console()


def _get_env_default(key: str, fallback: str = "") -> str:
    """Get default from environment or .env file in project root."""
    val = os.environ.get(key)
    if val:
        return val
    # Try reading .env from common locations
    for env_path in [".env", os.path.join(os.path.dirname(__file__), "../../.env")]:
        try:
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f"{key}=") and not line.startswith("#"):
                        return line.split("=", 1)[1].strip().strip('"').strip("'")
        except FileNotFoundError:
            continue
    return fallback


def _build_client(profile, region, env_name) -> CloudSecureAPI:
    """Build a SigV4-signed API client."""
    endpoint = resolve_api_endpoint(profile=profile, region=region, env_name=env_name)
    return CloudSecureAPI(endpoint, profile=profile, region=region)


@click.group()
@click.version_option(version=__version__, prog_name="cloudsecure")
@click.option("--profile", default=None, envvar="AWS_PROFILE",
              help="AWS profile name")
@click.option("--region", default=None, envvar="AWS_REGION",
              help="AWS region")
@click.option("--env", "env_name", default="dev", envvar="CLOUDSECURE_ENV",
              help="CloudSecure environment (dev/test/prod)")
@click.pass_context
def cli(ctx, profile, region, env_name):
    """CloudSecure Assessment Platform CLI."""
    ctx.ensure_object(dict)
    ctx.obj["profile"] = profile
    ctx.obj["region"] = region
    ctx.obj["env_name"] = env_name


@cli.command()
@click.option("--account-id", required=True, help="12-digit AWS account ID to assess")
@click.option("--role-arn", required=True, help="IAM role ARN for assessment access")
@click.option("--external-id", required=True, help="External ID for role assumption")
@click.option("--customer-id", default=None, help="Optional customer identifier")
@click.option("--scope", multiple=True, default=None,
              help="Scan scope: iam, s3, network, encryption, cloudtrail, ec2, rds, vpc. Repeat for multiple. Default: all")
@click.option("--no-wait", is_flag=True, help="Don't wait for completion")
@click.pass_context
def assess(ctx, account_id, role_arn, external_id, customer_id, scope, no_wait):
    """Start a new security assessment."""
    client = _build_client(ctx.obj["profile"], ctx.obj["region"], ctx.obj["env_name"])

    body = {
        "accountId": account_id,
        "roleArn": role_arn,
        "externalId": external_id,
    }
    if customer_id:
        body["customerId"] = customer_id
    if scope:
        body["scope"] = list(scope)

    try:
        result = client.post("assessments", body)
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    assessment_id = result.get("assessmentId")
    console.print(f"[green]Assessment started:[/green] {assessment_id}")

    if no_wait:
        console.print(f"Run [cyan]cloudsecure status {assessment_id}[/cyan] to check progress.")
        return

    # Poll for completion
    console.print("")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running assessment...", total=None)

        while True:
            time.sleep(10)
            try:
                status_data = client.get(f"assessments/{assessment_id}")
                status = status_data.get("status", "UNKNOWN")
                progress.update(task, description=f"Assessment status: {status}")

                if status in ("COMPLETED", "FAILED"):
                    break
            except RuntimeError:
                pass

    # Print results
    console.print("")
    if status == "COMPLETED":
        console.print("[green]Assessment completed![/green]")
        _print_assessment_summary(status_data)
        console.print(f"\nDownload report: [cyan]cloudsecure report {assessment_id} --open[/cyan]")
    else:
        console.print(f"[red]Assessment failed:[/red] {status_data.get('errorMessage', 'Unknown error')}")
        sys.exit(1)


@cli.command()
@click.argument("assessment_id", required=False)
@click.pass_context
def status(ctx, assessment_id):
    """Show assessment status or list all assessments."""
    client = _build_client(ctx.obj["profile"], ctx.obj["region"], ctx.obj["env_name"])

    if assessment_id:
        try:
            data = client.get(f"assessments/{assessment_id}")
        except RuntimeError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)

        _print_assessment_summary(data)
    else:
        try:
            data = client.get("assessments")
        except RuntimeError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)

        assessments = data.get("assessments", data.get("items", []))
        if not assessments:
            console.print("No assessments found.")
            return

        table = Table(title="Assessments")
        table.add_column("ID", style="cyan", max_width=36)
        table.add_column("Account", style="white")
        table.add_column("Status", style="bold")
        table.add_column("Created", style="dim")

        for a in assessments:
            status_style = {
                "COMPLETED": "green",
                "FAILED": "red",
                "RUNNING": "yellow",
                "PENDING": "dim",
            }.get(a.get("status", ""), "white")

            table.add_row(
                a.get("assessmentId", ""),
                a.get("accountId", ""),
                f"[{status_style}]{a.get('status', '')}[/{status_style}]",
                a.get("createdAt", ""),
            )

        console.print(table)


@cli.command()
@click.argument("assessment_id")
@click.option("--format", "fmt", type=click.Choice(["html", "json", "csv"]),
              default="html", help="Report format")
@click.option("--output", "-o", "output_path", default=None,
              help="Output file path (default: cloudsecure-report.<format>)")
@click.option("--open", "open_browser", is_flag=True,
              help="Open report in browser after download")
@click.pass_context
def report(ctx, assessment_id, fmt, output_path, open_browser):
    """Download an assessment report."""
    client = _build_client(ctx.obj["profile"], ctx.obj["region"], ctx.obj["env_name"])

    try:
        data = client.get(f"assessments/{assessment_id}/report?format={fmt}")
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    # Handle presigned URL response
    download_url = data.get("url") or data.get("downloadUrl") or data.get("reportUrl")
    if download_url:
        import requests as req
        resp = req.get(download_url, timeout=60)
        if resp.status_code >= 400:
            console.print(f"[red]Error:[/red] Failed to download report (HTTP {resp.status_code})")
            sys.exit(1)
        content = resp.content
    else:
        content = data.get("body", data.get("report", "")).encode()

    if not output_path:
        output_path = f"cloudsecure-report.{fmt}"

    with open(output_path, "wb") as f:
        f.write(content)

    console.print(f"[green]Report saved:[/green] {output_path}")

    if open_browser and fmt == "html":
        webbrowser.open(f"file://{os.path.abspath(output_path)}")


def _print_assessment_summary(data: dict) -> None:
    """Print a formatted assessment summary."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold")
    table.add_column("Value")

    fields = [
        ("Assessment ID", data.get("assessmentId", "")),
        ("Account", data.get("accountId", "")),
        ("Status", data.get("status", "")),
        ("Created", data.get("createdAt", "")),
    ]

    # Optional fields
    if data.get("riskScore") is not None:
        fields.append(("Risk Score", f"{data['riskScore']}/100"))
    if data.get("riskLevel"):
        fields.append(("Risk Level", data["riskLevel"]))
    if data.get("totalFindings") is not None:
        fields.append(("Total Findings", str(data["totalFindings"])))
    if data.get("completedAt"):
        fields.append(("Completed", data["completedAt"]))

    for label, value in fields:
        table.add_row(label, str(value))

    console.print(table)


if __name__ == "__main__":
    cli()
