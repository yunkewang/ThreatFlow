"""
CLI sub-command: ``threatflow run``

    threatflow run <action_id> --provider <provider>
        [--param key=value ...]
        [--inputs-file params.json]
        [--dry-run]
        [--force]    # bypass soft-approval
"""

from __future__ import annotations

import json
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.pretty import Pretty

from threatflow.cli._registry import get_executor, get_registry
from threatflow.core.executor import ActionNotFound, ApprovalRequired, ProviderNotFound
from threatflow.core.models import ApprovalMode

run_app = typer.Typer(
    help="Execute a single response action via a provider.",
    invoke_without_command=True,
)
console = Console()
err_console = Console(stderr=True)


@run_app.callback(invoke_without_command=True)
def run_action(
    ctx: typer.Context,
    action_id: str = typer.Argument(..., help="Action ID to execute (e.g. isolate_host)"),
    provider: str = typer.Option(..., "--provider", "-p", help="Provider adapter to use"),
    params: list[str] = typer.Option(
        [],
        "--param",
        help="Input parameter in key=value format. Repeat for multiple.",
    ),
    inputs_file: Optional[str] = typer.Option(
        None,
        "--inputs-file",
        help="Path to a JSON file with input parameters.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate execution, no real changes."),
    force: bool = typer.Option(
        False,
        "--force",
        help="Bypass soft-approval gate (cannot bypass hard approval).",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output result as JSON."),
) -> None:
    """Execute a single response action against a provider.

    Examples::

        threatflow run isolate_host --provider crowdstrike --param host_id=abc123

        threatflow run disable_user --provider defender \\
            --param user_upn=jdoe@corp.com --param reason="Suspicious login"

        threatflow run isolate_host --provider crowdstrike \\
            --inputs-file host_params.json --dry-run
    """
    # Build params dict from --param flags and/or --inputs-file
    input_params: dict[str, str] = {}

    if inputs_file:
        try:
            with open(inputs_file) as f:
                file_data = json.load(f)
            if not isinstance(file_data, dict):
                err_console.print("[red]--inputs-file must contain a JSON object[/red]")
                raise typer.Exit(1)
            input_params.update(file_data)
        except (OSError, json.JSONDecodeError) as exc:
            err_console.print(f"[red]Failed to read inputs file: {exc}[/red]")
            raise typer.Exit(1)

    for param in params:
        if "=" not in param:
            err_console.print(f"[red]Invalid --param format: '{param}'. Use key=value.[/red]")
            raise typer.Exit(1)
        key, _, value = param.partition("=")
        input_params[key.strip()] = value.strip()

    registry = get_registry()
    executor = get_executor()

    # Check action exists
    action = registry.get(action_id)
    if action is None:
        err_console.print(f"[red]Action '{action_id}' not found in the catalog.[/red]")
        raise typer.Exit(1)

    # Soft approval prompt
    if not dry_run and action.approval_mode == ApprovalMode.SOFT and not force:
        console.print(
            Panel(
                f"[yellow]Action [bold]{action_id}[/bold] requires approval "
                f"(risk: [bold]{action.risk_level.value}[/bold]).[/yellow]\n\n"
                f"Provider: [bold]{provider}[/bold]\n"
                f"Params: {input_params}",
                title="Approval Required",
                border_style="yellow",
            )
        )
        confirmed = typer.confirm("Proceed with execution?", default=False)
        if not confirmed:
            console.print("[yellow]Execution cancelled.[/yellow]")
            raise typer.Exit()

    try:
        result = executor.execute(
            action_id=action_id,
            provider=provider,
            params=input_params,
            dry_run=dry_run,
            approved=force or dry_run,
        )
    except ActionNotFound as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    except ProviderNotFound as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    except ApprovalRequired as exc:
        err_console.print(
            f"[red]Approval required: {exc}[/red]\n"
            "[dim]Hard-approval actions require an out-of-band approval token.[/dim]"
        )
        raise typer.Exit(1)

    if output_json:
        console.print_json(result.model_dump_json(indent=2))
        raise typer.Exit(0 if result.success else 1)

    # Human-readable output
    if result.success:
        status = "[green]SUCCESS[/green]" + (" [dim](dry run)[/dim]" if result.dry_run else "")
        console.print(
            Panel(
                f"{status}\n\n"
                f"[cyan]Message:[/cyan] {result.message}\n\n"
                f"[cyan]Outputs:[/cyan]\n{_fmt_dict(result.outputs)}",
                title=f"[bold]{action_id}[/bold] via {provider}",
                border_style="green" if not result.dry_run else "dim",
            )
        )
    else:
        console.print(
            Panel(
                f"[red]FAILED[/red]\n\n"
                f"[cyan]Message:[/cyan] {result.message}\n"
                f"[cyan]Error:[/cyan] {result.error or 'unknown'}",
                title=f"[bold]{action_id}[/bold] via {provider}",
                border_style="red",
            )
        )
        raise typer.Exit(1)


def _fmt_dict(d: dict) -> str:
    if not d:
        return "  (none)"
    return "\n".join(f"  [bold]{k}[/bold]: {v}" for k, v in d.items())
