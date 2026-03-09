"""
OpenSecOps CLI — main entry point.

Provides the ``opensecops`` command with sub-groups:
    opensecops actions list
    opensecops actions show <id>
    opensecops run <action_id> --provider <provider>
    opensecops plan --attack-technique <technique_id>
    opensecops playbook validate <file>
    opensecops playbook run <file> --inputs <json_file>
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from opensecops import __version__
from opensecops.cli.actions import actions_app
from opensecops.cli.plan import plan_app
from opensecops.cli.playbook import playbook_app

# ──────────────────────────────────────────────────────────────────────────────
# Application setup
# ──────────────────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="opensecops",
    help=(
        "OpenSecOps — vendor-neutral SOC response abstraction framework.\n\n"
        "Standardises security response actions across CrowdStrike, Microsoft Defender, "
        "Splunk SOAR, and more. Maps actions to MITRE D3FEND and ATT&CK."
    ),
    no_args_is_help=True,
    add_completion=True,
    pretty_exceptions_enable=False,
)

app.add_typer(actions_app, name="actions")
app.add_typer(plan_app, name="plan")
app.add_typer(playbook_app, name="playbook")

console = Console()
err_console = Console(stderr=True)


# ──────────────────────────────────────────────────────────────────────────────
# Global options
# ──────────────────────────────────────────────────────────────────────────────


def version_callback(value: bool) -> None:
    if value:
        console.print(f"opensecops v{__version__}")
        raise typer.Exit()


@app.callback()
def global_options(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """OpenSecOps — vendor-neutral SOC response framework."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
    else:
        logging.basicConfig(level=logging.WARNING, stream=sys.stderr)


# ──────────────────────────────────────────────────────────────────────────────
# run command (top-level, not a sub-app, to avoid Typer routing issues)
# ──────────────────────────────────────────────────────────────────────────────


@app.command("run")
def run_action(
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
        help="Bypass soft-approval gate.",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output result as JSON."),
) -> None:
    """Execute a single response action against a provider.

    Examples:

        opensecops run isolate_host --provider crowdstrike --param host_id=abc123 --dry-run

        opensecops run block_ip --provider defender --param ip_address=1.2.3.4 --force
    """
    from opensecops.cli._registry import get_executor, get_registry
    from opensecops.core.executor import ActionNotFound, ApprovalRequired, ProviderNotFound
    from opensecops.core.models import ApprovalMode

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
        err_console.print(f"[red]Approval required: {exc}[/red]")
        raise typer.Exit(1)

    if output_json:
        console.print_json(result.model_dump_json(indent=2))
        raise typer.Exit(0 if result.success else 1)

    if result.success:
        status = "[green]SUCCESS[/green]" + (" [dim](dry run)[/dim]" if result.dry_run else "")
        outputs_str = "\n".join(f"  [bold]{k}[/bold]: {v}" for k, v in result.outputs.items()) or "  (none)"
        console.print(
            Panel(
                f"{status}\n\n[cyan]Message:[/cyan] {result.message}\n\n[cyan]Outputs:[/cyan]\n{outputs_str}",
                title=f"[bold]{action_id}[/bold] via {provider}",
                border_style="green" if not result.dry_run else "dim",
            )
        )
    else:
        console.print(
            Panel(
                f"[red]FAILED[/red]\n\n[cyan]Message:[/cyan] {result.message}\n[cyan]Error:[/cyan] {result.error or 'unknown'}",
                title=f"[bold]{action_id}[/bold] via {provider}",
                border_style="red",
            )
        )
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
