"""
CLI sub-commands: ``threatflow playbook``

    threatflow playbook validate <file>
    threatflow playbook run <file> --inputs <json_file> [--dry-run] [--force]
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from threatflow.cli._registry import get_executor, get_registry
from threatflow.playbook.executor import PlaybookExecutor, PlaybookRunResult, StepStatus
from threatflow.playbook.validator import PlaybookValidationError, PlaybookValidator

playbook_app = typer.Typer(
    help="Validate and run YAML playbooks.",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


@playbook_app.command("validate")
def playbook_validate(
    file: Path = typer.Argument(..., help="Path to the playbook YAML file.", exists=True),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show step-level details."),
) -> None:
    """Validate a playbook YAML file without executing any actions.

    Checks schema correctness, action catalog references, provider support,
    and template variable declarations.

    Examples::

        threatflow playbook validate playbooks/ransomware_response.yaml
    """
    registry = get_registry()
    validator = PlaybookValidator(registry)

    try:
        playbook = validator.validate_file(file)
    except PlaybookValidationError as exc:
        console.print(Panel(
            "\n".join(f"  [red]✗[/red] {e}" for e in exc.errors),
            title=f"[red]Validation FAILED — {file.name}[/red]",
            border_style="red",
        ))
        raise typer.Exit(1)

    # Success
    console.print(Panel(
        f"[green]✓[/green] Playbook [bold]{playbook.id}[/bold] is valid.\n"
        f"[dim]{playbook.description}[/dim]\n\n"
        f"[cyan]Steps:[/cyan] {len(playbook.steps)}  "
        f"[cyan]Version:[/cyan] {playbook.version}  "
        f"[cyan]Inputs:[/cyan] {len(playbook.inputs)}",
        title=f"[green]Valid — {file.name}[/green]",
        border_style="green",
    ))

    if verbose:
        _print_step_summary(playbook)


@playbook_app.command("run")
def playbook_run(
    file: Path = typer.Argument(..., help="Path to the playbook YAML file.", exists=True),
    inputs_file: Optional[Path] = typer.Option(
        None,
        "--inputs",
        "-i",
        help="JSON file with playbook input variables.",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate all steps, no real changes."),
    force: bool = typer.Option(
        False,
        "--force",
        help="Bypass soft-approval gates on all steps.",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output run result as JSON."),
) -> None:
    """Run a playbook YAML file.

    Validates the playbook first, then executes each step in order using
    the configured provider adapters.

    Examples::

        threatflow playbook run playbooks/ransomware_response.yaml \\
            --inputs incident_inputs.json

        threatflow playbook run playbooks/phishing_response.yaml \\
            --inputs inputs.json --dry-run
    """
    registry = get_registry()
    validator = PlaybookValidator(registry)

    # Validate first
    try:
        playbook = validator.validate_file(file)
    except PlaybookValidationError as exc:
        for err in exc.errors:
            err_console.print(f"[red]✗ {err}[/red]")
        raise typer.Exit(1)

    # Load inputs
    inputs: dict = {}
    if inputs_file:
        try:
            inputs = json.loads(inputs_file.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            err_console.print(f"[red]Failed to read inputs file: {exc}[/red]")
            raise typer.Exit(1)

    # Announce
    console.print(Panel(
        f"[bold]{playbook.name}[/bold]\n"
        f"[dim]{playbook.description}[/dim]\n\n"
        f"[cyan]Steps:[/cyan] {len(playbook.steps)}  "
        f"[cyan]Mode:[/cyan] {'[yellow]DRY RUN[/yellow]' if dry_run else '[green]LIVE[/green]'}",
        title=f"Running playbook: [bold]{playbook.id}[/bold]",
        border_style="cyan",
    ))

    executor = PlaybookExecutor(get_executor())
    result = executor.run(playbook, inputs=inputs, dry_run=dry_run, approved=force)

    if output_json:
        # Serialize manually since StepResult uses dataclasses
        console.print_json(json.dumps(_result_to_dict(result), indent=2))
        raise typer.Exit(0 if result.success else 1)

    _print_run_result(result, playbook.id)
    raise typer.Exit(0 if result.success else 1)


# ──────────────────────────────────────────────────────────────────────────────
# Rendering
# ──────────────────────────────────────────────────────────────────────────────


def _print_step_summary(playbook: "Playbook") -> None:  # type: ignore[name-defined]
    table = Table("Step ID", "Action", "Provider", "On Failure", box=box.SIMPLE)
    for step in playbook.steps:
        table.add_row(step.id, step.action_id, step.provider, step.on_failure.value)
    console.print(table)


def _print_run_result(result: PlaybookRunResult, playbook_id: str) -> None:
    table = Table(
        "Step", "Status", "Message",
        box=box.ROUNDED,
        header_style="bold cyan",
        expand=True,
        title=f"Playbook Run: [bold]{playbook_id}[/bold]",
    )

    status_styles = {
        StepStatus.SUCCESS: "green",
        StepStatus.FAILED: "red",
        StepStatus.SKIPPED: "yellow",
        StepStatus.SKIPPED_CONDITION: "dim yellow",
        StepStatus.RUNNING: "cyan",
        StepStatus.PENDING: "dim",
    }

    for step_result in result.steps:
        colour = status_styles.get(step_result.status, "white")
        message = ""
        if step_result.execution_result:
            message = step_result.execution_result.message
        elif step_result.error:
            message = step_result.error
        elif step_result.skipped_reason:
            message = step_result.skipped_reason

        table.add_row(
            step_result.step_id,
            Text(step_result.status.value, style=colour),
            message[:120] + ("…" if len(message) > 120 else ""),
        )

    console.print(table)

    # Summary
    summary_colour = "green" if result.success else "red"
    summary_icon = "✓" if result.success else "✗"
    console.print(
        f"\n[{summary_colour}]{summary_icon} Playbook {'succeeded' if result.success else 'FAILED'}.[/{summary_colour}]  "
        f"Succeeded: {result.steps_succeeded}  "
        f"Failed: {result.steps_failed}  "
        f"Skipped: {result.steps_skipped}"
        + (" [dim](dry run)[/dim]" if result.dry_run else "")
    )
    if result.error:
        console.print(f"[red]Error: {result.error}[/red]")


def _result_to_dict(result: PlaybookRunResult) -> dict:
    return {
        "playbook_id": result.playbook_id,
        "success": result.success,
        "dry_run": result.dry_run,
        "error": result.error,
        "steps": [
            {
                "step_id": sr.step_id,
                "status": sr.status.value,
                "error": sr.error,
                "skipped_reason": sr.skipped_reason,
                "outputs": sr.execution_result.outputs if sr.execution_result else {},
                "message": sr.execution_result.message if sr.execution_result else "",
            }
            for sr in result.steps
        ],
    }
