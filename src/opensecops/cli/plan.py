"""
CLI sub-command: ``opensecops plan``

    opensecops plan --attack-technique T1059.001
    opensecops plan --attack-technique T1486 --provider crowdstrike
"""

from __future__ import annotations

from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from opensecops.cli._registry import get_registry
from opensecops.mappings.mitre import MitreIndex

plan_app = typer.Typer(
    help="Suggest response actions for an ATT&CK technique.",
    invoke_without_command=True,
)
console = Console()
err_console = Console(stderr=True)


@plan_app.callback(invoke_without_command=True)
def plan(
    ctx: typer.Context,
    attack_technique: Optional[str] = typer.Option(
        None,
        "--attack-technique",
        "-t",
        help="ATT&CK technique ID (e.g. T1059, T1486).",
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        "-p",
        help="Filter recommendations to a specific provider.",
    ),
    show_d3fend: bool = typer.Option(
        True,
        "--d3fend/--no-d3fend",
        help="Show D3FEND technique mappings.",
    ),
) -> None:
    """Suggest response actions for an ATT&CK technique.

    Queries the bundled MITRE D3FEND cross-reference to identify relevant
    defensive techniques, then lists OpenSecOps actions that implement them.

    Examples::

        opensecops plan --attack-technique T1486
        opensecops plan --attack-technique T1059.001 --provider crowdstrike
    """
    if ctx.invoked_subcommand is not None:
        return

    if not attack_technique:
        err_console.print("[red]--attack-technique is required.[/red]")
        raise typer.Exit(1)

    registry = get_registry()
    index = MitreIndex.load()

    technique_id = attack_technique.upper()

    # Look up ATT&CK technique info
    attack_info = index.get_attack(technique_id)

    console.print(
        Panel(
            f"[bold cyan]ATT&CK Technique: {technique_id}[/bold cyan]\n"
            + (
                f"[bold]{attack_info.get('name', '')}[/bold]\n"
                f"[dim]{attack_info.get('description', '')}[/dim]\n"
                f"Tactic: {attack_info.get('tactic', 'Unknown')}"
                if attack_info
                else "[yellow]Technique not found in bundled ATT&CK index.[/yellow]"
            ),
            border_style="cyan",
        )
    )

    # Find D3FEND countermeasures
    d3fend_ids = index.d3fend_for_attack(technique_id)

    if show_d3fend:
        if d3fend_ids:
            console.print(f"\n[cyan]D3FEND Countermeasures ({len(d3fend_ids)}):[/cyan]")
            for d3_id in d3fend_ids:
                d3_info = index.get_d3fend(d3_id)
                name = d3_info.get("name", "") if d3_info else ""
                console.print(f"  • [bold]{d3_id}[/bold]  {name}")
        else:
            console.print(
                f"\n[yellow]No D3FEND countermeasures found for {technique_id}.[/yellow]"
            )

    # Find OpenSecOps actions
    actions = registry.by_attack_technique(technique_id)
    if provider:
        actions = [a for a in actions if a.supports_provider(provider)]

    if not actions:
        console.print(
            f"\n[yellow]No OpenSecOps actions found for {technique_id}"
            + (f" with provider '{provider}'" if provider else "")
            + ".[/yellow]"
        )
        console.print(
            "[dim]Consider adding ATT&CK mappings to catalog actions, "
            "or contributing a new action.[/dim]"
        )
        return

    table = Table(
        title=f"\nRecommended Response Actions for {technique_id}",
        box=box.ROUNDED,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Action ID", style="bold", no_wrap=True)
    table.add_column("Name")
    table.add_column("Domain")
    table.add_column("Risk", justify="center")
    table.add_column("Providers")
    table.add_column("D3FEND", overflow="fold")

    for action in actions:
        d3fend_labels = ", ".join(m.technique_id for m in action.d3fend_mappings)
        table.add_row(
            action.id,
            action.name,
            action.domain,
            action.risk_level.value,
            ", ".join(action.supported_providers),
            d3fend_labels,
        )

    console.print(table)
    console.print(
        f"\n[dim]Run [bold]opensecops run <action_id> --provider <provider>[/bold] to execute.[/dim]"
    )
