"""
CLI sub-commands: ``threatflow actions``

    threatflow actions list [--domain D] [--provider P] [--tag T]
    threatflow actions show <action_id>
"""

from __future__ import annotations

from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from threatflow.cli._registry import get_registry
from threatflow.core.models import Action, RiskLevel

actions_app = typer.Typer(
    help="Browse and inspect the action catalog.",
    no_args_is_help=True,
)
console = Console()

_RISK_COLOURS = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bold red",
}


@actions_app.command("list")
def actions_list(
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by domain"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="Filter by provider"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Filter by tag"),
    risk_level: Optional[str] = typer.Option(None, "--risk", "-r", help="Filter by risk level"),
) -> None:
    """List available response actions."""
    registry = get_registry()
    actions = registry.filter(domain=domain, provider=provider, tag=tag, risk_level=risk_level)

    if not actions:
        console.print("[yellow]No actions match the given filters.[/yellow]")
        raise typer.Exit()

    table = Table(
        title=f"ThreatFlow Action Catalog ({len(actions)} action(s))",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("ID", style="bold", no_wrap=True, min_width=20)
    table.add_column("Name", min_width=24)
    table.add_column("Domain", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("Approval", justify="center")
    table.add_column("Providers")
    table.add_column("Tags", overflow="fold")

    for action in actions:
        risk_colour = _RISK_COLOURS.get(action.risk_level, "white")
        table.add_row(
            action.id,
            action.name,
            action.domain,
            Text(action.risk_level.value, style=risk_colour),
            action.approval_mode.value,
            ", ".join(action.supported_providers),
            ", ".join(action.tags),
        )

    console.print(table)

    # Summary line
    domains = registry.all_domains()
    console.print(
        f"\n[dim]Domains: {', '.join(domains)}. "
        f"Run [bold]threatflow actions show <id>[/bold] for details.[/dim]"
    )


@actions_app.command("show")
def actions_show(
    action_id: str = typer.Argument(..., help="Action ID to display"),
) -> None:
    """Show detailed information about a single action."""
    registry = get_registry()
    action = registry.get(action_id)

    if action is None:
        console.print(f"[red]Action '{action_id}' not found.[/red]")
        _suggest_similar(action_id, registry)
        raise typer.Exit(1)

    _render_action_detail(action)


# ──────────────────────────────────────────────────────────────────────────────
# Rendering helpers
# ──────────────────────────────────────────────────────────────────────────────


def _render_action_detail(action: Action) -> None:
    risk_colour = _RISK_COLOURS.get(action.risk_level, "white")

    # Header panel
    console.print(
        Panel(
            f"[bold]{action.name}[/bold]\n"
            f"[dim]{action.description}[/dim]\n\n"
            f"[cyan]Domain:[/cyan] {action.domain}  "
            f"[cyan]Risk:[/cyan] [{risk_colour}]{action.risk_level.value}[/{risk_colour}]  "
            f"[cyan]Approval:[/cyan] {action.approval_mode.value}  "
            f"[cyan]Version:[/cyan] {action.version}",
            title=f"[bold cyan]{action.id}[/bold cyan]",
            border_style="cyan",
        )
    )

    # Inputs
    if action.inputs:
        in_table = Table("Name", "Type", "Required", "Default", "Description", box=box.SIMPLE)
        for inp in action.inputs:
            in_table.add_row(
                f"[bold]{inp.name}[/bold]",
                inp.type.value,
                "✓" if inp.required else "–",
                str(inp.default) if inp.default is not None else "–",
                inp.description,
            )
        console.print(Panel(in_table, title="Inputs", border_style="blue"))

    # Outputs
    if action.outputs:
        out_table = Table("Name", "Type", "Description", box=box.SIMPLE)
        for out in action.outputs:
            out_table.add_row(out.name, out.type.value, out.description)
        console.print(Panel(out_table, title="Outputs", border_style="blue"))

    # Providers
    console.print(
        f"[cyan]Supported providers:[/cyan] {', '.join(action.supported_providers) or 'none'}"
    )

    # D3FEND mappings
    if action.d3fend_mappings:
        console.print("\n[cyan]D3FEND Mappings:[/cyan]")
        for m in action.d3fend_mappings:
            console.print(f"  • [{m.technique_id}] {m.technique_name}")

    # ATT&CK mappings
    if action.attack_mappings:
        console.print("\n[cyan]ATT&CK Mappings (counters):[/cyan]")
        for m in action.attack_mappings:
            console.print(f"  • [{m.technique_id}] {m.technique_name}  [dim]{m.tactic}[/dim]")

    # Tags
    if action.tags:
        console.print(f"\n[cyan]Tags:[/cyan] {', '.join(action.tags)}")


def _suggest_similar(action_id: str, registry: "ActionRegistry") -> None:  # type: ignore[name-defined]
    from threatflow.core.registry import ActionRegistry

    similar = [
        a.id
        for a in registry.list_all()
        if action_id.lower() in a.id.lower() or a.id.lower() in action_id.lower()
    ]
    if similar:
        console.print(f"[dim]Did you mean: {', '.join(similar)}?[/dim]")
