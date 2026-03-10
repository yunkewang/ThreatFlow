"""
Playbook domain models.

A playbook is a YAML-defined sequence of ThreatFlow actions that form a
response workflow. Playbooks are deliberately simple in v1 — they are
ordered step lists with basic conditional branching (``on_success``,
``on_failure``) and input variable substitution via ``{{ var }}`` templates.

For complex orchestration, playbooks can be chained or wrapped in a higher-
level CACAO-compatible workflow engine in future versions.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class PlaybookInput(BaseModel):
    """An input variable declared by a playbook."""

    name: str = Field(..., description="Variable name (snake_case)")
    type: str = Field("string", description="Data type")
    required: bool = Field(True)
    description: str = Field("")
    default: Any = Field(None)
    example: Any = Field(None)


class OnError(str, Enum):
    """What to do when a step fails."""

    STOP = "stop"       # Halt the playbook, report failure
    CONTINUE = "continue"  # Log error, move to next step
    SKIP = "skip"       # Mark step skipped, continue


class PlaybookStep(BaseModel):
    """A single step in a playbook."""

    id: str = Field(..., description="Unique step identifier within the playbook")
    name: str = Field("", description="Human-readable step name")
    action_id: str = Field(..., description="ThreatFlow action to execute")
    provider: str = Field(..., description="Provider adapter to use")
    inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Input values; may use {{ variable }} template syntax",
    )
    condition: str | None = Field(
        None,
        description="Optional Python-safe boolean expression to gate this step",
    )
    on_success: str | None = Field(
        None,
        description="Next step ID on success. If None, proceed to next step.",
    )
    on_failure: OnError = Field(
        OnError.STOP,
        description="Behaviour on step failure",
    )
    dry_run: bool = Field(
        False,
        description="Force dry-run for this step regardless of global setting",
    )
    tags: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def id_must_be_identifier(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Step ID '{v}' must be alphanumeric (hyphens and underscores OK)")
        return v


class Playbook(BaseModel):
    """
    A complete playbook definition.

    Example::

        playbook = Playbook.model_validate_yaml(path.read_text())
    """

    id: str = Field(..., description="Unique playbook identifier")
    name: str = Field(..., description="Human-readable playbook name")
    description: str = Field("", description="What this playbook does")
    version: str = Field("1.0.0", description="Playbook schema version")
    author: str = Field("", description="Playbook author")
    severity: str = Field(
        "medium",
        description="Intended incident severity (informational, low, medium, high, critical)",
    )
    triggers: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique IDs or alert names that should trigger this playbook",
    )
    inputs: list[PlaybookInput] = Field(
        default_factory=list,
        description="Playbook-level input variables",
    )
    steps: list[PlaybookStep] = Field(..., description="Ordered response steps", min_length=1)
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list, description="Reference URLs")

    @field_validator("id")
    @classmethod
    def id_snake_case(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Playbook ID '{v}' must be alphanumeric")
        return v

    def get_step(self, step_id: str) -> PlaybookStep | None:
        """Look up a step by ID."""
        return next((s for s in self.steps if s.id == step_id), None)

    def get_step_index(self, step_id: str) -> int | None:
        """Return the 0-based index of a step by ID."""
        for i, s in enumerate(self.steps):
            if s.id == step_id:
                return i
        return None

    def step_ids(self) -> list[str]:
        """Return ordered list of step IDs."""
        return [s.id for s in self.steps]

    def required_inputs(self) -> list[PlaybookInput]:
        """Return only required input declarations."""
        return [i for i in self.inputs if i.required]
