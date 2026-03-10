"""
Core domain models for ThreatFlow.

All models use Pydantic v2 for validation and serialization. These are the
canonical types that flow through the entire framework — adapters, playbooks,
and the CLI all operate on these types.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class RiskLevel(str, Enum):
    """Risk classification for a response action.

    Determines default approval requirements and audit verbosity.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalMode(str, Enum):
    """Whether human approval is required before executing the action.

    - ``none``: execute immediately, no approval gate.
    - ``soft``: prompt the operator; can be skipped with ``--force``.
    - ``hard``: requires explicit out-of-band approval token; cannot be bypassed.
    """

    NONE = "none"
    SOFT = "soft"
    HARD = "hard"


class InputType(str, Enum):
    """Supported input/output field types for action schemas."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    NUMBER = "number"
    LIST = "list"
    DICT = "dict"


class ActionInput(BaseModel):
    """Defines a single input parameter for an action."""

    name: str = Field(..., description="Parameter name (snake_case)")
    type: InputType = Field(..., description="Data type of the parameter")
    required: bool = Field(True, description="Whether the parameter is mandatory")
    description: str = Field("", description="Human-readable description")
    default: Any = Field(None, description="Default value if not provided")
    enum: list[str] | None = Field(None, description="Allowed values (for string type)")
    example: Any = Field(None, description="Example value for documentation")

    @field_validator("name")
    @classmethod
    def name_must_be_snake_case(cls, v: str) -> str:
        if not v.replace("_", "").isalnum():
            raise ValueError(f"Input name '{v}' must be alphanumeric with underscores only")
        return v


class ActionOutput(BaseModel):
    """Defines a single output field produced by a successful action execution."""

    name: str = Field(..., description="Output field name (snake_case)")
    type: InputType = Field(..., description="Data type of the output")
    description: str = Field("", description="Human-readable description")
    example: Any = Field(None, description="Example value for documentation")


class D3FENDMapping(BaseModel):
    """Maps this action to a MITRE D3FEND defensive technique."""

    technique_id: str = Field(..., description="D3FEND technique ID (e.g. D3-IB)")
    technique_name: str = Field(..., description="D3FEND technique name")
    tactic: str = Field("", description="D3FEND tactic category")
    url: str = Field("", description="Reference URL")

    @field_validator("technique_id")
    @classmethod
    def validate_d3fend_id(cls, v: str) -> str:
        if not v.startswith("D3-"):
            raise ValueError(f"D3FEND technique ID must start with 'D3-', got '{v}'")
        return v


class ATTACKMapping(BaseModel):
    """Maps the adversary technique this action is designed to counter."""

    technique_id: str = Field(..., description="ATT&CK technique ID (e.g. T1059.001)")
    technique_name: str = Field(..., description="ATT&CK technique name")
    tactic: str = Field("", description="ATT&CK tactic (e.g. Execution)")
    url: str = Field("", description="Reference URL")

    @field_validator("technique_id")
    @classmethod
    def validate_attack_id(cls, v: str) -> str:
        if not v.upper().startswith("T"):
            raise ValueError(f"ATT&CK technique ID must start with 'T', got '{v}'")
        return v.upper()


class Action(BaseModel):
    """
    A vendor-neutral security response action definition.

    Actions are loaded from YAML catalog files and represent abstract operations
    (e.g. ``isolate_host``) that can be executed via a provider adapter.
    """

    id: str = Field(..., description="Unique action identifier (snake_case)")
    name: str = Field(..., description="Human-readable action name")
    domain: str = Field(
        ...,
        description="Security domain: endpoint, identity, email, network, case",
    )
    description: str = Field(..., description="What this action does")
    inputs: list[ActionInput] = Field(default_factory=list)
    outputs: list[ActionOutput] = Field(default_factory=list)
    risk_level: RiskLevel = Field(..., description="Risk classification")
    approval_mode: ApprovalMode = Field(
        ApprovalMode.NONE,
        description="Human approval gate",
    )
    supported_providers: list[str] = Field(
        default_factory=list,
        description="Provider IDs that implement this action",
    )
    d3fend_mappings: list[D3FENDMapping] = Field(default_factory=list)
    attack_mappings: list[ATTACKMapping] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    version: str = Field("1.0.0", description="Action schema version")

    @field_validator("id")
    @classmethod
    def id_must_be_snake_case(cls, v: str) -> str:
        if not v.replace("_", "").isalnum():
            raise ValueError(f"Action ID '{v}' must be alphanumeric with underscores only")
        return v

    @model_validator(mode="after")
    def high_risk_requires_approval(self) -> "Action":
        """Critical actions must have at least soft approval."""
        if self.risk_level == RiskLevel.CRITICAL and self.approval_mode == ApprovalMode.NONE:
            self.approval_mode = ApprovalMode.SOFT
        return self

    def get_required_inputs(self) -> list[ActionInput]:
        """Return only the required input definitions."""
        return [i for i in self.inputs if i.required]

    def get_input(self, name: str) -> ActionInput | None:
        """Look up an input definition by name."""
        return next((i for i in self.inputs if i.name == name), None)

    def supports_provider(self, provider_id: str) -> bool:
        """Return True if this action is implemented by the given provider."""
        return provider_id in self.supported_providers


class ExecutionResult(BaseModel):
    """
    Result of executing a single action through a provider adapter.

    Both real executions and dry-runs produce this type so callers can treat
    them uniformly.
    """

    success: bool = Field(..., description="Whether the action completed without error")
    action_id: str = Field(..., description="The action that was executed")
    provider: str = Field(..., description="The provider adapter used")
    outputs: dict[str, Any] = Field(default_factory=dict, description="Action output values")
    message: str = Field("", description="Human-readable status message")
    error: str | None = Field(None, description="Error detail if success=False")
    raw_response: dict[str, Any] = Field(
        default_factory=dict,
        description="Provider-native response payload",
    )
    dry_run: bool = Field(False, description="True if this was a simulation only")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Execution metadata (duration, request ID, etc.)",
    )

    @classmethod
    def ok(
        cls,
        action_id: str,
        provider: str,
        outputs: dict[str, Any] | None = None,
        message: str = "Action completed successfully.",
        raw_response: dict[str, Any] | None = None,
        dry_run: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> "ExecutionResult":
        """Factory for successful results."""
        return cls(
            success=True,
            action_id=action_id,
            provider=provider,
            outputs=outputs or {},
            message=message,
            raw_response=raw_response or {},
            dry_run=dry_run,
            metadata=metadata or {},
        )

    @classmethod
    def fail(
        cls,
        action_id: str,
        provider: str,
        error: str,
        message: str = "",
        raw_response: dict[str, Any] | None = None,
        dry_run: bool = False,
    ) -> "ExecutionResult":
        """Factory for failed results."""
        return cls(
            success=False,
            action_id=action_id,
            provider=provider,
            outputs={},
            message=message or f"Action failed: {error}",
            error=error,
            raw_response=raw_response or {},
            dry_run=dry_run,
        )


class ValidationError(BaseModel):
    """A single input validation error."""

    field: str
    message: str


class ValidationResult(BaseModel):
    """Aggregated result of validating action inputs against a provider."""

    valid: bool
    errors: list[ValidationError] = Field(default_factory=list)

    @classmethod
    def ok(cls) -> "ValidationResult":
        return cls(valid=True)

    @classmethod
    def fail(cls, errors: list[ValidationError]) -> "ValidationResult":
        return cls(valid=False, errors=errors)

    def add_error(self, field: str, message: str) -> None:
        self.valid = False
        self.errors.append(ValidationError(field=field, message=message))


class ProviderInfo(BaseModel):
    """Metadata about a registered provider adapter."""

    id: str
    name: str
    description: str = ""
    version: str = "0.1.0"
    capabilities: list[str] = Field(default_factory=list)
    config_schema: dict[str, Any] = Field(default_factory=dict)


# ──────────────────────────────────────────────
# Type aliases
# ──────────────────────────────────────────────

Domain = Literal["endpoint", "identity", "email", "network", "case"]
