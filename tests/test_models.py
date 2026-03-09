"""Tests for core domain models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from opensecops.core.models import (
    Action,
    ActionInput,
    ActionOutput,
    ApprovalMode,
    ATTACKMapping,
    D3FENDMapping,
    ExecutionResult,
    InputType,
    RiskLevel,
    ValidationResult,
)


class TestActionInput:
    def test_valid_input(self) -> None:
        inp = ActionInput(name="host_id", type=InputType.STRING, required=True)
        assert inp.name == "host_id"
        assert inp.required is True

    def test_invalid_name_raises(self) -> None:
        with pytest.raises(ValidationError):
            ActionInput(name="host-id", type=InputType.STRING)

    def test_optional_defaults(self) -> None:
        inp = ActionInput(name="comment", type=InputType.STRING, required=False, default="ok")
        assert inp.required is False
        assert inp.default == "ok"


class TestD3FENDMapping:
    def test_valid_d3fend(self) -> None:
        m = D3FENDMapping(technique_id="D3-NI", technique_name="Network Isolation")
        assert m.technique_id == "D3-NI"

    def test_invalid_prefix_raises(self) -> None:
        with pytest.raises(ValidationError):
            D3FENDMapping(technique_id="NI-1234", technique_name="Invalid")


class TestATTACKMapping:
    def test_valid_attack(self) -> None:
        m = ATTACKMapping(technique_id="T1486", technique_name="Ransomware", tactic="Impact")
        assert m.technique_id == "T1486"

    def test_lowercase_normalised(self) -> None:
        m = ATTACKMapping(technique_id="t1486", technique_name="Ransomware")
        assert m.technique_id == "T1486"

    def test_invalid_prefix_raises(self) -> None:
        with pytest.raises(ValidationError):
            ATTACKMapping(technique_id="X1234", technique_name="Bad")


class TestAction:
    def test_minimal_valid_action(self) -> None:
        action = Action(
            id="isolate_host",
            name="Isolate Host",
            domain="endpoint",
            description="Isolate a host.",
            risk_level=RiskLevel.HIGH,
            supported_providers=["crowdstrike"],
        )
        assert action.id == "isolate_host"
        assert action.domain == "endpoint"

    def test_invalid_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            Action(
                id="isolate-host",  # hyphen not allowed
                name="Isolate Host",
                domain="endpoint",
                description="Test",
                risk_level=RiskLevel.LOW,
                supported_providers=[],
            )

    def test_critical_risk_auto_upgrades_approval(self) -> None:
        """Critical risk + none approval should silently upgrade to soft."""
        action = Action(
            id="nuke_it",
            name="Nuke",
            domain="endpoint",
            description="Very dangerous.",
            risk_level=RiskLevel.CRITICAL,
            approval_mode=ApprovalMode.NONE,
            supported_providers=["crowdstrike"],
        )
        assert action.approval_mode == ApprovalMode.SOFT

    def test_get_required_inputs(self) -> None:
        action = Action(
            id="test_action",
            name="Test",
            domain="endpoint",
            description="Test",
            risk_level=RiskLevel.LOW,
            supported_providers=[],
            inputs=[
                ActionInput(name="required_field", type=InputType.STRING, required=True),
                ActionInput(name="optional_field", type=InputType.STRING, required=False),
            ],
        )
        required = action.get_required_inputs()
        assert len(required) == 1
        assert required[0].name == "required_field"

    def test_supports_provider(self) -> None:
        action = Action(
            id="test_action",
            name="Test",
            domain="endpoint",
            description="Test",
            risk_level=RiskLevel.LOW,
            supported_providers=["crowdstrike", "defender"],
        )
        assert action.supports_provider("crowdstrike")
        assert action.supports_provider("defender")
        assert not action.supports_provider("splunk_soar")

    def test_get_input_by_name(self) -> None:
        action = Action(
            id="test_action",
            name="Test",
            domain="endpoint",
            description="Test",
            risk_level=RiskLevel.LOW,
            supported_providers=[],
            inputs=[ActionInput(name="host_id", type=InputType.STRING)],
        )
        inp = action.get_input("host_id")
        assert inp is not None
        assert inp.name == "host_id"
        assert action.get_input("nonexistent") is None


class TestExecutionResult:
    def test_ok_factory(self) -> None:
        result = ExecutionResult.ok(
            action_id="isolate_host",
            provider="crowdstrike",
            outputs={"host_id": "abc", "status": "contained"},
            message="Host isolated.",
        )
        assert result.success is True
        assert result.action_id == "isolate_host"
        assert result.provider == "crowdstrike"
        assert result.outputs["status"] == "contained"
        assert result.error is None
        assert result.dry_run is False

    def test_fail_factory(self) -> None:
        result = ExecutionResult.fail(
            action_id="isolate_host",
            provider="crowdstrike",
            error="API timeout",
        )
        assert result.success is False
        assert result.error == "API timeout"
        assert "failed" in result.message.lower()

    def test_dry_run_flag(self) -> None:
        result = ExecutionResult.ok(
            action_id="test", provider="cs", dry_run=True
        )
        assert result.dry_run is True


class TestValidationResult:
    def test_ok(self) -> None:
        result = ValidationResult.ok()
        assert result.valid is True
        assert result.errors == []

    def test_fail_with_errors(self) -> None:
        from opensecops.core.models import ValidationError as VError
        result = ValidationResult.fail([VError(field="host_id", message="Required")])
        assert result.valid is False
        assert len(result.errors) == 1

    def test_add_error(self) -> None:
        result = ValidationResult.ok()
        result.add_error("field", "Bad value")
        assert not result.valid
        assert result.errors[0].field == "field"
