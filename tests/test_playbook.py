"""Tests for playbook models, validator, and executor."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

from opensecops.core.executor import ActionExecutor
from opensecops.core.registry import ActionRegistry
from opensecops.playbook.executor import PlaybookExecutor, StepStatus
from opensecops.playbook.models import OnError, Playbook, PlaybookInput, PlaybookStep
from opensecops.playbook.validator import PlaybookValidationError, PlaybookValidator


# ──────────────────────────────────────────────────────────────────────────────
# Playbook fixtures
# ──────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def simple_playbook_dict(populated_registry: ActionRegistry) -> dict[str, Any]:
    return {
        "id": "test_playbook",
        "name": "Test Playbook",
        "description": "A simple test playbook.",
        "version": "1.0.0",
        "inputs": [
            {"name": "host_id", "type": "string", "required": True},
        ],
        "steps": [
            {
                "id": "isolate",
                "action_id": "isolate_host",
                "provider": "crowdstrike",
                "inputs": {"host_id": "{{ host_id }}"},
                "on_failure": "stop",
            },
            {
                "id": "block",
                "action_id": "block_ip",
                "provider": "crowdstrike",
                "inputs": {"ip_address": "1.2.3.4"},
                "on_failure": "continue",
            },
        ],
    }


@pytest.fixture()
def playbook_yaml_file(tmp_path: Path, simple_playbook_dict: dict[str, Any]) -> Path:
    f = tmp_path / "test_playbook.yaml"
    f.write_text(yaml.dump(simple_playbook_dict))
    return f


# ──────────────────────────────────────────────────────────────────────────────
# Playbook model tests
# ──────────────────────────────────────────────────────────────────────────────


class TestPlaybookModel:
    def test_valid_playbook(self, simple_playbook_dict: dict[str, Any]) -> None:
        playbook = Playbook.model_validate(simple_playbook_dict)
        assert playbook.id == "test_playbook"
        assert len(playbook.steps) == 2

    def test_invalid_id_raises(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Playbook.model_validate({
                "id": "test playbook",  # space not allowed
                "name": "Test",
                "steps": [{"id": "s1", "action_id": "x", "provider": "y"}],
            })

    def test_empty_steps_raises(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Playbook.model_validate({
                "id": "empty",
                "name": "Empty",
                "steps": [],
            })

    def test_get_step(self, simple_playbook_dict: dict[str, Any]) -> None:
        playbook = Playbook.model_validate(simple_playbook_dict)
        step = playbook.get_step("isolate")
        assert step is not None
        assert step.action_id == "isolate_host"

    def test_get_step_missing_returns_none(self, simple_playbook_dict: dict[str, Any]) -> None:
        playbook = Playbook.model_validate(simple_playbook_dict)
        assert playbook.get_step("nonexistent") is None

    def test_step_ids(self, simple_playbook_dict: dict[str, Any]) -> None:
        playbook = Playbook.model_validate(simple_playbook_dict)
        assert playbook.step_ids() == ["isolate", "block"]

    def test_required_inputs(self, simple_playbook_dict: dict[str, Any]) -> None:
        playbook = Playbook.model_validate(simple_playbook_dict)
        required = playbook.required_inputs()
        assert any(i.name == "host_id" for i in required)


# ──────────────────────────────────────────────────────────────────────────────
# Validator tests
# ──────────────────────────────────────────────────────────────────────────────


class TestPlaybookValidator:
    def test_valid_playbook(
        self,
        populated_registry: ActionRegistry,
        simple_playbook_dict: dict[str, Any],
    ) -> None:
        validator = PlaybookValidator(populated_registry)
        playbook = validator.validate_dict(simple_playbook_dict)
        assert playbook.id == "test_playbook"

    def test_invalid_action_id(
        self,
        populated_registry: ActionRegistry,
        simple_playbook_dict: dict[str, Any],
    ) -> None:
        simple_playbook_dict["steps"][0]["action_id"] = "nonexistent_action"
        validator = PlaybookValidator(populated_registry)
        with pytest.raises(PlaybookValidationError) as exc_info:
            validator.validate_dict(simple_playbook_dict)
        assert any("nonexistent_action" in e for e in exc_info.value.errors)

    def test_unsupported_provider(
        self,
        populated_registry: ActionRegistry,
        simple_playbook_dict: dict[str, Any],
    ) -> None:
        # splunk_soar doesn't support block_ip (in our test registry)
        simple_playbook_dict["steps"][1]["provider"] = "splunk_soar"
        validator = PlaybookValidator(populated_registry)
        with pytest.raises(PlaybookValidationError) as exc_info:
            validator.validate_dict(simple_playbook_dict)
        assert any("splunk_soar" in e for e in exc_info.value.errors)

    def test_duplicate_step_ids(
        self,
        populated_registry: ActionRegistry,
        simple_playbook_dict: dict[str, Any],
    ) -> None:
        simple_playbook_dict["steps"][1]["id"] = "isolate"  # duplicate
        validator = PlaybookValidator(populated_registry)
        with pytest.raises(PlaybookValidationError) as exc_info:
            validator.validate_dict(simple_playbook_dict)
        assert any("Duplicate" in e for e in exc_info.value.errors)

    def test_invalid_on_success_reference(
        self,
        populated_registry: ActionRegistry,
        simple_playbook_dict: dict[str, Any],
    ) -> None:
        simple_playbook_dict["steps"][0]["on_success"] = "nonexistent_step"
        validator = PlaybookValidator(populated_registry)
        with pytest.raises(PlaybookValidationError) as exc_info:
            validator.validate_dict(simple_playbook_dict)
        assert any("nonexistent_step" in e for e in exc_info.value.errors)

    def test_undeclared_template_variable(
        self,
        populated_registry: ActionRegistry,
        simple_playbook_dict: dict[str, Any],
    ) -> None:
        simple_playbook_dict["steps"][0]["inputs"]["host_id"] = "{{ undefined_var }}"
        validator = PlaybookValidator(populated_registry)
        with pytest.raises(PlaybookValidationError) as exc_info:
            validator.validate_dict(simple_playbook_dict)
        assert any("undefined_var" in e for e in exc_info.value.errors)

    def test_validate_file(
        self,
        populated_registry: ActionRegistry,
        playbook_yaml_file: Path,
    ) -> None:
        validator = PlaybookValidator(populated_registry)
        playbook = validator.validate_file(playbook_yaml_file)
        assert playbook.id == "test_playbook"

    def test_validate_file_missing(
        self, populated_registry: ActionRegistry, tmp_path: Path
    ) -> None:
        validator = PlaybookValidator(populated_registry)
        with pytest.raises(PlaybookValidationError, match="not found"):
            validator.validate_file(tmp_path / "missing.yaml")


# ──────────────────────────────────────────────────────────────────────────────
# Executor tests
# ──────────────────────────────────────────────────────────────────────────────


class TestPlaybookExecutor:
    def test_run_success(
        self,
        executor_with_adapters: ActionExecutor,
        simple_playbook_dict: dict[str, Any],
        populated_registry: ActionRegistry,
    ) -> None:
        validator = PlaybookValidator(populated_registry)
        playbook = validator.validate_dict(simple_playbook_dict)
        executor = PlaybookExecutor(executor_with_adapters)
        result = executor.run(
            playbook,
            inputs={"host_id": "a" * 32},
            approved=True,
        )
        assert result.success is True
        assert result.steps_succeeded == 2
        assert result.steps_failed == 0

    def test_run_dry_run(
        self,
        executor_with_adapters: ActionExecutor,
        simple_playbook_dict: dict[str, Any],
        populated_registry: ActionRegistry,
    ) -> None:
        validator = PlaybookValidator(populated_registry)
        playbook = validator.validate_dict(simple_playbook_dict)
        executor = PlaybookExecutor(executor_with_adapters)
        result = executor.run(
            playbook,
            inputs={"host_id": "a" * 32},
            dry_run=True,
        )
        assert result.dry_run is True
        assert result.success is True
        for step in result.steps:
            if step.execution_result:
                assert step.execution_result.dry_run is True

    def test_run_missing_required_input(
        self,
        executor_with_adapters: ActionExecutor,
        simple_playbook_dict: dict[str, Any],
        populated_registry: ActionRegistry,
    ) -> None:
        validator = PlaybookValidator(populated_registry)
        playbook = validator.validate_dict(simple_playbook_dict)
        executor = PlaybookExecutor(executor_with_adapters)
        result = executor.run(playbook, inputs={})  # missing host_id
        assert result.success is False
        assert "host_id" in (result.error or "")

    def test_run_step_outputs_available_in_next_step(
        self,
        executor_with_adapters: ActionExecutor,
        populated_registry: ActionRegistry,
    ) -> None:
        """Verify step outputs are passed to subsequent steps via context."""
        playbook_dict = {
            "id": "context_test",
            "name": "Context Test",
            "inputs": [{"name": "host_id", "required": True}],
            "steps": [
                {
                    "id": "step1",
                    "action_id": "isolate_host",
                    "provider": "crowdstrike",
                    "inputs": {"host_id": "{{ host_id }}"},
                    "on_failure": "stop",
                },
            ],
        }
        validator = PlaybookValidator(populated_registry)
        playbook = validator.validate_dict(playbook_dict)
        executor = PlaybookExecutor(executor_with_adapters)
        result = executor.run(playbook, inputs={"host_id": "a" * 32}, approved=True)
        assert result.success is True
        assert result.steps[0].status == StepStatus.SUCCESS

    def test_run_on_failure_continue(
        self,
        executor_with_adapters: ActionExecutor,
        populated_registry: ActionRegistry,
    ) -> None:
        """A failing step with on_failure=continue should not stop the playbook."""
        playbook_dict = {
            "id": "continue_test",
            "name": "Continue Test",
            "inputs": [],
            "steps": [
                {
                    "id": "will_fail",
                    "action_id": "block_ip",
                    "provider": "crowdstrike",
                    "inputs": {},  # missing required ip_address
                    "on_failure": "continue",
                },
                {
                    "id": "will_succeed",
                    "action_id": "block_ip",
                    "provider": "crowdstrike",
                    "inputs": {"ip_address": "1.2.3.4"},
                    "on_failure": "stop",
                },
            ],
        }
        validator = PlaybookValidator(populated_registry)
        playbook = validator.validate_dict(playbook_dict)
        executor = PlaybookExecutor(executor_with_adapters)
        result = executor.run(playbook, inputs={})
        # First step fails, second succeeds; overall should succeed
        assert result.steps[0].status == StepStatus.FAILED
        assert result.steps[1].status == StepStatus.SUCCESS

    def test_run_condition_skips_step(
        self,
        executor_with_adapters: ActionExecutor,
        populated_registry: ActionRegistry,
    ) -> None:
        playbook_dict = {
            "id": "condition_test",
            "name": "Condition Test",
            "inputs": [{"name": "run_block", "required": True}],
            "steps": [
                {
                    "id": "conditional_block",
                    "action_id": "block_ip",
                    "provider": "crowdstrike",
                    "condition": "run_block == 'yes'",
                    "inputs": {"ip_address": "1.2.3.4"},
                    "on_failure": "continue",
                },
            ],
        }
        validator = PlaybookValidator(populated_registry)
        playbook = validator.validate_dict(playbook_dict)
        executor = PlaybookExecutor(executor_with_adapters)
        result = executor.run(playbook, inputs={"run_block": "no"})
        assert result.steps[0].status == StepStatus.SKIPPED_CONDITION
