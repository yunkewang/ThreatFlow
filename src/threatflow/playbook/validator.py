"""
Playbook validator.

Validates playbooks structurally and semantically against the action registry,
without executing any actions. Used by ``threatflow playbook validate``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from threatflow.core.registry import ActionRegistry
from threatflow.playbook.models import Playbook, PlaybookStep

logger = logging.getLogger(__name__)

_TEMPLATE_START = "{{"
_TEMPLATE_END = "}}"


class PlaybookValidationError(Exception):
    """Raised when a playbook fails validation."""

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        self.errors = errors or [message]
        super().__init__(message)


class PlaybookValidator:
    """
    Validates playbook YAML files against the action registry.

    Checks:
    - YAML parses successfully
    - Pydantic schema validates
    - All action IDs exist in the registry
    - All referenced providers support the actions
    - Step ``on_success`` references are valid step IDs
    - Required playbook inputs are declared
    - Template variables in step inputs are resolvable from playbook inputs

    Args:
        registry: Populated :class:`~threatflow.core.registry.ActionRegistry`.
    """

    def __init__(self, registry: ActionRegistry) -> None:
        self._registry = registry

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    def validate_file(self, path: Path | str) -> Playbook:
        """Load and validate a playbook YAML file.

        Args:
            path: Path to the playbook ``.yaml`` file.

        Returns:
            Validated :class:`~threatflow.playbook.models.Playbook`.

        Raises:
            :class:`PlaybookValidationError`: With a list of all errors found.
        """
        path = Path(path)
        if not path.exists():
            raise PlaybookValidationError(f"Playbook file not found: {path}")

        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError) as exc:
            raise PlaybookValidationError(f"Failed to parse YAML: {exc}") from exc

        if not isinstance(data, dict):
            raise PlaybookValidationError("Playbook YAML must be a mapping at the top level")

        return self.validate_dict(data)

    def validate_dict(self, data: dict[str, Any]) -> Playbook:
        """Validate a raw dict representing a playbook.

        Args:
            data: Raw playbook dictionary (typically from YAML).

        Returns:
            Validated :class:`~threatflow.playbook.models.Playbook`.

        Raises:
            :class:`PlaybookValidationError`: With a list of all errors found.
        """
        errors: list[str] = []

        # Schema validation
        try:
            playbook = Playbook.model_validate(data)
        except ValidationError as exc:
            for err in exc.errors():
                loc = " → ".join(str(l) for l in err["loc"])
                errors.append(f"Schema error at '{loc}': {err['msg']}")
            raise PlaybookValidationError(
                f"Playbook schema validation failed ({len(errors)} error(s))",
                errors=errors,
            ) from exc

        # Semantic validation
        errors.extend(self._check_steps(playbook))
        errors.extend(self._check_input_references(playbook))
        errors.extend(self._check_step_routing(playbook))

        if errors:
            raise PlaybookValidationError(
                f"Playbook '{playbook.id}' has {len(errors)} semantic error(s)",
                errors=errors,
            )

        return playbook

    # ──────────────────────────────────────────
    # Semantic checks
    # ──────────────────────────────────────────

    def _check_steps(self, playbook: Playbook) -> list[str]:
        """Verify action IDs exist in the registry and providers support them."""
        errors: list[str] = []
        step_ids: set[str] = set()

        for step in playbook.steps:
            # Duplicate step IDs
            if step.id in step_ids:
                errors.append(f"Duplicate step ID: '{step.id}'")
            step_ids.add(step.id)

            # Action existence
            action = self._registry.get(step.action_id)
            if action is None:
                errors.append(
                    f"Step '{step.id}': action '{step.action_id}' not found in the catalog"
                )
                continue

            # Provider support
            if not action.supports_provider(step.provider):
                errors.append(
                    f"Step '{step.id}': provider '{step.provider}' does not support "
                    f"action '{step.action_id}'. Supported: {action.supported_providers}"
                )

        return errors

    def _check_step_routing(self, playbook: Playbook) -> list[str]:
        """Verify on_success references point to valid step IDs."""
        errors: list[str] = []
        step_ids = set(playbook.step_ids())

        for step in playbook.steps:
            if step.on_success and step.on_success not in step_ids:
                errors.append(
                    f"Step '{step.id}': on_success references unknown step '{step.on_success}'"
                )

        return errors

    def _check_input_references(self, playbook: Playbook) -> list[str]:
        """Check that template variables in step inputs are resolvable.

        Variables may refer to:
        - Declared playbook inputs (e.g. ``{{ host_id }}``)
        - Outputs of a previous step (e.g. ``{{ create_case.case_id }}``)
        """
        errors: list[str] = []
        declared_inputs = {i.name for i in playbook.inputs}
        step_ids = set(playbook.step_ids())

        for step in playbook.steps:
            for param_name, param_value in step.inputs.items():
                if not isinstance(param_value, str):
                    continue
                templates = _extract_templates(param_value)
                for var in templates:
                    # Dot-notation references step outputs: "step_id.key"
                    root = var.split(".")[0].strip()
                    if root in declared_inputs or root in step_ids:
                        continue
                    errors.append(
                        f"Step '{step.id}', input '{param_name}': "
                        f"template variable '{{{{ {var} }}}}' is not declared "
                        f"as a playbook input and does not reference a step ID"
                    )

        return errors


def _extract_templates(value: str) -> list[str]:
    """Extract variable names from ``{{ variable }}`` template strings."""
    variables: list[str] = []
    start = 0
    while True:
        open_idx = value.find("{{", start)
        if open_idx == -1:
            break
        close_idx = value.find("}}", open_idx)
        if close_idx == -1:
            break
        var = value[open_idx + 2 : close_idx].strip()
        if var:
            variables.append(var)
        start = close_idx + 2
    return variables
