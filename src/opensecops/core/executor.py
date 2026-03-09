"""
Action executor — resolves the adapter for a provider and executes an action.

The executor is the single entry point for running actions. It handles:
- Provider adapter lookup
- Input validation (required fields, type coercion)
- Approval mode checks
- Dry-run vs real execution dispatch
- Result normalisation
"""

from __future__ import annotations

import logging
from typing import Any

from opensecops.core.models import (
    Action,
    ApprovalMode,
    ExecutionResult,
    ValidationResult,
)
from opensecops.core.registry import ActionRegistry

logger = logging.getLogger(__name__)


class ApprovalRequired(Exception):
    """Raised when an action requires approval that has not been granted."""

    def __init__(self, action_id: str, approval_mode: ApprovalMode) -> None:
        self.action_id = action_id
        self.approval_mode = approval_mode
        super().__init__(
            f"Action '{action_id}' requires {approval_mode.value!r} approval before execution."
        )


class ProviderNotFound(Exception):
    """Raised when no adapter is registered for the requested provider."""

    def __init__(self, provider_id: str) -> None:
        super().__init__(f"No adapter registered for provider '{provider_id}'")


class ActionNotFound(Exception):
    """Raised when the requested action ID is not in the registry."""

    def __init__(self, action_id: str) -> None:
        super().__init__(f"Action '{action_id}' not found in the catalog")


class ActionExecutor:
    """
    Orchestrates action execution through provider adapters.

    Usage::

        executor = ActionExecutor(registry)
        executor.register_adapter("crowdstrike", CrowdStrikeAdapter())
        result = executor.execute(
            "isolate_host",
            provider="crowdstrike",
            params={"host_id": "abc123"},
        )

    The executor does not enforce approval gates itself — the CLI layer is
    responsible for prompting the operator and passing ``approved=True`` once
    confirmed.
    """

    def __init__(self, registry: ActionRegistry) -> None:
        self._registry = registry
        self._adapters: dict[str, Any] = {}  # provider_id -> BaseAdapter

    # ──────────────────────────────────────────
    # Adapter management
    # ──────────────────────────────────────────

    def register_adapter(self, provider_id: str, adapter: Any) -> None:
        """Register a provider adapter.

        Args:
            provider_id: Canonical provider identifier (e.g. ``"crowdstrike"``).
            adapter: An instance implementing :class:`~opensecops.adapters.base.BaseAdapter`.
        """
        self._adapters[provider_id] = adapter
        logger.debug("Registered adapter for provider '%s'", provider_id)

    def get_adapter(self, provider_id: str) -> Any:
        """Return the adapter for *provider_id* or raise :class:`ProviderNotFound`."""
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            raise ProviderNotFound(provider_id)
        return adapter

    def registered_providers(self) -> list[str]:
        """Return sorted list of registered provider IDs."""
        return sorted(self._adapters.keys())

    # ──────────────────────────────────────────
    # Validation
    # ──────────────────────────────────────────

    def validate(
        self,
        action_id: str,
        provider: str,
        params: dict[str, Any],
    ) -> ValidationResult:
        """Validate *params* for *action_id* against the *provider* adapter.

        Returns:
            :class:`~opensecops.core.models.ValidationResult` with any errors.
        """
        action = self._get_action(action_id)
        adapter = self.get_adapter(provider)

        result = ValidationResult.ok()

        # Framework-level required-field check
        for inp in action.get_required_inputs():
            if inp.name not in params and inp.default is None:
                result.add_error(inp.name, f"Required input '{inp.name}' is missing")

        # Enum validation
        for inp in action.inputs:
            if inp.enum and inp.name in params:
                val = params[inp.name]
                if val not in inp.enum:
                    result.add_error(
                        inp.name,
                        f"'{val}' is not a valid value for '{inp.name}'. "
                        f"Allowed: {inp.enum}",
                    )

        # Provider-level validation
        provider_errors = adapter.validate_inputs(action, params)
        for err in provider_errors:
            result.add_error("provider", err)

        return result

    # ──────────────────────────────────────────
    # Execution
    # ──────────────────────────────────────────

    def execute(
        self,
        action_id: str,
        provider: str,
        params: dict[str, Any],
        *,
        dry_run: bool = False,
        approved: bool = False,
    ) -> ExecutionResult:
        """Execute *action_id* via *provider*.

        Args:
            action_id: The action to run.
            provider: The provider adapter to use.
            params: Input parameters for the action.
            dry_run: When True, simulate execution without real side-effects.
            approved: Pass True to bypass soft-approval gates (hard gates
                always require an approval token and cannot be bypassed here).

        Returns:
            :class:`~opensecops.core.models.ExecutionResult`.

        Raises:
            :class:`ActionNotFound`: If *action_id* is not in the registry.
            :class:`ProviderNotFound`: If no adapter is registered for *provider*.
            :class:`ApprovalRequired`: If the action requires approval and
                ``approved=False``.
        """
        action = self._get_action(action_id)
        adapter = self.get_adapter(provider)

        # Approval gate
        if not dry_run:
            self._check_approval(action, approved)

        # Validate inputs
        validation = self.validate(action_id, provider, params)
        if not validation.valid:
            errors_str = "; ".join(f"{e.field}: {e.message}" for e in validation.errors)
            return ExecutionResult.fail(
                action_id=action_id,
                provider=provider,
                error=f"Input validation failed: {errors_str}",
            )

        logger.info(
            "%s action '%s' via '%s'",
            "Dry-running" if dry_run else "Executing",
            action_id,
            provider,
        )

        if dry_run:
            return adapter.dry_run(action, params)

        return adapter.execute(action, params)

    # ──────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────

    def _get_action(self, action_id: str) -> Action:
        action = self._registry.get(action_id)
        if action is None:
            raise ActionNotFound(action_id)
        return action

    @staticmethod
    def _check_approval(action: Action, approved: bool) -> None:
        if action.approval_mode == ApprovalMode.NONE:
            return
        if action.approval_mode == ApprovalMode.SOFT and approved:
            return
        if action.approval_mode == ApprovalMode.HARD:
            # Hard approval always raises — must go through an out-of-band channel
            raise ApprovalRequired(action.id, action.approval_mode)
        if not approved:
            raise ApprovalRequired(action.id, action.approval_mode)
