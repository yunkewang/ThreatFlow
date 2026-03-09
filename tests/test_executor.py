"""Tests for ActionExecutor."""

from __future__ import annotations

import pytest

from opensecops.core.executor import (
    ActionExecutor,
    ActionNotFound,
    ApprovalRequired,
    ProviderNotFound,
)
from opensecops.core.models import ApprovalMode, RiskLevel
from opensecops.core.registry import ActionRegistry


class TestActionExecutor:
    def test_register_and_get_adapter(
        self, populated_registry: ActionRegistry, crowdstrike_adapter
    ) -> None:
        executor = ActionExecutor(populated_registry)
        executor.register_adapter("crowdstrike", crowdstrike_adapter)
        adapter = executor.get_adapter("crowdstrike")
        assert adapter is crowdstrike_adapter

    def test_get_adapter_missing_raises(self, populated_registry: ActionRegistry) -> None:
        executor = ActionExecutor(populated_registry)
        with pytest.raises(ProviderNotFound, match="nonexistent"):
            executor.get_adapter("nonexistent")

    def test_registered_providers(self, executor_with_adapters: ActionExecutor) -> None:
        providers = executor_with_adapters.registered_providers()
        assert "crowdstrike" in providers
        assert "defender" in providers

    def test_execute_success(self, executor_with_adapters: ActionExecutor) -> None:
        result = executor_with_adapters.execute(
            "isolate_host",
            provider="crowdstrike",
            params={"host_id": "a" * 32},
            approved=True,
        )
        assert result.success is True
        assert result.action_id == "isolate_host"
        assert result.provider == "crowdstrike"

    def test_execute_dry_run(self, executor_with_adapters: ActionExecutor) -> None:
        result = executor_with_adapters.execute(
            "isolate_host",
            provider="crowdstrike",
            params={"host_id": "a" * 32},
            dry_run=True,
        )
        assert result.success is True
        assert result.dry_run is True

    def test_execute_action_not_found(self, executor_with_adapters: ActionExecutor) -> None:
        with pytest.raises(ActionNotFound):
            executor_with_adapters.execute(
                "nonexistent_action",
                provider="crowdstrike",
                params={},
            )

    def test_execute_provider_not_found(self, executor_with_adapters: ActionExecutor) -> None:
        with pytest.raises(ProviderNotFound):
            executor_with_adapters.execute(
                "isolate_host",
                provider="unknown_provider",
                params={"host_id": "a" * 32},
            )

    def test_execute_missing_required_input(self, executor_with_adapters: ActionExecutor) -> None:
        # block_ip has approval_mode=none so we can test validation without approval
        result = executor_with_adapters.execute(
            "block_ip",
            provider="crowdstrike",
            params={},  # missing required ip_address
        )
        assert result.success is False
        assert "validation" in result.message.lower()

    def test_execute_invalid_enum_value(self, executor_with_adapters: ActionExecutor) -> None:
        result = executor_with_adapters.execute(
            "block_ip",
            provider="crowdstrike",
            params={"ip_address": "1.2.3.4", "direction": "diagonal"},
        )
        assert result.success is False

    def test_soft_approval_raises_without_approval(
        self,
        executor_with_adapters: ActionExecutor,
        isolate_host_action,
    ) -> None:
        """isolate_host is soft-approval; executing without approved=True raises."""
        with pytest.raises(ApprovalRequired):
            executor_with_adapters.execute(
                "isolate_host",
                provider="crowdstrike",
                params={"host_id": "a" * 32},
                dry_run=False,
                approved=False,
            )

    def test_soft_approval_succeeds_with_approval(
        self, executor_with_adapters: ActionExecutor
    ) -> None:
        result = executor_with_adapters.execute(
            "isolate_host",
            provider="crowdstrike",
            params={"host_id": "a" * 32},
            dry_run=False,
            approved=True,
        )
        assert result.success is True

    def test_dry_run_bypasses_approval(self, executor_with_adapters: ActionExecutor) -> None:
        """Dry-run should never raise approval errors."""
        result = executor_with_adapters.execute(
            "isolate_host",
            provider="crowdstrike",
            params={"host_id": "a" * 32},
            dry_run=True,
            approved=False,
        )
        assert result.success is True

    def test_validate_returns_errors_for_missing_field(
        self, executor_with_adapters: ActionExecutor
    ) -> None:
        validation = executor_with_adapters.validate(
            "isolate_host", "crowdstrike", {}
        )
        assert not validation.valid
        assert any("host_id" in e.field for e in validation.errors)

    def test_validate_passes_with_correct_params(
        self, executor_with_adapters: ActionExecutor
    ) -> None:
        validation = executor_with_adapters.validate(
            "isolate_host", "crowdstrike", {"host_id": "a" * 32}
        )
        assert validation.valid
