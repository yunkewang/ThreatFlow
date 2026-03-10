"""Tests for provider adapters (CrowdStrike, Defender, Splunk SOAR)."""

from __future__ import annotations

import pytest

from threatflow.adapters.base import BaseAdapter, NativeActionMapping
from threatflow.adapters.crowdstrike import CrowdStrikeAdapter
from threatflow.adapters.defender import DefenderAdapter
from threatflow.adapters.splunk_soar import SplunkSOARAdapter
from threatflow.core.models import Action, RiskLevel


# ──────────────────────────────────────────────────────────────────────────────
# Common adapter contract tests (parameterised)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "adapter_cls",
    [CrowdStrikeAdapter, DefenderAdapter, SplunkSOARAdapter],
)
class TestAdapterContract:
    """All adapters must satisfy the BaseAdapter interface contract."""

    def test_is_base_adapter_subclass(self, adapter_cls: type) -> None:
        assert issubclass(adapter_cls, BaseAdapter)

    def test_has_provider_id(self, adapter_cls: type) -> None:
        assert adapter_cls.PROVIDER_ID != ""

    def test_provider_info(self, adapter_cls: type) -> None:
        adapter = adapter_cls()
        info = adapter.provider_info()
        assert info.id == adapter_cls.PROVIDER_ID
        assert info.name

    def test_get_capabilities_returns_list(self, adapter_cls: type) -> None:
        adapter = adapter_cls()
        caps = adapter.get_capabilities()
        assert isinstance(caps, list)
        assert len(caps) > 0

    def test_supports_action(self, adapter_cls: type) -> None:
        adapter = adapter_cls()
        caps = adapter.get_capabilities()
        assert adapter.supports_action(caps[0])
        assert not adapter.supports_action("action_that_does_not_exist_xyz")


# ──────────────────────────────────────────────────────────────────────────────
# CrowdStrike adapter
# ──────────────────────────────────────────────────────────────────────────────


class TestCrowdStrikeAdapter:
    def test_isolate_host(
        self,
        crowdstrike_adapter: CrowdStrikeAdapter,
        isolate_host_action: Action,
    ) -> None:
        result = crowdstrike_adapter.execute(
            isolate_host_action, {"host_id": "a" * 32, "comment": "test"}
        )
        assert result.success is True
        assert result.provider == "crowdstrike"
        assert result.outputs["host_id"] == "a" * 32
        assert result.outputs["status"] == "contained"

    def test_dry_run(
        self,
        crowdstrike_adapter: CrowdStrikeAdapter,
        isolate_host_action: Action,
    ) -> None:
        result = crowdstrike_adapter.dry_run(isolate_host_action, {"host_id": "a" * 32})
        assert result.success is True
        assert result.dry_run is True

    def test_map_native_action(
        self,
        crowdstrike_adapter: CrowdStrikeAdapter,
        isolate_host_action: Action,
    ) -> None:
        mapping = crowdstrike_adapter.map_native_action(isolate_host_action)
        assert isinstance(mapping, NativeActionMapping)
        assert mapping.provider == "crowdstrike"
        assert "contain" in mapping.native_params.get("action_name", "")

    def test_validate_short_host_id(
        self,
        crowdstrike_adapter: CrowdStrikeAdapter,
        isolate_host_action: Action,
    ) -> None:
        errors = crowdstrike_adapter.validate_inputs(
            isolate_host_action, {"host_id": "short"}
        )
        assert len(errors) > 0

    def test_validate_correct_host_id(
        self,
        crowdstrike_adapter: CrowdStrikeAdapter,
        isolate_host_action: Action,
    ) -> None:
        errors = crowdstrike_adapter.validate_inputs(
            isolate_host_action, {"host_id": "a" * 32}
        )
        assert errors == []

    def test_unsupported_action(
        self,
        crowdstrike_adapter: CrowdStrikeAdapter,
        disable_user_action: Action,
    ) -> None:
        """disable_user is not in CrowdStrike capabilities."""
        result = crowdstrike_adapter.execute(disable_user_action, {"user_upn": "x@y.com"})
        assert result.success is False

    def test_block_ip(self, crowdstrike_adapter: CrowdStrikeAdapter, block_ip_action: Action) -> None:
        result = crowdstrike_adapter.execute(
            block_ip_action, {"ip_address": "1.2.3.4", "direction": "both"}
        )
        assert result.success is True
        assert result.outputs["ip_address"] == "1.2.3.4"
        assert result.outputs["blocked"] is True


# ──────────────────────────────────────────────────────────────────────────────
# Defender adapter
# ──────────────────────────────────────────────────────────────────────────────


class TestDefenderAdapter:
    def test_disable_user(
        self,
        defender_adapter: DefenderAdapter,
        disable_user_action: Action,
    ) -> None:
        result = defender_adapter.execute(
            disable_user_action, {"user_upn": "jdoe@corp.com"}
        )
        assert result.success is True
        assert result.outputs["user_upn"] == "jdoe@corp.com"
        assert result.outputs["account_enabled"] is False

    def test_validate_bad_upn_format(
        self,
        defender_adapter: DefenderAdapter,
        disable_user_action: Action,
    ) -> None:
        errors = defender_adapter.validate_inputs(
            disable_user_action, {"user_upn": "just_username"}
        )
        assert len(errors) > 0
        assert "UPN" in errors[0]

    def test_validate_good_upn(
        self,
        defender_adapter: DefenderAdapter,
        disable_user_action: Action,
    ) -> None:
        errors = defender_adapter.validate_inputs(
            disable_user_action, {"user_upn": "user@domain.com"}
        )
        assert errors == []

    def test_isolate_host(
        self,
        defender_adapter: DefenderAdapter,
        isolate_host_action: Action,
    ) -> None:
        result = defender_adapter.execute(
            isolate_host_action, {"host_id": "machine-id-xyz", "comment": "Test"}
        )
        assert result.success is True
        assert "mde_action_id" in result.outputs

    def test_dry_run(
        self,
        defender_adapter: DefenderAdapter,
        isolate_host_action: Action,
    ) -> None:
        result = defender_adapter.dry_run(isolate_host_action, {"host_id": "abc"})
        assert result.dry_run is True
        assert result.success is True


# ──────────────────────────────────────────────────────────────────────────────
# Splunk SOAR adapter
# ──────────────────────────────────────────────────────────────────────────────


class TestSplunkSOARAdapter:
    def test_create_case(self, splunk_soar_adapter: SplunkSOARAdapter) -> None:
        from threatflow.core.models import Action, RiskLevel, ApprovalMode
        action = Action(
            id="create_case",
            name="Create Case",
            domain="case",
            description="Create case",
            risk_level=RiskLevel.LOW,
            supported_providers=["splunk_soar"],
        )
        result = splunk_soar_adapter.execute(
            action, {"title": "Test Case", "severity": "high"}
        )
        assert result.success is True
        assert "container_id" in result.outputs
        assert result.outputs["title"] == "Test Case"

    def test_validate_requires_container_id(
        self,
        splunk_soar_adapter: SplunkSOARAdapter,
        isolate_host_action: Action,
    ) -> None:
        errors = splunk_soar_adapter.validate_inputs(
            isolate_host_action, {"host_id": "abc"}
        )
        assert any("container_id" in e for e in errors)

    def test_validate_passes_with_container_id(
        self,
        splunk_soar_adapter: SplunkSOARAdapter,
        isolate_host_action: Action,
    ) -> None:
        errors = splunk_soar_adapter.validate_inputs(
            isolate_host_action, {"host_id": "abc", "container_id": "1234"}
        )
        assert errors == []

    def test_isolate_host(
        self,
        splunk_soar_adapter: SplunkSOARAdapter,
        isolate_host_action: Action,
    ) -> None:
        result = splunk_soar_adapter.execute(
            isolate_host_action,
            {"host_id": "device-abc", "container_id": "9999"},
        )
        assert result.success is True
        assert "action_run_id" in result.outputs

    def test_dry_run(
        self,
        splunk_soar_adapter: SplunkSOARAdapter,
        isolate_host_action: Action,
    ) -> None:
        result = splunk_soar_adapter.dry_run(
            isolate_host_action, {"host_id": "abc", "container_id": "1"}
        )
        assert result.dry_run is True
        assert "DRY RUN" in result.message
