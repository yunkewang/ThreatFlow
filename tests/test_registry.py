"""Tests for ActionRegistry."""

from __future__ import annotations

import pytest

from opensecops.core.registry import ActionRegistry
from opensecops.core.models import Action, RiskLevel, ApprovalMode


class TestActionRegistry:
    def test_register_and_get(self, isolate_host_action: Action) -> None:
        registry = ActionRegistry()
        registry.register(isolate_host_action)
        assert registry.get("isolate_host") is isolate_host_action

    def test_get_missing_returns_none(self) -> None:
        registry = ActionRegistry()
        assert registry.get("nonexistent") is None

    def test_get_or_raise(self, isolate_host_action: Action) -> None:
        registry = ActionRegistry()
        registry.register(isolate_host_action)
        action = registry.get_or_raise("isolate_host")
        assert action is isolate_host_action

    def test_get_or_raise_missing(self) -> None:
        registry = ActionRegistry()
        with pytest.raises(KeyError, match="isolate_host"):
            registry.get_or_raise("isolate_host")

    def test_contains(self, isolate_host_action: Action) -> None:
        registry = ActionRegistry()
        registry.register(isolate_host_action)
        assert "isolate_host" in registry
        assert "missing" not in registry

    def test_len(self, populated_registry: ActionRegistry) -> None:
        assert len(populated_registry) == 3

    def test_iter(self, populated_registry: ActionRegistry) -> None:
        ids = {a.id for a in populated_registry}
        assert "isolate_host" in ids

    def test_unregister(self, isolate_host_action: Action) -> None:
        registry = ActionRegistry()
        registry.register(isolate_host_action)
        assert registry.unregister("isolate_host") is True
        assert registry.get("isolate_host") is None
        assert registry.unregister("isolate_host") is False

    def test_filter_by_domain(self, populated_registry: ActionRegistry) -> None:
        results = populated_registry.filter(domain="endpoint")
        assert all(a.domain == "endpoint" for a in results)
        assert any(a.id == "isolate_host" for a in results)

    def test_filter_by_provider(self, populated_registry: ActionRegistry) -> None:
        results = populated_registry.filter(provider="defender")
        for action in results:
            assert "defender" in action.supported_providers

    def test_filter_by_tag(self, populated_registry: ActionRegistry) -> None:
        results = populated_registry.filter(tag="containment")
        assert any(a.id == "isolate_host" for a in results)

    def test_filter_by_risk_level(self, populated_registry: ActionRegistry) -> None:
        results = populated_registry.filter(risk_level="medium")
        assert all(a.risk_level.value == "medium" for a in results)

    def test_by_attack_technique(self, populated_registry: ActionRegistry) -> None:
        results = populated_registry.by_attack_technique("T1486")
        assert any(a.id == "isolate_host" for a in results)

    def test_by_attack_technique_prefix_match(self, populated_registry: ActionRegistry) -> None:
        # T1486 should match T1486 exactly
        results = populated_registry.by_attack_technique("T1486")
        assert len(results) > 0

    def test_by_d3fend_technique(self, populated_registry: ActionRegistry) -> None:
        results = populated_registry.by_d3fend_technique("D3-NI")
        assert any(a.id == "isolate_host" for a in results)

    def test_all_domains(self, populated_registry: ActionRegistry) -> None:
        domains = populated_registry.all_domains()
        assert "endpoint" in domains
        assert "network" in domains
        assert "identity" in domains
        assert domains == sorted(domains)

    def test_all_providers(self, populated_registry: ActionRegistry) -> None:
        providers = populated_registry.all_providers()
        assert "crowdstrike" in providers
        assert "defender" in providers
        assert providers == sorted(providers)

    def test_all_tags(self, populated_registry: ActionRegistry) -> None:
        tags = populated_registry.all_tags()
        assert "containment" in tags
        assert "endpoint" in tags

    def test_summary(self, populated_registry: ActionRegistry) -> None:
        summary = populated_registry.summary()
        assert summary.get("endpoint", 0) >= 1

    def test_list_all_sorted(self, populated_registry: ActionRegistry) -> None:
        actions = populated_registry.list_all()
        ids = [a.id for a in actions]
        assert ids == sorted(ids)

    def test_register_many(self) -> None:
        registry = ActionRegistry()
        actions = [
            Action(
                id=f"action_{i}",
                name=f"Action {i}",
                domain="endpoint",
                description="Test",
                risk_level=RiskLevel.LOW,
                supported_providers=[],
            )
            for i in range(5)
        ]
        registry.register_many(actions)
        assert len(registry) == 5
