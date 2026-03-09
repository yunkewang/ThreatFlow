"""
Shared pytest fixtures for OpenSecOps tests.
"""

from __future__ import annotations

import pytest

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
)
from opensecops.core.registry import ActionRegistry
from opensecops.core.executor import ActionExecutor
from opensecops.adapters.crowdstrike import CrowdStrikeAdapter
from opensecops.adapters.defender import DefenderAdapter
from opensecops.adapters.splunk_soar import SplunkSOARAdapter


# ──────────────────────────────────────────────────────────────────────────────
# Minimal action fixtures
# ──────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def isolate_host_action() -> Action:
    """A minimal isolate_host action for testing."""
    return Action(
        id="isolate_host",
        name="Isolate Host",
        domain="endpoint",
        description="Isolate a host from the network.",
        risk_level=RiskLevel.HIGH,
        approval_mode=ApprovalMode.SOFT,
        supported_providers=["crowdstrike", "defender", "splunk_soar"],
        inputs=[
            ActionInput(name="host_id", type=InputType.STRING, required=True, description="Host ID"),
            ActionInput(
                name="comment",
                type=InputType.STRING,
                required=False,
                description="Reason",
                default="Isolated via OpenSecOps",
            ),
        ],
        outputs=[
            ActionOutput(name="host_id", type=InputType.STRING, description="Isolated host"),
            ActionOutput(name="status", type=InputType.STRING, description="Status"),
        ],
        d3fend_mappings=[
            D3FENDMapping(technique_id="D3-NI", technique_name="Network Isolation", tactic="Isolate")
        ],
        attack_mappings=[
            ATTACKMapping(technique_id="T1486", technique_name="Data Encrypted for Impact", tactic="Impact")
        ],
        tags=["endpoint", "containment"],
    )


@pytest.fixture()
def block_ip_action() -> Action:
    return Action(
        id="block_ip",
        name="Block IP Address",
        domain="network",
        description="Block an IP address.",
        risk_level=RiskLevel.MEDIUM,
        approval_mode=ApprovalMode.NONE,
        supported_providers=["crowdstrike", "defender"],
        inputs=[
            ActionInput(name="ip_address", type=InputType.STRING, required=True, description="IP"),
            ActionInput(
                name="direction",
                type=InputType.STRING,
                required=False,
                default="both",
                enum=["inbound", "outbound", "both"],
            ),
        ],
        outputs=[
            ActionOutput(name="ip_address", type=InputType.STRING, description="Blocked IP"),
            ActionOutput(name="blocked", type=InputType.BOOLEAN, description="Success flag"),
        ],
        tags=["network", "block"],
    )


@pytest.fixture()
def disable_user_action() -> Action:
    return Action(
        id="disable_user",
        name="Disable User Account",
        domain="identity",
        description="Disable a user account.",
        risk_level=RiskLevel.HIGH,
        approval_mode=ApprovalMode.SOFT,
        supported_providers=["defender"],
        inputs=[
            ActionInput(
                name="user_upn",
                type=InputType.STRING,
                required=True,
                description="User UPN",
            ),
        ],
        outputs=[
            ActionOutput(name="user_upn", type=InputType.STRING, description="UPN"),
            ActionOutput(name="account_enabled", type=InputType.BOOLEAN, description="Status"),
        ],
        tags=["identity", "account"],
    )


@pytest.fixture()
def critical_action() -> Action:
    """An action with critical risk level (should auto-upgrade approval to soft)."""
    return Action(
        id="critical_test",
        name="Critical Test Action",
        domain="endpoint",
        description="Test critical action.",
        risk_level=RiskLevel.CRITICAL,
        approval_mode=ApprovalMode.NONE,  # should be upgraded
        supported_providers=["crowdstrike"],
        inputs=[],
        outputs=[],
    )


# ──────────────────────────────────────────────────────────────────────────────
# Registry and executor fixtures
# ──────────────────────────────────────────────────────────────────────────────


@pytest.fixture()
def populated_registry(
    isolate_host_action: Action,
    block_ip_action: Action,
    disable_user_action: Action,
) -> ActionRegistry:
    registry = ActionRegistry()
    registry.register_many([isolate_host_action, block_ip_action, disable_user_action])
    return registry


@pytest.fixture()
def crowdstrike_adapter() -> CrowdStrikeAdapter:
    return CrowdStrikeAdapter()


@pytest.fixture()
def defender_adapter() -> DefenderAdapter:
    return DefenderAdapter()


@pytest.fixture()
def splunk_soar_adapter() -> SplunkSOARAdapter:
    return SplunkSOARAdapter()


@pytest.fixture()
def executor_with_adapters(populated_registry: ActionRegistry) -> ActionExecutor:
    executor = ActionExecutor(populated_registry)
    executor.register_adapter("crowdstrike", CrowdStrikeAdapter())
    executor.register_adapter("defender", DefenderAdapter())
    executor.register_adapter("splunk_soar", SplunkSOARAdapter())
    return executor
