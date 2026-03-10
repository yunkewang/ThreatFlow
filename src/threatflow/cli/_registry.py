"""
Shared registry and executor factory for CLI commands.

Centralises catalog loading and adapter registration so every CLI sub-command
gets a consistent, fully-populated registry and executor without duplication.
"""

from __future__ import annotations

from functools import lru_cache

from threatflow.adapters.crowdstrike import CrowdStrikeAdapter
from threatflow.adapters.defender import DefenderAdapter
from threatflow.adapters.splunk_soar import SplunkSOARAdapter
from threatflow.core.executor import ActionExecutor
from threatflow.core.loader import CatalogLoader
from threatflow.core.registry import ActionRegistry


@lru_cache(maxsize=1)
def get_registry() -> ActionRegistry:
    """Load and return the default action catalog (cached for the process lifetime)."""
    loader = CatalogLoader(strict=False)
    return loader.load_default_catalog()


@lru_cache(maxsize=1)
def get_executor() -> ActionExecutor:
    """Return a fully-configured ActionExecutor with all built-in adapters registered."""
    registry = get_registry()
    executor = ActionExecutor(registry)
    # Register built-in adapters with default (unauthenticated) configs.
    # In production, pass config dicts loaded from a secrets manager or env vars.
    executor.register_adapter(CrowdStrikeAdapter.PROVIDER_ID, CrowdStrikeAdapter())
    executor.register_adapter(DefenderAdapter.PROVIDER_ID, DefenderAdapter())
    executor.register_adapter(SplunkSOARAdapter.PROVIDER_ID, SplunkSOARAdapter())
    return executor
