"""
Base adapter interface.

All provider adapters must extend :class:`BaseAdapter` and implement its
abstract methods. The interface is intentionally minimal — the contract covers
capability discovery, input validation, execution, dry-run, and native-action
mapping.

Adapter authors should also provide a ``PROVIDER_ID`` class attribute used by
the adapter auto-discovery mechanism.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from opensecops.core.models import Action, ExecutionResult, ProviderInfo


@dataclass
class NativeActionMapping:
    """
    Describes how an abstract OpenSecOps action maps to a provider-native
    API call or workflow.

    Adapters return this from :meth:`BaseAdapter.map_native_action` so that
    callers can inspect (or log) the underlying provider operation without
    executing it.
    """

    provider: str
    native_action: str
    native_params: dict[str, Any] = field(default_factory=dict)
    notes: str = ""
    documentation_url: str = ""


class BaseAdapter(ABC):
    """
    Abstract base class for all OpenSecOps provider adapters.

    Subclasses must implement five methods:

    - :meth:`provider_info` — adapter metadata.
    - :meth:`get_capabilities` — supported action IDs.
    - :meth:`validate_inputs` — provider-level param checking.
    - :meth:`execute` — real action execution.
    - :meth:`dry_run` — simulated execution (no side-effects).
    - :meth:`map_native_action` — return the native API call for an action.

    Adapters are stateless with respect to action execution; any provider
    session/auth state should be initialised in ``__init__``.
    """

    #: Override in subclasses with the canonical provider ID string.
    PROVIDER_ID: str = ""

    # ──────────────────────────────────────────
    # Metadata
    # ──────────────────────────────────────────

    @abstractmethod
    def provider_info(self) -> ProviderInfo:
        """Return static metadata about this adapter and provider.

        Returns:
            :class:`~opensecops.core.models.ProviderInfo` describing the adapter.
        """

    @abstractmethod
    def get_capabilities(self) -> list[str]:
        """Return the list of action IDs this adapter can execute.

        Returns:
            List of action ID strings (e.g. ``["isolate_host", "kill_process"]``).
        """

    # ──────────────────────────────────────────
    # Validation
    # ──────────────────────────────────────────

    @abstractmethod
    def validate_inputs(self, action: Action, params: dict[str, Any]) -> list[str]:
        """Perform provider-specific input validation.

        The framework already validates required fields and enum constraints
        before calling this method. Implement provider-specific checks here
        (e.g. UUID format, field length limits, cross-field dependencies).

        Args:
            action: The abstract action definition.
            params: Caller-supplied input parameters.

        Returns:
            List of human-readable error strings. Empty list means valid.
        """

    # ──────────────────────────────────────────
    # Execution
    # ──────────────────────────────────────────

    @abstractmethod
    def execute(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Execute the action against the provider.

        This method MUST produce real side-effects (API calls, state changes).
        Implementations should catch provider API errors and return a failed
        :class:`~opensecops.core.models.ExecutionResult` rather than raising.

        Args:
            action: The abstract action definition.
            params: Validated input parameters.

        Returns:
            :class:`~opensecops.core.models.ExecutionResult`.
        """

    @abstractmethod
    def dry_run(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Simulate execution without producing real side-effects.

        Should validate that the action *could* succeed (e.g. check connectivity,
        resolve entity IDs) and return a representative result with
        ``dry_run=True``.

        Args:
            action: The abstract action definition.
            params: Input parameters.

        Returns:
            :class:`~opensecops.core.models.ExecutionResult` with ``dry_run=True``.
        """

    @abstractmethod
    def map_native_action(self, action: Action) -> NativeActionMapping:
        """Return the provider-native action that implements this abstraction.

        This is used for documentation, audit logging, and operator review.
        No execution occurs.

        Args:
            action: The abstract action to map.

        Returns:
            :class:`NativeActionMapping` describing the underlying API call.
        """

    # ──────────────────────────────────────────
    # Optional helpers (with default implementations)
    # ──────────────────────────────────────────

    def supports_action(self, action_id: str) -> bool:
        """Return True if this adapter can execute the given action ID."""
        return action_id in self.get_capabilities()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(provider={self.PROVIDER_ID!r})"
