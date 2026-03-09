"""
Action registry — the in-memory store of all loaded action definitions.

The registry is the single source of truth for available actions during a
session. It supports lookup by ID, filtering by domain/provider/tag, and
querying by ATT&CK technique.
"""

from __future__ import annotations

from typing import Iterator

from opensecops.core.models import Action


class ActionRegistry:
    """
    In-memory catalog of action definitions.

    Typically populated by :class:`~opensecops.core.loader.CatalogLoader`
    at startup, then queried by the CLI and playbook executor.

    Example::

        registry = ActionRegistry()
        registry.register(action)
        action = registry.get("isolate_host")
    """

    def __init__(self) -> None:
        self._actions: dict[str, Action] = {}

    # ──────────────────────────────────────────
    # Mutation
    # ──────────────────────────────────────────

    def register(self, action: Action) -> None:
        """Add or replace an action definition.

        Args:
            action: The :class:`~opensecops.core.models.Action` to register.
        """
        self._actions[action.id] = action

    def register_many(self, actions: list[Action]) -> None:
        """Bulk-register a list of actions."""
        for action in actions:
            self.register(action)

    def unregister(self, action_id: str) -> bool:
        """Remove an action by ID. Returns True if it existed."""
        if action_id in self._actions:
            del self._actions[action_id]
            return True
        return False

    # ──────────────────────────────────────────
    # Lookup
    # ──────────────────────────────────────────

    def get(self, action_id: str) -> Action | None:
        """Return the action with the given ID, or None."""
        return self._actions.get(action_id)

    def get_or_raise(self, action_id: str) -> Action:
        """Return the action or raise :class:`KeyError` if not found."""
        action = self.get(action_id)
        if action is None:
            raise KeyError(f"Action '{action_id}' not found in registry")
        return action

    def __contains__(self, action_id: str) -> bool:
        return action_id in self._actions

    def __len__(self) -> int:
        return len(self._actions)

    def __iter__(self) -> Iterator[Action]:
        return iter(self._actions.values())

    # ──────────────────────────────────────────
    # Filtering
    # ──────────────────────────────────────────

    def list_all(self) -> list[Action]:
        """Return all registered actions sorted by ID."""
        return sorted(self._actions.values(), key=lambda a: a.id)

    def filter(
        self,
        *,
        domain: str | None = None,
        provider: str | None = None,
        tag: str | None = None,
        risk_level: str | None = None,
    ) -> list[Action]:
        """Return actions matching all supplied criteria.

        Args:
            domain: Filter by domain (e.g. ``"endpoint"``).
            provider: Filter to actions that list this provider.
            tag: Filter to actions that include this tag.
            risk_level: Filter by risk level string.

        Returns:
            Sorted list of matching :class:`~opensecops.core.models.Action`.
        """
        results: list[Action] = []
        for action in self._actions.values():
            if domain and action.domain != domain:
                continue
            if provider and provider not in action.supported_providers:
                continue
            if tag and tag not in action.tags:
                continue
            if risk_level and action.risk_level.value != risk_level:
                continue
            results.append(action)
        return sorted(results, key=lambda a: a.id)

    def by_attack_technique(self, technique_id: str) -> list[Action]:
        """Return actions mapped to the given ATT&CK technique ID.

        Args:
            technique_id: Technique ID such as ``"T1059"`` or ``"T1059.001"``.

        Returns:
            Actions whose ATT&CK mappings include the technique (prefix match).
        """
        technique_id = technique_id.upper()
        results = []
        for action in self._actions.values():
            for mapping in action.attack_mappings:
                if mapping.technique_id.startswith(technique_id):
                    results.append(action)
                    break
        return sorted(results, key=lambda a: a.id)

    def by_d3fend_technique(self, technique_id: str) -> list[Action]:
        """Return actions mapped to the given D3FEND technique ID."""
        results = []
        for action in self._actions.values():
            for mapping in action.d3fend_mappings:
                if mapping.technique_id == technique_id:
                    results.append(action)
                    break
        return sorted(results, key=lambda a: a.id)

    def all_domains(self) -> list[str]:
        """Return the sorted unique set of domains in the registry."""
        return sorted({a.domain for a in self._actions.values()})

    def all_providers(self) -> list[str]:
        """Return the sorted unique set of provider IDs across all actions."""
        providers: set[str] = set()
        for action in self._actions.values():
            providers.update(action.supported_providers)
        return sorted(providers)

    def all_tags(self) -> list[str]:
        """Return the sorted unique set of tags across all actions."""
        tags: set[str] = set()
        for action in self._actions.values():
            tags.update(action.tags)
        return sorted(tags)

    # ──────────────────────────────────────────
    # Debug / introspection
    # ──────────────────────────────────────────

    def summary(self) -> dict[str, int]:
        """Return a breakdown of action counts per domain."""
        counts: dict[str, int] = {}
        for action in self._actions.values():
            counts[action.domain] = counts.get(action.domain, 0) + 1
        return dict(sorted(counts.items()))
