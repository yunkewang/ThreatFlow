"""
MITRE ATT&CK and D3FEND index helpers.

This module provides utilities for querying the embedded MITRE mapping YAML
files that ship with ThreatFlow. It intentionally avoids live API calls to
the MITRE TAXII server — the bundled data is sufficient for the ``plan``
command and offline environments.

To update the bundled data, regenerate ``catalog/mappings/d3fend.yaml`` and
``catalog/mappings/attack.yaml`` from the authoritative MITRE sources.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class MitreIndex:
    """
    In-memory index of MITRE ATT&CK techniques and D3FEND countermeasures.

    Loaded from the bundled YAML mapping files. Used by the ``plan`` command
    to suggest response actions given an ATT&CK technique ID.

    Usage::

        index = MitreIndex.load()
        actions = index.d3fend_for_attack("T1059")
    """

    def __init__(
        self,
        attack_techniques: dict[str, Any],
        d3fend_techniques: dict[str, Any],
        attack_to_d3fend: dict[str, list[str]],
        d3fend_to_attack: dict[str, list[str]],
    ) -> None:
        self._attack = attack_techniques
        self._d3fend = d3fend_techniques
        self._attack_to_d3fend = attack_to_d3fend
        self._d3fend_to_attack = d3fend_to_attack

    # ──────────────────────────────────────────
    # Factory
    # ──────────────────────────────────────────

    @classmethod
    def load(cls, mappings_dir: Path | str | None = None) -> "MitreIndex":
        """Load the MITRE index from YAML mapping files.

        Args:
            mappings_dir: Directory containing ``attack.yaml`` and
                ``d3fend.yaml``. Defaults to the bundled catalog.

        Returns:
            Populated :class:`MitreIndex`.
        """
        mappings_dir = Path(mappings_dir) if mappings_dir else cls._default_dir()

        attack_path = mappings_dir / "attack.yaml"
        d3fend_path = mappings_dir / "d3fend.yaml"

        attack_data: dict[str, Any] = {}
        d3fend_data: dict[str, Any] = {}

        if attack_path.exists():
            try:
                attack_data = yaml.safe_load(attack_path.read_text()) or {}
            except yaml.YAMLError as exc:
                logger.warning("Failed to load ATT&CK mappings: %s", exc)

        if d3fend_path.exists():
            try:
                d3fend_data = yaml.safe_load(d3fend_path.read_text()) or {}
            except yaml.YAMLError as exc:
                logger.warning("Failed to load D3FEND mappings: %s", exc)

        # Build cross-reference indexes
        attack_to_d3fend: dict[str, list[str]] = {}
        d3fend_to_attack: dict[str, list[str]] = {}

        for d3fend_id, d3fend_entry in d3fend_data.get("techniques", {}).items():
            counters: list[str] = d3fend_entry.get("counters_attack", [])
            d3fend_to_attack[d3fend_id] = counters
            for attack_id in counters:
                attack_to_d3fend.setdefault(attack_id, []).append(d3fend_id)

        return cls(
            attack_techniques=attack_data.get("techniques", {}),
            d3fend_techniques=d3fend_data.get("techniques", {}),
            attack_to_d3fend=attack_to_d3fend,
            d3fend_to_attack=d3fend_to_attack,
        )

    # ──────────────────────────────────────────
    # Query API
    # ──────────────────────────────────────────

    def get_attack(self, technique_id: str) -> dict[str, Any] | None:
        """Return ATT&CK technique details by ID (prefix match)."""
        technique_id = technique_id.upper()
        # Exact match first
        if technique_id in self._attack:
            return self._attack[technique_id]
        # Prefix match (e.g. T1059 matches T1059.001)
        for tid, details in self._attack.items():
            if tid.startswith(technique_id):
                return details
        return None

    def get_d3fend(self, technique_id: str) -> dict[str, Any] | None:
        """Return D3FEND technique details by ID."""
        return self._d3fend.get(technique_id)

    def d3fend_for_attack(self, technique_id: str) -> list[str]:
        """Return D3FEND technique IDs that counter the given ATT&CK technique."""
        technique_id = technique_id.upper()
        # Collect all matching (technique and sub-techniques)
        results: set[str] = set()
        for attack_id, d3fend_ids in self._attack_to_d3fend.items():
            if attack_id.startswith(technique_id) or technique_id.startswith(attack_id):
                results.update(d3fend_ids)
        return sorted(results)

    def attack_for_d3fend(self, d3fend_id: str) -> list[str]:
        """Return ATT&CK technique IDs that the given D3FEND technique counters."""
        return self._d3fend_to_attack.get(d3fend_id, [])

    def all_attack_ids(self) -> list[str]:
        """Return sorted list of all ATT&CK technique IDs in the index."""
        return sorted(self._attack.keys())

    def all_d3fend_ids(self) -> list[str]:
        """Return sorted list of all D3FEND technique IDs in the index."""
        return sorted(self._d3fend.keys())

    # ──────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────

    @staticmethod
    def _default_dir() -> Path:
        """Resolve the default mappings directory."""
        env_override = os.environ.get("THREATFLOW_MAPPINGS_DIR")
        if env_override:
            return Path(env_override)

        cwd_candidate = Path.cwd() / "catalog" / "mappings"
        if cwd_candidate.exists():
            return cwd_candidate

        # Package-relative path
        pkg_root = Path(__file__).resolve().parents[3]
        return pkg_root / "catalog" / "mappings"
