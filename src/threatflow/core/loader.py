"""
Catalog loader — reads YAML action definitions and populates the registry.

Catalog YAML files live under ``catalog/actions/`` by default, but the path
can be overridden via ``THREATFLOW_CATALOG_DIR`` or by passing a directory to
:meth:`CatalogLoader.load_directory`.
"""

from __future__ import annotations

import importlib.resources
import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from threatflow.core.models import Action
from threatflow.core.registry import ActionRegistry

logger = logging.getLogger(__name__)


class CatalogLoadError(Exception):
    """Raised when a catalog file cannot be parsed or validated."""


class CatalogLoader:
    """
    Loads action definitions from YAML files into an :class:`ActionRegistry`.

    Typical usage::

        loader = CatalogLoader()
        registry = loader.load_default_catalog()
        action = registry.get("isolate_host")

    The default catalog is resolved in this order:

    1. ``THREATFLOW_CATALOG_DIR`` environment variable.
    2. A ``catalog/actions`` directory relative to the current working directory.
    3. The bundled catalog shipped with the package.
    """

    _DEFAULT_CATALOG_SUBDIR = "catalog/actions"

    def __init__(self, strict: bool = False) -> None:
        """
        Args:
            strict: When True, raise :class:`CatalogLoadError` on any invalid
                action definition. When False, log a warning and skip it.
        """
        self.strict = strict

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────

    def load_default_catalog(self) -> ActionRegistry:
        """Load the default catalog and return a populated registry."""
        catalog_dir = self._resolve_catalog_dir()
        return self.load_directory(catalog_dir)

    def load_directory(self, directory: Path | str) -> ActionRegistry:
        """Load all ``.yaml``/``.yml`` files from *directory* into a registry.

        Args:
            directory: Path to a directory of action YAML files.

        Returns:
            Populated :class:`ActionRegistry`.

        Raises:
            :class:`CatalogLoadError`: If *directory* does not exist and
                ``strict=True``.
        """
        directory = Path(directory)
        registry = ActionRegistry()

        if not directory.exists():
            msg = f"Catalog directory not found: {directory}"
            if self.strict:
                raise CatalogLoadError(msg)
            logger.warning(msg)
            return registry

        yaml_files = sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml"))
        if not yaml_files:
            logger.warning("No YAML files found in catalog directory: %s", directory)

        for path in yaml_files:
            try:
                actions = self.load_file(path)
                registry.register_many(actions)
                logger.debug("Loaded %d action(s) from %s", len(actions), path.name)
            except CatalogLoadError as exc:
                if self.strict:
                    raise
                logger.warning("Skipping %s: %s", path.name, exc)

        logger.info(
            "Catalog loaded: %d action(s) from %d file(s)",
            len(registry),
            len(yaml_files),
        )
        return registry

    def load_file(self, path: Path | str) -> list[Action]:
        """Parse a single YAML catalog file.

        The file may contain either:
        - A single action document (mapping with an ``id`` key), or
        - A list of action documents under an ``actions`` key.

        Args:
            path: Path to the YAML file.

        Returns:
            List of validated :class:`Action` objects.

        Raises:
            :class:`CatalogLoadError`: On YAML parse or Pydantic validation error.
        """
        path = Path(path)
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError) as exc:
            raise CatalogLoadError(f"Failed to read {path}: {exc}") from exc

        if data is None:
            return []

        # Support both single-action files and multi-action files
        if isinstance(data, dict) and "actions" in data:
            items: list[Any] = data["actions"]
        elif isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data
        else:
            raise CatalogLoadError(f"Unexpected YAML structure in {path}")

        actions: list[Action] = []
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                raise CatalogLoadError(f"Action #{i} in {path} is not a mapping")
            try:
                action = Action.model_validate(item)
                actions.append(action)
            except ValidationError as exc:
                action_id = item.get("id", f"<unknown #{i}>")
                raise CatalogLoadError(
                    f"Invalid action '{action_id}' in {path}: {exc}"
                ) from exc

        return actions

    def load_single(self, data: dict[str, Any]) -> Action:
        """Validate and return a single action from a raw dict.

        Args:
            data: Raw action definition dictionary.

        Returns:
            Validated :class:`Action`.

        Raises:
            :class:`CatalogLoadError`: On validation failure.
        """
        try:
            return Action.model_validate(data)
        except ValidationError as exc:
            action_id = data.get("id", "<unknown>")
            raise CatalogLoadError(f"Invalid action '{action_id}': {exc}") from exc

    # ──────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────

    def _resolve_catalog_dir(self) -> Path:
        """Return the catalog directory path, applying override precedence."""
        env_override = os.environ.get("THREATFLOW_CATALOG_DIR")
        if env_override:
            return Path(env_override)

        cwd_path = Path.cwd() / self._DEFAULT_CATALOG_SUBDIR
        if cwd_path.exists():
            return cwd_path

        # Fall back to the package-bundled catalog
        return self._bundled_catalog_dir()

    @staticmethod
    def _bundled_catalog_dir() -> Path:
        """Return the path to the catalog bundled inside the installed package."""
        try:
            # When installed as a package the catalog lives beside src/
            pkg_root = Path(__file__).resolve().parents[3]
            candidate = pkg_root / "catalog" / "actions"
            if candidate.exists():
                return candidate
        except IndexError:
            pass

        # Development layout fallback
        return Path(__file__).resolve().parents[4] / "catalog" / "actions"
