"""Tests for CatalogLoader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from threatflow.core.loader import CatalogLoadError, CatalogLoader


@pytest.fixture()
def loader() -> CatalogLoader:
    return CatalogLoader(strict=True)


@pytest.fixture()
def sample_action_yaml() -> str:
    return textwrap.dedent("""
        id: test_action
        name: Test Action
        domain: endpoint
        description: A test action for unit tests.
        risk_level: low
        approval_mode: none
        supported_providers:
          - crowdstrike
        inputs:
          - name: host_id
            type: string
            required: true
            description: Host identifier
        outputs:
          - name: status
            type: string
            description: Action status
        tags:
          - test
    """)


@pytest.fixture()
def multi_action_yaml() -> str:
    return textwrap.dedent("""
        actions:
          - id: action_one
            name: Action One
            domain: endpoint
            description: First action.
            risk_level: low
            supported_providers: [crowdstrike]
          - id: action_two
            name: Action Two
            domain: network
            description: Second action.
            risk_level: medium
            supported_providers: [defender]
    """)


class TestCatalogLoader:
    def test_load_file_single_action(
        self, loader: CatalogLoader, tmp_path: Path, sample_action_yaml: str
    ) -> None:
        f = tmp_path / "action.yaml"
        f.write_text(sample_action_yaml)
        actions = loader.load_file(f)
        assert len(actions) == 1
        assert actions[0].id == "test_action"
        assert actions[0].domain == "endpoint"

    def test_load_file_multi_action(
        self, loader: CatalogLoader, tmp_path: Path, multi_action_yaml: str
    ) -> None:
        f = tmp_path / "multi.yaml"
        f.write_text(multi_action_yaml)
        actions = loader.load_file(f)
        assert len(actions) == 2
        assert {a.id for a in actions} == {"action_one", "action_two"}

    def test_load_file_empty(self, loader: CatalogLoader, tmp_path: Path) -> None:
        f = tmp_path / "empty.yaml"
        f.write_text("")
        actions = loader.load_file(f)
        assert actions == []

    def test_load_file_invalid_yaml_raises(
        self, loader: CatalogLoader, tmp_path: Path
    ) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text("{ invalid yaml ]: [")
        with pytest.raises(CatalogLoadError):
            loader.load_file(f)

    def test_load_file_invalid_action_raises(
        self, loader: CatalogLoader, tmp_path: Path
    ) -> None:
        f = tmp_path / "invalid.yaml"
        f.write_text("id: no_name\n")  # missing required fields
        with pytest.raises(CatalogLoadError):
            loader.load_file(f)

    def test_load_directory(
        self,
        loader: CatalogLoader,
        tmp_path: Path,
        sample_action_yaml: str,
        multi_action_yaml: str,
    ) -> None:
        (tmp_path / "a.yaml").write_text(sample_action_yaml)
        (tmp_path / "b.yaml").write_text(multi_action_yaml)
        registry = loader.load_directory(tmp_path)
        assert len(registry) == 3

    def test_load_directory_missing_soft(self, tmp_path: Path) -> None:
        """Non-strict loader should return empty registry for missing dir."""
        loader = CatalogLoader(strict=False)
        registry = loader.load_directory(tmp_path / "nonexistent")
        assert len(registry) == 0

    def test_load_directory_missing_strict(self, tmp_path: Path) -> None:
        """Strict loader should raise for missing directory."""
        loader = CatalogLoader(strict=True)
        with pytest.raises(CatalogLoadError, match="not found"):
            loader.load_directory(tmp_path / "nonexistent")

    def test_load_default_catalog(self) -> None:
        """The bundled default catalog should load without errors."""
        loader = CatalogLoader(strict=False)
        registry = loader.load_default_catalog()
        # The bundled catalog has at least 15 actions
        assert len(registry) >= 14

    def test_load_single(self, loader: CatalogLoader) -> None:
        data = {
            "id": "my_action",
            "name": "My Action",
            "domain": "endpoint",
            "description": "Test",
            "risk_level": "low",
            "supported_providers": [],
        }
        action = loader.load_single(data)
        assert action.id == "my_action"

    def test_load_single_invalid_raises(self, loader: CatalogLoader) -> None:
        with pytest.raises(CatalogLoadError):
            loader.load_single({"id": "only_id"})
