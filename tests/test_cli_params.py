"""Tests for CLI parameter parsing helpers."""

from __future__ import annotations

import json

import pytest

from threatflow.cli.params import ParamParseError, parse_input_params, parse_param_value


class TestParseParamValue:
    def test_parses_json_literals(self) -> None:
        assert parse_param_value("true") is True
        assert parse_param_value("42") == 42
        assert parse_param_value("3.14") == 3.14
        assert parse_param_value("[1,2,3]") == [1, 2, 3]
        assert parse_param_value('{"k":"v"}') == {"k": "v"}

    def test_falls_back_to_string(self) -> None:
        assert parse_param_value("host-123") == "host-123"
        assert parse_param_value("quoted value") == "quoted value"


class TestParseInputParams:
    def test_merges_inputs_file_and_cli_flags(self, tmp_path) -> None:
        inputs_file = tmp_path / "inputs.json"
        inputs_file.write_text(json.dumps({"enabled": False, "count": 1}))

        parsed = parse_input_params(
            params=["count=2", "tags=[\"a\",\"b\"]"],
            inputs_file=inputs_file,
        )

        assert parsed == {
            "enabled": False,
            "count": 2,
            "tags": ["a", "b"],
        }

    def test_rejects_invalid_format(self) -> None:
        with pytest.raises(ParamParseError, match="key=value"):
            parse_input_params(params=["missing_separator"])

    def test_rejects_empty_param_name(self) -> None:
        with pytest.raises(ParamParseError, match="name is empty"):
            parse_input_params(params=[" =value"])
