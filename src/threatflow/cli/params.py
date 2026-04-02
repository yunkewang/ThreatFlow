"""Helpers for parsing CLI input parameters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ParamParseError(ValueError):
    """Raised when CLI parameters cannot be parsed."""


def parse_param_value(raw: str) -> Any:
    """Parse a ``--param`` value into a native Python value when possible.

    The parser supports JSON literals for better CLI ergonomics::

        --param enabled=true
        --param retries=3
        --param tags='["phishing", "high_priority"]'

    If parsing fails, the original string is returned unchanged.
    """
    value = raw.strip()
    if value == "":
        return ""

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def parse_input_params(*, params: list[str], inputs_file: str | Path | None = None) -> dict[str, Any]:
    """Merge parameters from ``--inputs-file`` and repeated ``--param`` flags."""
    input_params: dict[str, Any] = {}

    if inputs_file:
        path = Path(inputs_file)
        try:
            file_data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ParamParseError(f"Failed to read inputs file: {exc}") from exc

        if not isinstance(file_data, dict):
            raise ParamParseError("--inputs-file must contain a JSON object")

        input_params.update(file_data)

    for param in params:
        if "=" not in param:
            raise ParamParseError(f"Invalid --param format: '{param}'. Use key=value.")

        key, _, value = param.partition("=")
        parsed_key = key.strip()
        if not parsed_key:
            raise ParamParseError(f"Invalid --param format: '{param}'. Parameter name is empty.")

        input_params[parsed_key] = parse_param_value(value)

    return input_params
