"""
Example: Writing a custom provider adapter for OpenSecOps.

This file demonstrates how to implement a new provider adapter from scratch.
The example adapter connects to a hypothetical "AcmeSIEM" platform.

To use your adapter:
    1. Copy and adapt this template.
    2. Register it with the ActionExecutor:

        executor.register_adapter("acme_siem", AcmeSIEMAdapter(config={"url": "..."}))

    3. Add "acme_siem" to the supported_providers list in action YAML files,
       or create new action definitions in catalog/actions/.
"""

from __future__ import annotations

from typing import Any

from opensecops.adapters.base import BaseAdapter, NativeActionMapping
from opensecops.core.models import Action, ExecutionResult, ProviderInfo


class AcmeSIEMAdapter(BaseAdapter):
    """
    Example adapter for a hypothetical AcmeSIEM platform.

    Demonstrates the minimum required implementation of BaseAdapter.
    Replace all ``# TODO`` sections with real API calls.
    """

    PROVIDER_ID = "acme_siem"

    _CAPABILITIES = [
        "isolate_host",
        "block_ip",
        "create_case",
        "append_note",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._base_url = config.get("url", "") if config else ""
        self._api_key = config.get("api_key", "") if config else ""

        # TODO: Initialise your HTTP session here, e.g.:
        # import httpx
        # self._client = httpx.Client(
        #     base_url=self._base_url,
        #     headers={"X-API-Key": self._api_key},
        # )

    # ──────────────────────────────────────────
    # Metadata (required)
    # ──────────────────────────────────────────

    def provider_info(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.PROVIDER_ID,
            name="AcmeSIEM",
            description="Hypothetical SIEM platform adapter for OpenSecOps examples.",
            version="0.1.0",
            capabilities=self._CAPABILITIES,
            config_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "AcmeSIEM API URL"},
                    "api_key": {"type": "string", "description": "API key"},
                },
                "required": ["url", "api_key"],
            },
        )

    def get_capabilities(self) -> list[str]:
        return list(self._CAPABILITIES)

    # ──────────────────────────────────────────
    # Validation (required)
    # ──────────────────────────────────────────

    def validate_inputs(self, action: Action, params: dict[str, Any]) -> list[str]:
        """
        Perform platform-specific input validation.

        The framework has already checked that required fields are present
        and enum values are valid. Add any extra checks here.
        """
        errors: list[str] = []

        # Example: AcmeSIEM requires host_id to be a UUID
        if action.id == "isolate_host":
            host_id = params.get("host_id", "")
            if host_id and len(host_id) != 36:  # UUID format
                errors.append(
                    f"AcmeSIEM requires host_id to be a UUID (36 chars), got {len(host_id)}"
                )

        return errors

    # ──────────────────────────────────────────
    # Execution (required)
    # ──────────────────────────────────────────

    def execute(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Dispatch to the appropriate action handler."""
        handler = getattr(self, f"_exec_{action.id}", None)
        if handler is None:
            return ExecutionResult.fail(
                action_id=action.id,
                provider=self.PROVIDER_ID,
                error=f"Action '{action.id}' is not implemented by AcmeSIEMAdapter.",
            )
        return handler(action, params)

    def dry_run(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Simulate execution without side effects."""
        native = self.map_native_action(action)
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"simulated": True, "would_call": native.native_action},
            message=f"[DRY RUN] Would call {native.native_action} with {params}",
            dry_run=True,
        )

    def map_native_action(self, action: Action) -> NativeActionMapping:
        """Return the AcmeSIEM API call that implements this action."""
        native_map = {
            "isolate_host": "POST /api/v1/hosts/{id}/isolate",
            "block_ip": "POST /api/v1/network/blocklist",
            "create_case": "POST /api/v1/cases",
            "append_note": "POST /api/v1/cases/{id}/notes",
        }
        return NativeActionMapping(
            provider=self.PROVIDER_ID,
            native_action=native_map.get(action.id, "UNKNOWN"),
            native_params={},
            notes="AcmeSIEM REST API v1",
            documentation_url="https://docs.acme-siem.example.com/api/",
        )

    # ──────────────────────────────────────────
    # Action handlers
    # ──────────────────────────────────────────

    def _exec_isolate_host(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        host_id = params["host_id"]

        # TODO: Replace with real API call
        # response = self._client.post(f"/api/v1/hosts/{host_id}/isolate", json={
        #     "comment": params.get("comment", ""),
        # })
        # response.raise_for_status()
        # data = response.json()

        # Simulated response for the example:
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"host_id": host_id, "status": "isolated"},
            message=f"Host {host_id} isolated via AcmeSIEM.",
            raw_response={"status": "ok", "host_id": host_id},
        )

    def _exec_block_ip(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        ip_address = params["ip_address"]

        # TODO: Replace with real API call
        # response = self._client.post("/api/v1/network/blocklist", json={
        #     "ip": ip_address,
        #     "direction": params.get("direction", "both"),
        # })

        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"ip_address": ip_address, "blocked": True},
            message=f"IP {ip_address} blocked via AcmeSIEM.",
        )

    def _exec_create_case(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        import uuid
        case_id = f"ACME-{uuid.uuid4().hex[:6].upper()}"

        # TODO: Replace with real API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"case_id": case_id, "title": params.get("title", "")},
            message=f"Case {case_id} created in AcmeSIEM.",
        )

    def _exec_append_note(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        # TODO: Replace with real API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"note_appended": True, "case_id": params.get("case_id", "")},
            message=f"Note appended to case {params.get('case_id', '')} in AcmeSIEM.",
        )


# ──────────────────────────────────────────
# Usage example (run directly to test)
# ──────────────────────────────────────────

if __name__ == "__main__":
    from opensecops.core.loader import CatalogLoader
    from opensecops.core.executor import ActionExecutor

    # Load the catalog
    loader = CatalogLoader(strict=False)
    registry = loader.load_default_catalog()

    # Create executor and register your adapter
    executor = ActionExecutor(registry)
    executor.register_adapter(AcmeSIEMAdapter.PROVIDER_ID, AcmeSIEMAdapter())

    # Show provider info
    adapter = executor.get_adapter("acme_siem")
    info = adapter.provider_info()
    print(f"Adapter: {info.name}")
    print(f"Capabilities: {info.capabilities}")

    # Dry-run an action
    result = executor.execute(
        "isolate_host",
        provider="acme_siem",
        params={"host_id": "12345678-1234-1234-1234-123456789012"},
        dry_run=True,
    )
    print(f"Dry-run result: {result.message}")
