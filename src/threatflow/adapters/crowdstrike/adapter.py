"""
CrowdStrike Falcon adapter.

This is a **demo/mock adapter** that returns realistic structured responses
without making real API calls. Each method documents the actual CrowdStrike
Falcon API endpoint it would use in production.

To wire up a real implementation:
1. Install ``falconpy`` (``pip install crowdstrike-falconpy``).
2. Replace the ``# TODO: real API call`` blocks with FalconPy SDK calls.
3. Pass credentials via the config dict at construction time.

CrowdStrike Falcon API reference:
    https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from threatflow.adapters.base import BaseAdapter, NativeActionMapping
from threatflow.core.models import Action, ExecutionResult, ProviderInfo


class CrowdStrikeAdapter(BaseAdapter):
    """
    Demo adapter for CrowdStrike Falcon.

    Supports endpoint containment, process management, and file quarantine
    via the Falcon Real-Time Response (RTR) and Hosts APIs.

    Args:
        config: Optional configuration dict. In production this would include
            ``client_id``, ``client_secret``, and ``base_url``.
    """

    PROVIDER_ID = "crowdstrike"

    #: Actions this adapter implements.
    _CAPABILITIES = [
        "isolate_host",
        "release_host",
        "kill_process",
        "quarantine_file",
        "block_ip",
        "unblock_ip",
        "create_case",
        "append_note",
        "add_artifact",
    ]

    #: Maps action IDs to the Falcon API resource/operation they use.
    _NATIVE_MAP: dict[str, dict[str, str]] = {
        "isolate_host": {
            "api": "Hosts API",
            "operation": "PerformActionV2",
            "action_name": "contain",
            "docs": "https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/hosts-api",
        },
        "release_host": {
            "api": "Hosts API",
            "operation": "PerformActionV2",
            "action_name": "lift_containment",
            "docs": "https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/hosts-api",
        },
        "kill_process": {
            "api": "Real Time Response Admin API",
            "operation": "BatchAdminCmd",
            "action_name": "kill",
            "docs": "https://falcon.crowdstrike.com/documentation/page/b8ad9512/real-time-response-api",
        },
        "quarantine_file": {
            "api": "Quarantine API",
            "operation": "UpdateQuarantinedDetectsById",
            "action_name": "quarantine",
            "docs": "https://falcon.crowdstrike.com/documentation/page/74416a3b/quarantine-api",
        },
        "block_ip": {
            "api": "Custom IOA API",
            "operation": "CreateRule",
            "action_name": "block",
            "docs": "https://falcon.crowdstrike.com/documentation/page/c3948f9d/custom-ioa-api",
        },
        "unblock_ip": {
            "api": "Custom IOA API",
            "operation": "DeleteRules",
            "action_name": "unblock",
            "docs": "https://falcon.crowdstrike.com/documentation/page/c3948f9d/custom-ioa-api",
        },
        "create_case": {
            "api": "Falcon Fusion Workflows",
            "operation": "CreateWorkflow",
            "action_name": "create_case",
            "docs": "https://falcon.crowdstrike.com/documentation/",
        },
        "append_note": {
            "api": "Falcon Fusion Workflows",
            "operation": "UpdateCase",
            "action_name": "append_note",
            "docs": "https://falcon.crowdstrike.com/documentation/",
        },
        "add_artifact": {
            "api": "Falcon Fusion Workflows",
            "operation": "AttachArtifact",
            "action_name": "add_artifact",
            "docs": "https://falcon.crowdstrike.com/documentation/",
        },
    }

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        # TODO: Initialise FalconPy OAuth2 session here in production
        # from falconpy import OAuth2
        # self._auth = OAuth2(
        #     client_id=config["client_id"],
        #     client_secret=config["client_secret"],
        # )

    # ──────────────────────────────────────────
    # BaseAdapter interface
    # ──────────────────────────────────────────

    def provider_info(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.PROVIDER_ID,
            name="CrowdStrike Falcon",
            description=(
                "EDR/XDR platform with endpoint containment, RTR, and threat graph capabilities."
            ),
            version="0.1.0",
            capabilities=self._CAPABILITIES,
            config_schema={
                "type": "object",
                "properties": {
                    "client_id": {"type": "string"},
                    "client_secret": {"type": "string"},
                    "base_url": {"type": "string", "default": "https://api.crowdstrike.com"},
                },
                "required": ["client_id", "client_secret"],
            },
        )

    def get_capabilities(self) -> list[str]:
        return list(self._CAPABILITIES)

    def validate_inputs(self, action: Action, params: dict[str, Any]) -> list[str]:
        errors: list[str] = []

        if action.id in ("isolate_host", "release_host", "kill_process"):
            host_id = params.get("host_id", "")
            if host_id and len(host_id) != 32:
                errors.append(
                    f"CrowdStrike host_id must be a 32-character hexadecimal string, "
                    f"got {len(host_id)} characters."
                )

        return errors

    def execute(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        handler = getattr(self, f"_exec_{action.id}", None)
        if handler is None:
            return ExecutionResult.fail(
                action_id=action.id,
                provider=self.PROVIDER_ID,
                error=f"Action '{action.id}' is not implemented by this adapter.",
            )
        return handler(action, params)

    def dry_run(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        native = self.map_native_action(action)
        # Simulate outputs using passed params + placeholder values so downstream
        # steps can reference step outputs in template expressions
        simulated_outputs: dict[str, Any] = {
            inp.name: params.get(inp.name, f"<{inp.name}>")
            for inp in action.inputs
        }
        simulated_outputs["simulated"] = True
        # Add common output fields with placeholder values
        for out in action.outputs:
            if out.name not in simulated_outputs:
                simulated_outputs[out.name] = f"<dry-run:{out.name}>"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs=simulated_outputs,
            message=(
                f"[DRY RUN] Would call CrowdStrike {native.native_action} "
                f"on {native.native_params}"
            ),
            dry_run=True,
        )

    def map_native_action(self, action: Action) -> NativeActionMapping:
        info = self._NATIVE_MAP.get(action.id, {})
        return NativeActionMapping(
            provider=self.PROVIDER_ID,
            native_action=info.get("operation", "UNKNOWN"),
            native_params={"action_name": info.get("action_name", "")},
            notes=f"Uses the CrowdStrike {info.get('api', 'Falcon')} API.",
            documentation_url=info.get("docs", ""),
        )

    # ──────────────────────────────────────────
    # Action handlers (mock implementations)
    # ──────────────────────────────────────────

    def _exec_isolate_host(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Contain a host via the Falcon Hosts API.

        Real implementation:
            from falconpy import Hosts
            falcon = Hosts(auth_object=self._auth)
            response = falcon.perform_action(action_name="contain", ids=[params["host_id"]])
        """
        host_id = params["host_id"]
        comment = params.get("comment", "Isolated via ThreatFlow")
        # TODO: Real API call — see docstring above
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "host_id": host_id,
                "status": "contained",
                "timestamp": _now_iso(),
            },
            message=f"Host {host_id} isolated (contained). Reason: {comment}",
            raw_response={
                "status_code": 200,
                "body": {"resources": [host_id], "errors": []},
            },
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_release_host(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Lift containment via the Falcon Hosts API.

        Real implementation:
            response = falcon.perform_action(action_name="lift_containment", ids=[...])
        """
        host_id = params["host_id"]
        # TODO: Real API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"host_id": host_id, "status": "normal", "timestamp": _now_iso()},
            message=f"Containment lifted for host {host_id}.",
            raw_response={"status_code": 200, "body": {"resources": [host_id], "errors": []}},
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_kill_process(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Kill a process via RTR AdminCmd.

        Real implementation:
            from falconpy import RealTimeResponseAdmin
            rtr = RealTimeResponseAdmin(auth_object=self._auth)
            rtr.batch_admin_command(base_command="kill", command_string=f"kill {params['pid']}")
        """
        host_id = params["host_id"]
        pid = params["pid"]
        # TODO: Real RTR API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"host_id": host_id, "pid": pid, "killed": True, "timestamp": _now_iso()},
            message=f"Process {pid} killed on host {host_id}.",
            raw_response={"status_code": 200, "body": {"combined": {"resources": {}}}},
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_quarantine_file(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Quarantine a file via the Falcon Quarantine API.

        Real implementation:
            from falconpy import Quarantine
            q = Quarantine(auth_object=self._auth)
            q.update_quarantined_detects_by_id(action="quarantine", ids=[...])
        """
        file_path = params["file_path"]
        host_id = params.get("host_id", "")
        # TODO: Real Quarantine API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "file_path": file_path,
                "host_id": host_id,
                "quarantined": True,
                "timestamp": _now_iso(),
            },
            message=f"File '{file_path}' quarantined on host {host_id}.",
            raw_response={"status_code": 200},
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_block_ip(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Block an IP via a Custom IOA rule."""
        ip_address = params["ip_address"]
        direction = params.get("direction", "both")
        # TODO: Create Custom IOA rule via Falcon API
        rule_id = f"rule-{uuid.uuid4().hex[:8]}"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "ip_address": ip_address,
                "direction": direction,
                "rule_id": rule_id,
                "blocked": True,
                "timestamp": _now_iso(),
            },
            message=f"IP {ip_address} blocked ({direction}) via IOA rule {rule_id}.",
            raw_response={"status_code": 200, "body": {"resources": [rule_id]}},
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_unblock_ip(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Remove an IP block by deleting the Custom IOA rule."""
        ip_address = params["ip_address"]
        rule_id = params.get("rule_id", "")
        # TODO: Delete IOA rule via Falcon API
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "ip_address": ip_address,
                "rule_id": rule_id,
                "unblocked": True,
                "timestamp": _now_iso(),
            },
            message=f"IP {ip_address} unblocked (rule {rule_id} removed).",
            raw_response={"status_code": 200},
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_create_case(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        case_id = f"CS-{uuid.uuid4().hex[:8].upper()}"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"case_id": case_id, "title": params.get("title", ""), "timestamp": _now_iso()},
            message=f"Case {case_id} created.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_append_note(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"case_id": params.get("case_id", ""), "note_appended": True},
            message=f"Note appended to case {params.get('case_id', '')}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_add_artifact(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        artifact_id = f"ART-{uuid.uuid4().hex[:8].upper()}"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"artifact_id": artifact_id, "case_id": params.get("case_id", "")},
            message=f"Artifact {artifact_id} attached to case {params.get('case_id', '')}.",
            metadata={"request_id": _fake_request_id()},
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fake_request_id() -> str:
    return uuid.uuid4().hex
