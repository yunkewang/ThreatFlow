"""
Splunk SOAR (formerly Phantom) adapter.

This is a **demo/mock adapter**. Each method documents the Splunk SOAR REST
API endpoint it would use in production.

To wire up a real implementation:
1. Set ``base_url``, ``token`` (or ``username``/``password``) in the config.
2. Use ``requests`` or ``httpx`` to call the SOAR REST API.
3. Replace the ``# TODO: real API call`` blocks.

Splunk SOAR REST API reference:
    https://docs.splunk.com/Documentation/SOARonprem/latest/DevelopApps/RESTAPI
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from opensecops.adapters.base import BaseAdapter, NativeActionMapping
from opensecops.core.models import Action, ExecutionResult, ProviderInfo


class SplunkSOARAdapter(BaseAdapter):
    """
    Demo adapter for Splunk SOAR (Phantom).

    Splunk SOAR models security operations as **actions** run against **assets**
    within **containers** (cases). This adapter maps OpenSecOps abstract actions
    to SOAR app actions executed via the ``/rest/action_run`` endpoint.

    Args:
        config: Optional configuration dict. In production this would include
            ``base_url`` and ``token``.
    """

    PROVIDER_ID = "splunk_soar"

    _CAPABILITIES = [
        "isolate_host",
        "release_host",
        "kill_process",
        "quarantine_file",
        "disable_user",
        "block_ip",
        "unblock_ip",
        "block_domain",
        "block_sender",
        "create_case",
        "append_note",
        "add_artifact",
    ]

    _NATIVE_MAP: dict[str, dict[str, str]] = {
        "isolate_host": {
            "app": "CrowdStrike Falcon",
            "action": "quarantine device",
            "endpoint": "POST /rest/action_run",
        },
        "release_host": {
            "app": "CrowdStrike Falcon",
            "action": "unquarantine device",
            "endpoint": "POST /rest/action_run",
        },
        "kill_process": {
            "app": "CrowdStrike Falcon",
            "action": "kill process",
            "endpoint": "POST /rest/action_run",
        },
        "quarantine_file": {
            "app": "CrowdStrike Falcon",
            "action": "quarantine file",
            "endpoint": "POST /rest/action_run",
        },
        "disable_user": {
            "app": "LDAP / Active Directory",
            "action": "disable account",
            "endpoint": "POST /rest/action_run",
        },
        "block_ip": {
            "app": "Palo Alto Firewall / Generic",
            "action": "block ip",
            "endpoint": "POST /rest/action_run",
        },
        "unblock_ip": {
            "app": "Palo Alto Firewall / Generic",
            "action": "unblock ip",
            "endpoint": "POST /rest/action_run",
        },
        "block_domain": {
            "app": "Cisco Umbrella / Generic",
            "action": "block domain",
            "endpoint": "POST /rest/action_run",
        },
        "block_sender": {
            "app": "Exchange / O365",
            "action": "block sender",
            "endpoint": "POST /rest/action_run",
        },
        "create_case": {
            "app": "SOAR Core",
            "action": "create container",
            "endpoint": "POST /rest/container",
        },
        "append_note": {
            "app": "SOAR Core",
            "action": "add comment",
            "endpoint": "POST /rest/container/{id}/comments",
        },
        "add_artifact": {
            "app": "SOAR Core",
            "action": "create artifact",
            "endpoint": "POST /rest/artifact",
        },
    }

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._base_url = config.get("base_url", "https://soar.example.com") if config else ""
        # TODO: Set up authenticated requests.Session here
        # import requests
        # self._session = requests.Session()
        # self._session.headers["ph-auth-token"] = config["token"]
        # self._session.verify = config.get("verify_ssl", True)

    def provider_info(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.PROVIDER_ID,
            name="Splunk SOAR",
            description=(
                "Splunk SOAR (Phantom) automation platform. Actions are dispatched via "
                "the SOAR REST API and executed through installed app connectors."
            ),
            version="0.1.0",
            capabilities=self._CAPABILITIES,
            config_schema={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "description": "SOAR instance URL (e.g. https://soar.corp.com)",
                    },
                    "token": {
                        "type": "string",
                        "description": "SOAR API auth token",
                    },
                    "verify_ssl": {
                        "type": "boolean",
                        "default": True,
                    },
                },
                "required": ["base_url", "token"],
            },
        )

    def get_capabilities(self) -> list[str]:
        return list(self._CAPABILITIES)

    def validate_inputs(self, action: Action, params: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        # SOAR actions always require a container_id for context (except create_case)
        if action.id not in ("create_case",) and not params.get("container_id"):
            errors.append(
                "Splunk SOAR requires 'container_id' to associate the action with a case. "
                "Pass container_id or run 'create_case' first."
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
        simulated_outputs: dict[str, Any] = {
            inp.name: params.get(inp.name, f"<{inp.name}>")
            for inp in action.inputs
        }
        simulated_outputs["simulated"] = True
        for out in action.outputs:
            if out.name not in simulated_outputs:
                simulated_outputs[out.name] = f"<dry-run:{out.name}>"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs=simulated_outputs,
            message=(
                f"[DRY RUN] Would POST to {self._base_url}/rest/action_run "
                f"dispatching '{native.native_action}' via SOAR."
            ),
            dry_run=True,
        )

    def map_native_action(self, action: Action) -> NativeActionMapping:
        info = self._NATIVE_MAP.get(action.id, {})
        return NativeActionMapping(
            provider=self.PROVIDER_ID,
            native_action=info.get("action", "UNKNOWN"),
            native_params={
                "app": info.get("app", ""),
                "endpoint": info.get("endpoint", "POST /rest/action_run"),
            },
            notes=(
                f"Dispatched via the SOAR app '{info.get('app', 'Generic')}'. "
                "The app connector must be installed and configured on the SOAR instance."
            ),
            documentation_url="https://docs.splunk.com/Documentation/SOARonprem/latest/DevelopApps/RESTAPI",
        )

    # ──────────────────────────────────────────
    # Action handlers (mock implementations)
    # ──────────────────────────────────────────

    def _exec_isolate_host(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Isolate host by dispatching 'quarantine device' action on the SOAR platform.

        Real:
            POST /rest/action_run
            {
                "action": "quarantine device",
                "container_id": params["container_id"],
                "name": "isolate_host",
                "assets": ["crowdstrike_asset"],
                "parameters": [{"device_id": params["host_id"]}]
            }
        """
        host_id = params["host_id"]
        container_id = params.get("container_id", "")
        action_run_id = _fake_action_run_id()
        # TODO: Real SOAR API call — POST /rest/action_run
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "host_id": host_id,
                "action_run_id": action_run_id,
                "container_id": container_id,
                "status": "running",
                "timestamp": _now_iso(),
            },
            message=f"SOAR action_run {action_run_id} submitted for host isolation ({host_id}).",
            raw_response={"id": action_run_id, "status": "running"},
            metadata={"request_id": _fake_request_id(), "soar_url": f"{self._base_url}/rest/action_run/{action_run_id}"},
        )

    def _exec_release_host(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        host_id = params["host_id"]
        action_run_id = _fake_action_run_id()
        # TODO: Real SOAR API call — POST /rest/action_run (unquarantine device)
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"host_id": host_id, "action_run_id": action_run_id, "status": "running"},
            message=f"SOAR action_run {action_run_id} submitted for host release ({host_id}).",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_kill_process(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        host_id = params["host_id"]
        pid = params["pid"]
        action_run_id = _fake_action_run_id()
        # TODO: Real SOAR API call — POST /rest/action_run (kill process)
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"host_id": host_id, "pid": pid, "action_run_id": action_run_id},
            message=f"SOAR action_run {action_run_id} submitted to kill process {pid} on {host_id}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_quarantine_file(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        file_path = params["file_path"]
        action_run_id = _fake_action_run_id()
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"file_path": file_path, "action_run_id": action_run_id},
            message=f"SOAR action_run {action_run_id} submitted to quarantine '{file_path}'.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_disable_user(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        upn = params.get("user_upn") or params.get("user_id", "")
        action_run_id = _fake_action_run_id()
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"user_upn": upn, "action_run_id": action_run_id, "disabled": True},
            message=f"SOAR action_run {action_run_id} submitted to disable account '{upn}'.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_block_ip(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        ip_address = params["ip_address"]
        action_run_id = _fake_action_run_id()
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"ip_address": ip_address, "action_run_id": action_run_id, "blocked": True},
            message=f"SOAR action_run {action_run_id} submitted to block IP {ip_address}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_unblock_ip(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        ip_address = params["ip_address"]
        action_run_id = _fake_action_run_id()
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"ip_address": ip_address, "action_run_id": action_run_id, "unblocked": True},
            message=f"SOAR action_run {action_run_id} submitted to unblock IP {ip_address}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_block_domain(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        domain = params["domain"]
        action_run_id = _fake_action_run_id()
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"domain": domain, "action_run_id": action_run_id, "blocked": True},
            message=f"SOAR action_run {action_run_id} submitted to block domain '{domain}'.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_block_sender(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        sender = params["sender"]
        action_run_id = _fake_action_run_id()
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"sender": sender, "action_run_id": action_run_id, "blocked": True},
            message=f"SOAR action_run {action_run_id} submitted to block sender '{sender}'.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_create_case(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Create a SOAR container (case).

        Real:
            POST /rest/container
            {"name": "...", "label": "events", "severity": "high"}
        """
        title = params.get("title", "Untitled Case")
        severity = params.get("severity", "medium")
        container_id = _fake_container_id()
        # TODO: POST /rest/container
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "case_id": str(container_id),
                "container_id": str(container_id),
                "title": title,
                "severity": severity,
                "timestamp": _now_iso(),
            },
            message=f"SOAR container #{container_id} created: '{title}'.",
            raw_response={"id": container_id, "success": True},
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_append_note(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        case_id = params.get("case_id", "")
        comment_id = _fake_action_run_id()
        # TODO: POST /rest/container/{id}/comments
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"comment_id": str(comment_id), "case_id": case_id},
            message=f"Note appended to SOAR container #{case_id}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_add_artifact(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        case_id = params.get("case_id", "")
        artifact_id = _fake_action_run_id()
        # TODO: POST /rest/artifact
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"artifact_id": str(artifact_id), "case_id": case_id},
            message=f"Artifact #{artifact_id} attached to SOAR container #{case_id}.",
            metadata={"request_id": _fake_request_id()},
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fake_request_id() -> str:
    return str(uuid.uuid4())


def _fake_action_run_id() -> int:
    import random
    return random.randint(10000, 99999)


def _fake_container_id() -> int:
    import random
    return random.randint(1000, 9999)
