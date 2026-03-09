"""
Microsoft Defender for Endpoint + Entra ID adapter.

This is a **demo/mock adapter** that returns realistic structured responses
without making real API calls. Each method documents the Microsoft Graph API
or MDE REST API endpoint it would use in production.

To wire up a real implementation:
1. Register an Entra ID app with the required permissions (see config_schema).
2. Install ``msal`` and ``requests`` (or ``httpx``).
3. Replace the ``# TODO: real API call`` blocks with authenticated HTTP requests.
4. Pass ``tenant_id``, ``client_id``, and ``client_secret`` in the config dict.

MDE API reference:
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/apis-intro
Graph API reference:
    https://learn.microsoft.com/en-us/graph/overview
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from opensecops.adapters.base import BaseAdapter, NativeActionMapping
from opensecops.core.models import Action, ExecutionResult, ProviderInfo


class DefenderAdapter(BaseAdapter):
    """
    Demo adapter for Microsoft Defender for Endpoint and Entra ID.

    Covers endpoint isolation, user management, session revocation,
    password reset, email purging, and sender/domain blocking.

    Args:
        config: Optional configuration dict. In production, requires
            ``tenant_id``, ``client_id``, and ``client_secret``.
    """

    PROVIDER_ID = "defender"

    _CAPABILITIES = [
        "isolate_host",
        "release_host",
        "kill_process",
        "quarantine_file",
        "disable_user",
        "revoke_session",
        "reset_password",
        "purge_email",
        "block_sender",
        "block_domain",
        "block_ip",
        "unblock_ip",
        "create_case",
        "append_note",
        "add_artifact",
    ]

    _NATIVE_MAP: dict[str, dict[str, str]] = {
        "isolate_host": {
            "api": "MDE REST API",
            "endpoint": "POST /api/machines/{id}/isolate",
            "docs": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/isolate-machine",
        },
        "release_host": {
            "api": "MDE REST API",
            "endpoint": "POST /api/machines/{id}/unisolate",
            "docs": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/unisolate-machine",
        },
        "kill_process": {
            "api": "MDE Live Response",
            "endpoint": "POST /api/machines/{id}/runliveresponse",
            "docs": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response",
        },
        "quarantine_file": {
            "api": "MDE REST API",
            "endpoint": "POST /api/machines/{id}/StopAndQuarantineFile",
            "docs": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/stop-and-quarantine-file",
        },
        "disable_user": {
            "api": "Microsoft Graph API",
            "endpoint": "PATCH /v1.0/users/{id}",
            "docs": "https://learn.microsoft.com/en-us/graph/api/user-update",
        },
        "revoke_session": {
            "api": "Microsoft Graph API",
            "endpoint": "POST /v1.0/users/{id}/revokeSignInSessions",
            "docs": "https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions",
        },
        "reset_password": {
            "api": "Microsoft Graph API",
            "endpoint": "PATCH /v1.0/users/{id}/passwordProfile",
            "docs": "https://learn.microsoft.com/en-us/graph/api/user-update",
        },
        "purge_email": {
            "api": "Microsoft Purview / Security & Compliance",
            "endpoint": "POST /v1.0/security/microsoft.graph.runHuntingQuery",
            "docs": "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/",
        },
        "block_sender": {
            "api": "Exchange Online Protection",
            "endpoint": "Set-HostedContentFilterPolicy (PowerShell)",
            "docs": "https://learn.microsoft.com/en-us/powershell/module/exchange/set-hostedcontentfilterpolicy",
        },
        "block_domain": {
            "api": "Exchange Online Protection",
            "endpoint": "Set-TenantAllowBlockList",
            "docs": "https://learn.microsoft.com/en-us/powershell/module/exchange/set-tenantallowblocklist",
        },
        "block_ip": {
            "api": "MDE Indicators API",
            "endpoint": "POST /api/indicators",
            "docs": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/post-ti-indicator",
        },
        "unblock_ip": {
            "api": "MDE Indicators API",
            "endpoint": "DELETE /api/indicators/{id}",
            "docs": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/delete-ti-indicator-by-id",
        },
        "create_case": {
            "api": "Microsoft Sentinel",
            "endpoint": "PUT /subscriptions/.../incidents/{incidentId}",
            "docs": "https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents",
        },
        "append_note": {
            "api": "Microsoft Sentinel",
            "endpoint": "PUT .../incidents/{incidentId}/comments/{commentId}",
            "docs": "https://learn.microsoft.com/en-us/rest/api/securityinsights/incident-comments",
        },
        "add_artifact": {
            "api": "Microsoft Sentinel",
            "endpoint": "PUT .../incidents/{incidentId}/bookmarks/{bookmarkId}",
            "docs": "https://learn.microsoft.com/en-us/rest/api/securityinsights/bookmarks",
        },
    }

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        # TODO: Authenticate via MSAL in production
        # import msal
        # app = msal.ConfidentialClientApplication(
        #     client_id=config["client_id"],
        #     client_credential=config["client_secret"],
        #     authority=f"https://login.microsoftonline.com/{config['tenant_id']}",
        # )
        # self._token = app.acquire_token_for_client(scopes=["https://api.securitycenter.microsoft.com/.default"])

    def provider_info(self) -> ProviderInfo:
        return ProviderInfo(
            id=self.PROVIDER_ID,
            name="Microsoft Defender / Entra ID",
            description=(
                "Microsoft security stack: Defender for Endpoint (MDE), "
                "Entra ID (Azure AD), Exchange Online Protection, and Sentinel."
            ),
            version="0.1.0",
            capabilities=self._CAPABILITIES,
            config_schema={
                "type": "object",
                "properties": {
                    "tenant_id": {"type": "string"},
                    "client_id": {"type": "string"},
                    "client_secret": {"type": "string"},
                    "subscription_id": {
                        "type": "string",
                        "description": "Required for Sentinel actions",
                    },
                    "workspace_id": {
                        "type": "string",
                        "description": "Sentinel Log Analytics workspace ID",
                    },
                },
                "required": ["tenant_id", "client_id", "client_secret"],
            },
        )

    def get_capabilities(self) -> list[str]:
        return list(self._CAPABILITIES)

    def validate_inputs(self, action: Action, params: dict[str, Any]) -> list[str]:
        errors: list[str] = []

        # UPN format check for identity actions
        if action.id in ("disable_user", "revoke_session", "reset_password"):
            upn = params.get("user_upn") or params.get("user_id", "")
            if upn and "@" not in upn:
                errors.append(
                    f"user_upn should be in UPN format (user@domain.com), got '{upn}'"
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
            message=f"[DRY RUN] Would call {native.native_action} with params {params}",
            dry_run=True,
        )

    def map_native_action(self, action: Action) -> NativeActionMapping:
        info = self._NATIVE_MAP.get(action.id, {})
        return NativeActionMapping(
            provider=self.PROVIDER_ID,
            native_action=info.get("endpoint", "UNKNOWN"),
            native_params={},
            notes=f"Uses the {info.get('api', 'Microsoft')} API.",
            documentation_url=info.get("docs", ""),
        )

    # ──────────────────────────────────────────
    # Action handlers (mock implementations)
    # ──────────────────────────────────────────

    def _exec_isolate_host(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Isolate a machine via the MDE Machines API.

        Real:
            POST https://api.securitycenter.microsoft.com/api/machines/{machineId}/isolate
            Body: {"Comment": "...", "IsolationType": "Full"}
        """
        machine_id = params["host_id"]
        comment = params.get("comment", "Isolated via OpenSecOps")
        # TODO: Real MDE API call
        action_id_mde = f"mde-{uuid.uuid4().hex[:8]}"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "machine_id": machine_id,
                "mde_action_id": action_id_mde,
                "status": "Pending",
                "timestamp": _now_iso(),
            },
            message=f"Isolation request submitted for machine {machine_id}. MDE Action: {action_id_mde}",
            raw_response={"id": action_id_mde, "type": "Isolate", "status": "Pending"},
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_release_host(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Unisolate a machine via the MDE Machines API.

        Real:
            POST https://api.securitycenter.microsoft.com/api/machines/{machineId}/unisolate
        """
        machine_id = params["host_id"]
        # TODO: Real API call
        action_id_mde = f"mde-{uuid.uuid4().hex[:8]}"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"machine_id": machine_id, "mde_action_id": action_id_mde, "status": "Pending"},
            message=f"Unisolation request submitted for machine {machine_id}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_kill_process(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Kill a process via MDE Live Response.

        Real:
            POST .../machines/{machineId}/runliveresponse
            Commands: [{"type": "RunScript", "params": [{"key":"ScriptName","value":"kill_process.ps1"},...]}]
        """
        host_id = params["host_id"]
        pid = params["pid"]
        action_id_mde = f"mde-{uuid.uuid4().hex[:8]}"
        # TODO: Live Response API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"host_id": host_id, "pid": pid, "mde_action_id": action_id_mde, "killed": True},
            message=f"Process {pid} kill initiated on {host_id} via Live Response.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_quarantine_file(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Stop and quarantine a file via MDE.

        Real:
            POST .../machines/{machineId}/StopAndQuarantineFile
            Body: {"Comment": "...", "Sha1": "..."}
        """
        file_path = params["file_path"]
        sha1 = params.get("sha1", "")
        host_id = params.get("host_id", "")
        action_id_mde = f"mde-{uuid.uuid4().hex[:8]}"
        # TODO: Real API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "file_path": file_path,
                "sha1": sha1,
                "host_id": host_id,
                "mde_action_id": action_id_mde,
                "quarantined": True,
            },
            message=f"File '{file_path}' quarantined on {host_id}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_disable_user(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Disable a user account via Microsoft Graph.

        Real:
            PATCH https://graph.microsoft.com/v1.0/users/{upn}
            Body: {"accountEnabled": false}
        """
        upn = params.get("user_upn") or params.get("user_id", "")
        reason = params.get("reason", "Disabled via OpenSecOps")
        # TODO: Real Graph API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"user_upn": upn, "account_enabled": False, "timestamp": _now_iso()},
            message=f"User account '{upn}' disabled. Reason: {reason}",
            raw_response={"id": upn, "accountEnabled": False},
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_revoke_session(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Revoke all sign-in sessions via Microsoft Graph.

        Real:
            POST https://graph.microsoft.com/v1.0/users/{upn}/revokeSignInSessions
        """
        upn = params.get("user_upn") or params.get("user_id", "")
        # TODO: Real Graph API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"user_upn": upn, "sessions_revoked": True, "timestamp": _now_iso()},
            message=f"All sign-in sessions revoked for '{upn}'.",
            raw_response={"value": True},
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_reset_password(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Force a password reset via Microsoft Graph.

        Real:
            PATCH https://graph.microsoft.com/v1.0/users/{upn}
            Body: {"passwordProfile": {"forceChangePasswordNextSignIn": true, "password": "<temp>"}}
        """
        upn = params.get("user_upn") or params.get("user_id", "")
        # TODO: Real Graph API call — generate temp password, send to help desk
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "user_upn": upn,
                "force_change_on_next_login": True,
                "timestamp": _now_iso(),
            },
            message=f"Password reset forced for '{upn}'. User must change at next login.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_purge_email(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """
        Soft-delete matching emails via Microsoft Purview threat explorer.

        Real: Use the Security & Compliance PowerShell or Threat Explorer API
        to search and purge messages matching the query.
        """
        message_id = params.get("message_id", "")
        recipient = params.get("recipient", "")
        purge_type = params.get("purge_type", "SoftDelete")
        # TODO: Real Purview/Security & Compliance Center API call
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={
                "message_id": message_id,
                "recipient": recipient,
                "purge_type": purge_type,
                "purged": True,
                "timestamp": _now_iso(),
            },
            message=f"Email purge ({purge_type}) submitted for message {message_id}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_block_sender(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Block a sender via Exchange Online Protection blocked senders list."""
        sender = params["sender"]
        # TODO: EXO PowerShell or Graph-based block
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"sender": sender, "blocked": True, "timestamp": _now_iso()},
            message=f"Sender '{sender}' added to blocked senders list.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_block_domain(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Block a domain via the Tenant Allow/Block List."""
        domain = params["domain"]
        # TODO: EXO Set-TenantAllowBlockList
        entry_id = f"tabl-{uuid.uuid4().hex[:8]}"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"domain": domain, "entry_id": entry_id, "blocked": True, "timestamp": _now_iso()},
            message=f"Domain '{domain}' added to Tenant Allow/Block List (entry {entry_id}).",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_block_ip(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Block an IP via MDE Indicators API."""
        ip_address = params["ip_address"]
        # TODO: POST /api/indicators with indicatorType: IpAddress, action: Block
        indicator_id = f"ind-{uuid.uuid4().hex[:8]}"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"ip_address": ip_address, "indicator_id": indicator_id, "blocked": True},
            message=f"IP {ip_address} blocked via MDE indicator {indicator_id}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_unblock_ip(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Remove an IP block by deleting the MDE indicator."""
        ip_address = params["ip_address"]
        indicator_id = params.get("indicator_id", "")
        # TODO: DELETE /api/indicators/{id}
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"ip_address": ip_address, "indicator_id": indicator_id, "unblocked": True},
            message=f"IP {ip_address} unblocked (indicator {indicator_id} deleted).",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_create_case(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        """Create a Microsoft Sentinel incident."""
        incident_id = str(uuid.uuid4())
        case_id = f"SENT-{uuid.uuid4().hex[:6].upper()}"
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"case_id": case_id, "incident_id": incident_id, "title": params.get("title", "")},
            message=f"Sentinel incident {case_id} created.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_append_note(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        comment_id = str(uuid.uuid4())
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"comment_id": comment_id, "case_id": params.get("case_id", "")},
            message=f"Note appended to Sentinel incident {params.get('case_id', '')}.",
            metadata={"request_id": _fake_request_id()},
        )

    def _exec_add_artifact(self, action: Action, params: dict[str, Any]) -> ExecutionResult:
        bookmark_id = str(uuid.uuid4())
        return ExecutionResult.ok(
            action_id=action.id,
            provider=self.PROVIDER_ID,
            outputs={"bookmark_id": bookmark_id, "case_id": params.get("case_id", "")},
            message=f"Artifact bookmarked in Sentinel incident {params.get('case_id', '')}.",
            metadata={"request_id": _fake_request_id()},
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fake_request_id() -> str:
    return str(uuid.uuid4())
