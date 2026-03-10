# ThreatFlow Roadmap

This document captures planned features, design decisions, and community priorities.
It is updated quarterly. Items are roughly ordered by priority within each milestone.

---

## v0.1 — Foundation (current)

**Status:** In progress

- [x] Core Pydantic models (`Action`, `ExecutionResult`, `Playbook`, etc.)
- [x] YAML action catalog (15 built-in actions across 5 domains)
- [x] `ActionRegistry` — in-memory catalog store
- [x] `CatalogLoader` — YAML catalog loading with strict/soft modes
- [x] `ActionExecutor` — validation, approval gate, adapter dispatch
- [x] `BaseAdapter` — abstract adapter interface
- [x] CrowdStrike Falcon adapter (mock/demo)
- [x] Microsoft Defender + Entra ID adapter (mock/demo)
- [x] Splunk SOAR adapter (mock/demo)
- [x] Playbook models, validator, and executor
- [x] Template variable substitution (`{{ variable }}`, `{{ step.output }}`)
- [x] Conditional step execution
- [x] MITRE D3FEND and ATT&CK bundled index
- [x] CLI (`actions list/show`, `run`, `plan`, `playbook validate/run`)
- [x] JSON schemas for actions and playbooks
- [x] Example playbooks (ransomware, phishing, compromised account)
- [x] Unit tests for all core components
- [x] README, CONTRIBUTING, roadmap

---

## v0.2 — Real API integration

**Goal:** Make the demo adapters production-ready for at least one provider.

- [ ] **CrowdStrike Falcon** — wire up real FalconPy calls for all 9 capabilities
  - Host containment/release via Hosts API
  - RTR kill process
  - Quarantine API
  - Custom IOA rule creation for IP blocking
- [ ] **Microsoft Defender** — wire up real MSAL + REST API calls
  - MDE machine isolation/unisolation
  - Graph API user disable/revoke/reset-password
  - EXO sender/domain blocking
- [ ] Provider config file support (`providers.yaml` with env var interpolation)
- [ ] `threatflow providers list` / `threatflow providers check` CLI commands
- [ ] Adapter connectivity test (`adapter.ping()`)

---

## v0.3 — Playbook improvements

**Goal:** Make playbooks robust enough for production runbooks.

- [ ] Playbook step retry with configurable backoff (`retry: 3, delay: 5s`)
- [ ] Step timeout (`timeout: 30s`)
- [ ] Parallel step execution (`parallel: [step_a, step_b]`)
- [ ] Playbook-level rollback steps (`on_failure_playbook_rollback: true`)
- [ ] Import/include support for shared step libraries
- [ ] Playbook output declaration (formal output schema)
- [ ] `threatflow playbook list` command (index of available playbooks)
- [ ] JSON output for all CLI commands (`--json` flag complete)

---

## v0.4 — Expanded catalog

**Goal:** Broaden coverage of security domains.

- [ ] **Cloud** domain: `suspend_aws_principal`, `revoke_azure_app_grant`, `disable_gcp_service_account`
- [ ] **Threat intel** domain: `submit_hash_to_sandbox`, `lookup_ioc`, `tag_ioc`
- [ ] **Vulnerability** domain: `trigger_scan`, `create_exception`, `patch_asset`
- [ ] ATT&CK sub-technique granularity in all existing mappings
- [ ] D3FEND full-ontology import script (auto-generate from MITRE API)
- [ ] STIX/TAXII export of the action catalog

---

## v0.5 — Additional adapters

Community-contributed adapter targets (in rough priority order):

- [ ] **Palo Alto Cortex XSOAR** — via Cortex XSOAR REST API
- [ ] **SentinelOne** — via SentinelOne REST API
- [ ] **Microsoft Sentinel** — as a first-class adapter (currently via Defender adapter)
- [ ] **Elastic Security** — via Elastic Security REST API
- [ ] **Tines** — emit Tines stories from playbooks
- [ ] **JIRA / ServiceNow** — case management adapters
- [ ] **PagerDuty** — alert and case creation
- [ ] **Slack / Teams** — notification adapter

---

## v1.0 — Production-ready

**Goal:** Stable API, comprehensive adapter coverage, community validation.

- [ ] Stable public API (`threatflow.core`, `threatflow.adapters.base`) — semver guarantees
- [ ] Published to PyPI
- [ ] CI/CD integration guide (GitHub Actions, GitLab CI, Jenkins)
- [ ] CACAO-compatible playbook export/import
- [ ] Audit log format (structured JSON, OCSF-compatible)
- [ ] Role-based action authorization model
- [ ] Approval workflow integration (Slack approval bot, PagerDuty acknowledge)
- [ ] Documentation site (MkDocs or Sphinx)
- [ ] Contributor hall of fame and adapter certification process

---

## Future / Under consideration

These are ideas raised by the community that need more design work:

- **Event-driven triggers** — lightweight daemon that watches a webhook/queue and auto-dispatches playbooks
- **Playbook testing framework** — mock adapter for CI-based playbook testing
- **Visual playbook editor** — a minimal web UI for playbook authoring (not a full SOAR)
- **Threat intel enrichment** — auto-enrich IOCs before blocking (VirusTotal, MISP)
- **Multi-tenancy** — run ThreatFlow as a shared service with per-tenant provider configs
- **gRPC API** — server mode for programmatic integration from other tools

---

## How to influence the roadmap

- Open a GitHub issue with the `roadmap` label
- Upvote existing issues
- Submit a PR — working code moves faster than proposals
- Join the discussion in GitHub Discussions

Items with multiple community upvotes and a working implementation will be fast-tracked.
