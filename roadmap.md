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

### v0.1.1 — Framework modernization (April 2026)

- [x] **ATT&CK v18 mappings** — updated from v14 to v18 (Oct 2025 release)
  - 38 techniques (up from 20), covering cloud, identity, and impact tactics
  - Sub-technique granularity for key areas (T1078.004, T1098.001, T1136.003, T1562.001)
- [x] **MITRE ATLAS integration** — adversarial AI/ML technique taxonomy
  - 12 ATLAS techniques covering prompt injection, model poisoning, LLM jailbreak
  - `ATLASMapping` model + `atlas.yaml` bundled mappings
  - `MitreIndex.get_atlas()` and `all_atlas_ids()` query API
- [x] **Cloud domain** — 4 new actions: `suspend_cloud_identity`, `revoke_cloud_credentials`, `restrict_storage_access`, `isolate_container`
- [x] **AI security domain** — 4 new actions: `disable_ai_endpoint`, `revoke_ai_api_keys`, `block_prompt_source`, `quarantine_ml_model`
- [x] **Expanded identity actions** — `enforce_mfa`, `revoke_app_consent`
- [x] **Detection-as-Code integration** — `sigma_rule_refs` field links actions to Sigma rules
- [x] **CTEM lifecycle tagging** — `ctem_stage` field maps actions to Gartner CTEM stages
- [x] **New playbooks** — AI prompt injection response, cloud credential compromise
- [x] 7 domains (up from 5): endpoint, identity, email, network, case, cloud, ai_security
- [x] 25 actions (up from 15) across all domains

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

## v0.4 — Expanded catalog & cloud-native

**Goal:** Broaden coverage to match 2025–2026 threat landscape.

- [ ] **Cloud domain — real providers**: AWS (Boto3), Azure (azure-mgmt), GCP (google-cloud-iam)
- [ ] **Kubernetes adapter**: native K8s API for pod isolation, RBAC, network policies
- [ ] **Threat intel** domain: `submit_hash_to_sandbox`, `lookup_ioc`, `tag_ioc`
- [ ] **Vulnerability** domain: `trigger_scan`, `create_exception`, `patch_asset`
- [ ] **Exposure management** domain: `run_attack_path_analysis`, `validate_control_effectiveness`
- [ ] D3FEND full-ontology import script (auto-generate from MITRE API)
- [ ] ATLAS full-matrix import from atlas.mitre.org
- [ ] STIX/TAXII export of the action catalog

---

## v0.5 — Agentic SOC & AI integration

**Goal:** Support AI-assisted and AI-automated response workflows.

This milestone addresses the dominant 2025–2026 industry trend toward agentic SOC
platforms where AI systems autonomously handle detection, triage, investigation,
and response.

- [ ] **AI-assisted playbook generation** — given an ATT&CK/ATLAS technique, LLM
      suggests a playbook with steps, providers, and variable bindings
- [ ] **Natural language action invocation** — "isolate the compromised host" → action selection + param extraction
- [ ] **Streaming detection integration** — consume events from Kafka/Confluent,
      trigger playbooks from Sigma-in-stream matches (Confluent Sigma pattern)
- [ ] **Decision-grade enrichment** — pre-execution enrichment step that assembles
      context (threat intel, asset criticality, user risk score) into a narrative
- [ ] **CTEM orchestration** — full 5-stage workflow: scope → discover → prioritize → validate → mobilize
- [ ] **Human-in-the-loop for AI actions** — approval workflows specific to AI/ML model changes

---

## v0.6 — Additional adapters

Community-contributed adapter targets (in rough priority order):

- [ ] **Palo Alto Cortex XSOAR** — via Cortex XSOAR REST API
- [ ] **Palo Alto Cortex XSIAM** — aligned with proactive defense trend
- [ ] **SentinelOne** — via SentinelOne REST API
- [ ] **Microsoft Sentinel** — as a first-class adapter
- [ ] **Elastic Security** — via Elastic Security REST API
- [ ] **Wazuh** — open-source XDR integration (dominant OSS SIEM/XDR)
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
- **MITRE ATT&CK Evaluations alignment** — benchmark ThreatFlow coverage against annual eval results
- **CTI-REALM integration** — leverage Microsoft's AI-agent detection rule generation benchmark
- **Shadow AI discovery** — detect and inventory unmanaged AI tools/models in the environment
- **Post-quantum credential rotation** — support for quantum-safe key rotation workflows

---

## How to influence the roadmap

- Open a GitHub issue with the `roadmap` label
- Upvote existing issues
- Submit a PR — working code moves faster than proposals
- Join the discussion in GitHub Discussions

Items with multiple community upvotes and a working implementation will be fast-tracked.
