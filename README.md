# ThreatFlow

**Vendor-neutral SOC response abstraction framework.**

ThreatFlow is the *Sigma for response actions* — a standardised schema, action catalog, and adapter layer that lets security teams write response logic once and execute it across CrowdStrike Falcon, Microsoft Defender, Splunk SOAR, and custom tools.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![MITRE D3FEND](https://img.shields.io/badge/MITRE-D3FEND-red.svg)](https://d3fend.mitre.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange.svg)](https://attack.mitre.org/)

---

## What it is

- **Action catalog** — YAML-defined, vendor-neutral response actions (isolate host, block IP, disable user…)
- **Provider adapters** — thin translation layers to CrowdStrike, Defender, Splunk SOAR APIs
- **Playbook engine** — YAML playbooks with variable substitution, conditional steps, and step routing
- **MITRE integration** — every action maps to D3FEND defensive techniques and ATT&CK techniques it counters
- **CLI** — `threatflow` command for operators and CI/CD pipelines

## What it is NOT

- Not a full SOAR platform (no web UI, no event ingestion pipeline)
- Not an async distributed worker system
- Not a database-backed application

---

## Architecture

```
threatflow/
├── core/
│   ├── models.py        # Pydantic domain models (Action, ExecutionResult, …)
│   ├── registry.py      # In-memory action registry
│   ├── loader.py        # YAML catalog loader
│   └── executor.py      # Action executor (validation + dispatch)
├── adapters/
│   ├── base.py          # BaseAdapter abstract interface
│   ├── crowdstrike/     # CrowdStrike Falcon adapter
│   ├── defender/        # Microsoft Defender + Entra ID adapter
│   └── splunk_soar/     # Splunk SOAR adapter
├── playbook/
│   ├── models.py        # Playbook Pydantic models
│   ├── validator.py     # Structural + semantic playbook validation
│   └── executor.py      # Step-by-step playbook runner
├── mappings/
│   └── mitre.py         # ATT&CK ↔ D3FEND cross-reference index
└── cli/
    ├── main.py          # CLI app (Typer)
    ├── actions.py       # `threatflow actions` commands
    ├── run.py           # `threatflow run` command
    ├── plan.py          # `threatflow plan` command
    └── playbook.py      # `threatflow playbook` commands

catalog/
├── actions/             # Action definition YAML files (one file per domain)
│   ├── endpoint.yaml
│   ├── identity.yaml
│   ├── email.yaml
│   ├── network.yaml
│   └── case.yaml
└── mappings/
    ├── attack.yaml      # Bundled ATT&CK technique subset
    └── d3fend.yaml      # Bundled D3FEND technique subset

playbooks/               # Example YAML playbooks
schemas/                 # JSON schemas for validation
```

### Key design principles

| Principle | Implementation |
|-----------|---------------|
| **Vendor-neutral schema** | Actions defined in YAML with no provider coupling |
| **Vendor-native execution** | Adapters translate to each platform's native API |
| **D3FEND-aware** | Every action carries D3FEND technique mappings |
| **Safe by default** | Risk levels and approval modes built into action definitions |
| **Offline-first** | No runtime calls to MITRE APIs; bundled mapping data |

---

## Installation

```bash
# From source (development)
git clone https://github.com/threatflow/threatflow
cd threatflow
pip install -e ".[dev]"

# From PyPI (when published)
pip install threatflow
```

Requires Python 3.12+.

---

## Quick start

### Browse the action catalog

```bash
threatflow actions list
threatflow actions list --domain endpoint
threatflow actions list --provider crowdstrike
threatflow actions show isolate_host
```

### Run a single action

```bash
# Dry-run first (no real API calls)
threatflow run isolate_host --provider crowdstrike \
    --param host_id=abc1234567890abcdef1234567890ab \
    --dry-run

# Execute (soft-approval prompt)
threatflow run isolate_host --provider crowdstrike \
    --param host_id=abc1234567890abcdef1234567890ab

# Bypass soft approval (--force), useful in automated pipelines
threatflow run block_ip --provider defender \
    --param ip_address=198.51.100.42 \
    --force
```

### Plan a response from an ATT&CK technique

```bash
threatflow plan --attack-technique T1486
threatflow plan --attack-technique T1566 --provider defender
```

### Validate a playbook

```bash
threatflow playbook validate playbooks/ransomware_response.yaml
```

### Run a playbook

```bash
# Dry-run all steps
threatflow playbook run playbooks/ransomware_response.yaml \
    --inputs incident_inputs.json \
    --dry-run

# Live run
threatflow playbook run playbooks/compromised_account.yaml \
    --inputs inputs.json \
    --force
```

**`incident_inputs.json`** example:
```json
{
    "host_id": "abc1234567890abcdef1234567890ab",
    "c2_ip": "198.51.100.42",
    "analyst_upn": "analyst@corp.com"
}
```

---

## Action catalog

The catalog ships 15 built-in actions across 5 domains:

| Domain | Actions |
|--------|---------|
| **endpoint** | `isolate_host`, `release_host`, `kill_process`, `quarantine_file` |
| **identity** | `disable_user`, `revoke_session`, `reset_password` |
| **email** | `purge_email`, `block_sender`, `block_domain` |
| **network** | `block_ip`, `unblock_ip` |
| **case** | `create_case`, `append_note`, `add_artifact` |

### Action schema

```yaml
id: isolate_host
name: Isolate Host
domain: endpoint
description: Isolate a host from the network.
risk_level: high          # low | medium | high | critical
approval_mode: soft       # none | soft | hard
supported_providers:
  - crowdstrike
  - defender
  - splunk_soar
inputs:
  - name: host_id
    type: string
    required: true
    description: Platform-specific host identifier.
outputs:
  - name: status
    type: string
    description: Isolation status.
d3fend_mappings:
  - technique_id: D3-NI
    technique_name: Network Isolation
    tactic: Isolate
attack_mappings:
  - technique_id: T1486
    technique_name: Data Encrypted for Impact
    tactic: Impact
tags: [endpoint, containment]
```

### Approval modes

| Mode | Behaviour |
|------|-----------|
| `none` | Execute immediately |
| `soft` | Prompt operator for confirmation; `--force` bypasses |
| `hard` | Requires out-of-band approval token; cannot be bypassed via CLI |

---

## Playbook format

```yaml
id: ransomware_response
name: Ransomware Incident Response
version: "1.0.0"
severity: critical
triggers: [T1486]

inputs:
  - name: host_id
    type: string
    required: true

steps:
  - id: create_case
    action_id: create_case
    provider: crowdstrike
    inputs:
      title: "Ransomware — Active Encryption"
      severity: critical
    on_failure: stop

  - id: isolate_host
    action_id: isolate_host
    provider: crowdstrike
    inputs:
      host_id: "{{ host_id }}"
      comment: "Case {{ create_case.case_id }}"
    on_failure: stop
```

### Template variables

- `{{ variable_name }}` — resolved from playbook inputs
- `{{ step_id.output_key }}` — resolved from a previous step's outputs
- Conditions: `condition: "c2_ip != ''"` — Python boolean expressions evaluated against context

---

## Provider adapters

### Built-in adapters

| Provider | ID | Coverage |
|----------|-----|---------|
| CrowdStrike Falcon | `crowdstrike` | Endpoint isolation, RTR, quarantine, custom IOA |
| Microsoft Defender + Entra ID | `defender` | MDE, Graph API, EXO, Sentinel |
| Splunk SOAR | `splunk_soar` | All capabilities via SOAR app connector dispatch |

### Writing a custom adapter

See [`examples/custom_adapter.py`](examples/custom_adapter.py) for a complete template.

The interface is six methods:

```python
class MyAdapter(BaseAdapter):
    PROVIDER_ID = "my_platform"

    def provider_info(self) -> ProviderInfo: ...
    def get_capabilities(self) -> list[str]: ...
    def validate_inputs(self, action, params) -> list[str]: ...
    def execute(self, action, params) -> ExecutionResult: ...
    def dry_run(self, action, params) -> ExecutionResult: ...
    def map_native_action(self, action) -> NativeActionMapping: ...
```

Register it with the executor:

```python
executor.register_adapter("my_platform", MyAdapter(config={"url": "..."}))
```

---

## Python API

```python
from threatflow.core.loader import CatalogLoader
from threatflow.core.executor import ActionExecutor
from threatflow.adapters.crowdstrike import CrowdStrikeAdapter

# Load catalog
registry = CatalogLoader().load_default_catalog()

# Configure executor
executor = ActionExecutor(registry)
executor.register_adapter("crowdstrike", CrowdStrikeAdapter(config={...}))

# Execute an action
result = executor.execute(
    "isolate_host",
    provider="crowdstrike",
    params={"host_id": "abc123..."},
    dry_run=True,
)
print(result.success, result.outputs)

# Run a playbook
from threatflow.playbook.validator import PlaybookValidator
from threatflow.playbook.executor import PlaybookExecutor
from pathlib import Path

playbook = PlaybookValidator(registry).validate_file(Path("playbooks/ransomware_response.yaml"))
result = PlaybookExecutor(executor).run(playbook, inputs={"host_id": "abc..."})
print(result.success, result.steps_succeeded)
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_CATALOG_DIR` | `./catalog/actions` | Override the action catalog directory |
| `THREATFLOW_MAPPINGS_DIR` | `./catalog/mappings` | Override the MITRE mappings directory |

---

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage
pytest --cov=threatflow --cov-report=term-missing

# Specific test file
pytest tests/test_adapters.py -v
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add actions, adapters, and playbooks.

## Roadmap

See [roadmap.md](roadmap.md) for planned features.

## License

Apache 2.0 — see [LICENSE](LICENSE).
