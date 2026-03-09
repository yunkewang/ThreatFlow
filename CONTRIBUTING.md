# Contributing to OpenSecOps

Thank you for contributing to OpenSecOps. This guide covers the three most common contribution types:

1. **Adding a catalog action** — new vendor-neutral response action
2. **Writing a provider adapter** — connect a new security tool
3. **Creating a playbook** — new response workflow

---

## Project setup

```bash
git clone https://github.com/opensecops/opensecops
cd opensecops
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest  # verify everything passes
```

---

## 1. Adding a catalog action

Actions live in `catalog/actions/` as YAML files, grouped by domain.

### Decision checklist

Before adding a new action, verify:
- [ ] The action is **vendor-neutral** (can in principle be implemented by 2+ providers)
- [ ] It maps to at least one **D3FEND** technique
- [ ] It maps to at least one **ATT&CK** technique it counters
- [ ] It does not duplicate an existing action (run `opensecops actions list`)

### Action YAML template

```yaml
id: your_action_id        # snake_case, unique
name: Human Readable Name
domain: endpoint          # endpoint | identity | email | network | case
description: >
  Clear description of what this action does, why it matters,
  and when to use it.
version: "1.0.0"
risk_level: medium        # low | medium | high | critical
approval_mode: none       # none | soft | hard
supported_providers:
  - crowdstrike           # only list providers with working implementations
inputs:
  - name: required_param
    type: string          # string | integer | boolean | number | list | dict
    required: true
    description: What this parameter controls.
    example: "example_value"
  - name: optional_param
    type: string
    required: false
    default: "default_value"
    description: Optional parameter with a default.
outputs:
  - name: output_field
    type: string
    description: What this field contains.
d3fend_mappings:
  - technique_id: D3-XX   # must start with D3-
    technique_name: D3FEND Technique Name
    tactic: Harden
attack_mappings:
  - technique_id: T1234   # must start with T
    technique_name: ATT&CK Technique Name
    tactic: Tactic Name
tags:
  - domain_tag
  - descriptive_tag
```

### Adding to the correct file

| Domain | File |
|--------|------|
| Endpoint (host, process, file) | `catalog/actions/endpoint.yaml` |
| Identity (user, session, credential) | `catalog/actions/identity.yaml` |
| Email (message, sender, domain) | `catalog/actions/email.yaml` |
| Network (IP, firewall, DNS) | `catalog/actions/network.yaml` |
| Case management | `catalog/actions/case.yaml` |

### Validate and test

```bash
# Validate that your action loads correctly
opensecops actions list
opensecops actions show your_action_id

# Run tests
pytest tests/test_loader.py -v
```

---

## 2. Writing a provider adapter

### File structure

Create a new directory under `src/opensecops/adapters/`:

```
src/opensecops/adapters/
└── my_platform/
    ├── __init__.py          # exports MyPlatformAdapter
    └── adapter.py           # implementation
```

### Required interface

Your adapter must subclass `BaseAdapter` and implement these methods:

```python
from opensecops.adapters.base import BaseAdapter, NativeActionMapping
from opensecops.core.models import Action, ExecutionResult, ProviderInfo

class MyPlatformAdapter(BaseAdapter):
    PROVIDER_ID = "my_platform"   # kebab-case or snake_case, unique

    def provider_info(self) -> ProviderInfo:
        """Return static metadata."""

    def get_capabilities(self) -> list[str]:
        """Return list of action IDs this adapter implements."""

    def validate_inputs(self, action: Action, params: dict) -> list[str]:
        """Platform-specific validation. Return list of error strings."""

    def execute(self, action: Action, params: dict) -> ExecutionResult:
        """Execute the action. Return ExecutionResult.ok() or ExecutionResult.fail()."""

    def dry_run(self, action: Action, params: dict) -> ExecutionResult:
        """Simulate without side effects. Must set dry_run=True on result."""

    def map_native_action(self, action: Action) -> NativeActionMapping:
        """Return the native API call that implements this action."""
```

### Implementation guidance

- **Never raise exceptions** from `execute()` — catch API errors and return `ExecutionResult.fail(...)`.
- Document each handler with the real API endpoint in the docstring.
- Start with mock/demo implementations and add `# TODO: real API call` comments.
- Use `_NATIVE_MAP` dict to keep the `map_native_action` implementation clean.
- See `examples/custom_adapter.py` for a complete walkthrough.

### Register in the CLI registry

Add your adapter to `src/opensecops/cli/_registry.py`:

```python
from opensecops.adapters.my_platform import MyPlatformAdapter

executor.register_adapter(MyPlatformAdapter.PROVIDER_ID, MyPlatformAdapter())
```

### Add adapter tests

Create `tests/test_adapter_my_platform.py` following the pattern in `tests/test_adapters.py`.
At minimum, test:
- `provider_info()` returns a valid `ProviderInfo`
- `get_capabilities()` returns a non-empty list
- `execute()` returns `ExecutionResult.ok()` for a supported action
- `dry_run()` returns a result with `dry_run=True`
- `validate_inputs()` catches platform-specific errors

---

## 3. Creating a playbook

Playbooks live in `playbooks/`. See `schemas/playbook.schema.json` for the full schema.

### Playbook template

```yaml
id: my_playbook_id
name: My Response Playbook
description: >
  What this playbook responds to and how.
version: "1.0.0"
author: "Your Name or Team"
severity: high           # informational | low | medium | high | critical
triggers:
  - T1234               # ATT&CK technique IDs
tags:
  - domain
  - scenario

inputs:
  - name: target_host
    type: string
    required: true
    description: Host to act on.

steps:
  - id: step_one
    name: Descriptive step name
    action_id: some_action
    provider: crowdstrike
    inputs:
      param_one: "{{ target_host }}"
    on_failure: stop     # stop | continue | skip

  - id: step_two
    action_id: another_action
    provider: crowdstrike
    condition: "some_var != ''"   # optional gating condition
    inputs:
      reference: "{{ step_one.output_field }}"
    on_failure: continue
```

### Validate your playbook

```bash
opensecops playbook validate playbooks/my_playbook.yaml
```

### Test with dry-run

```bash
opensecops playbook run playbooks/my_playbook.yaml \
    --inputs test_inputs.json \
    --dry-run
```

---

## Code style

- Python 3.12+, type-annotated, docstrings on all public APIs
- `ruff` for linting: `ruff check src/`
- `mypy` for type checking: `mypy src/`
- All PRs must pass `pytest` with no new failures

## Pull request process

1. Open an issue describing the change
2. Fork and create a feature branch (`feature/add-xyz-adapter`)
3. Implement with tests
4. Run `pytest` and `ruff check src/`
5. Open a PR with a clear description referencing the issue

## Code of conduct

Be respectful, constructive, and collaborative. Security tooling affects real systems — careful review is a feature, not a delay.
