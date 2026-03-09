"""
Playbook executor.

Runs a validated :class:`~opensecops.playbook.models.Playbook` step by step,
performing input template substitution, conditional evaluation, and step
routing (on_success / on_failure).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from opensecops.core.executor import ActionExecutor, ApprovalRequired
from opensecops.core.models import ExecutionResult
from opensecops.playbook.models import OnError, Playbook, PlaybookStep

logger = logging.getLogger(__name__)


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    SKIPPED_CONDITION = "skipped_condition"


@dataclass
class StepResult:
    """Result of executing a single playbook step."""

    step_id: str
    status: StepStatus
    execution_result: ExecutionResult | None = None
    error: str | None = None
    skipped_reason: str | None = None


@dataclass
class PlaybookRunResult:
    """Aggregated result of a full playbook run."""

    playbook_id: str
    success: bool
    steps: list[StepResult] = field(default_factory=list)
    error: str | None = None
    dry_run: bool = False

    @property
    def steps_succeeded(self) -> int:
        return sum(1 for s in self.steps if s.status == StepStatus.SUCCESS)

    @property
    def steps_failed(self) -> int:
        return sum(1 for s in self.steps if s.status == StepStatus.FAILED)

    @property
    def steps_skipped(self) -> int:
        return sum(
            1
            for s in self.steps
            if s.status in (StepStatus.SKIPPED, StepStatus.SKIPPED_CONDITION)
        )


class PlaybookExecutor:
    """
    Executes a :class:`~opensecops.playbook.models.Playbook` using an
    :class:`~opensecops.core.executor.ActionExecutor`.

    Template substitution uses ``{{ variable_name }}`` syntax. Variable values
    come from the ``inputs`` dict passed to :meth:`run`, plus outputs from
    previously executed steps (accessible as ``{{ step_id.output_key }}``).

    Args:
        executor: Configured :class:`~opensecops.core.executor.ActionExecutor`.
    """

    def __init__(self, executor: ActionExecutor) -> None:
        self._executor = executor

    def run(
        self,
        playbook: Playbook,
        inputs: dict[str, Any] | None = None,
        *,
        dry_run: bool = False,
        approved: bool = False,
    ) -> PlaybookRunResult:
        """Execute all steps of *playbook*.

        Args:
            playbook: Validated playbook to run.
            inputs: Runtime values for playbook input variables.
            dry_run: When True, all steps are simulated.
            approved: When True, soft-approval gates are bypassed for all steps.

        Returns:
            :class:`PlaybookRunResult` with per-step results.
        """
        inputs = inputs or {}
        context: dict[str, Any] = dict(inputs)
        step_results: list[StepResult] = []

        logger.info(
            "%s playbook '%s' (%d steps)",
            "Dry-running" if dry_run else "Running",
            playbook.id,
            len(playbook.steps),
        )

        # Validate required inputs and apply all defaults
        for inp in playbook.inputs:
            if inp.name not in context:
                if inp.required and inp.default is None:
                    return PlaybookRunResult(
                        playbook_id=playbook.id,
                        success=False,
                        error=f"Required playbook input '{inp.name}' not provided",
                        dry_run=dry_run,
                    )
                if inp.default is not None:
                    context[inp.name] = inp.default

        # Execute steps in order (with routing)
        step_index = 0
        executed_step_ids: set[str] = set()

        while step_index < len(playbook.steps):
            step = playbook.steps[step_index]

            # Prevent infinite loops from bad routing
            if step.id in executed_step_ids:
                logger.warning("Cycle detected at step '%s', stopping.", step.id)
                break
            executed_step_ids.add(step.id)

            # Evaluate condition
            if step.condition:
                try:
                    condition_met = bool(eval(step.condition, {}, dict(context)))  # noqa: S307
                except Exception as exc:
                    step_result = StepResult(
                        step_id=step.id,
                        status=StepStatus.SKIPPED_CONDITION,
                        skipped_reason=f"Condition evaluation error: {exc}",
                    )
                    step_results.append(step_result)
                    step_index += 1
                    continue

                if not condition_met:
                    step_result = StepResult(
                        step_id=step.id,
                        status=StepStatus.SKIPPED_CONDITION,
                        skipped_reason=f"Condition not met: {step.condition!r}",
                    )
                    step_results.append(step_result)
                    step_index += 1
                    continue

            # Resolve template inputs
            try:
                resolved_inputs = _resolve_inputs(step.inputs, context)
            except TemplateError as exc:
                step_result = StepResult(
                    step_id=step.id,
                    status=StepStatus.FAILED,
                    error=f"Template error: {exc}",
                )
                step_results.append(step_result)
                break

            # Execute the step
            step_dry_run = dry_run or step.dry_run
            logger.info("Step [%s] %s → %s via %s", step.id, step.name or step.action_id, step.action_id, step.provider)

            try:
                result = self._executor.execute(
                    action_id=step.action_id,
                    provider=step.provider,
                    params=resolved_inputs,
                    dry_run=step_dry_run,
                    approved=approved,
                )
            except ApprovalRequired as exc:
                step_result = StepResult(
                    step_id=step.id,
                    status=StepStatus.FAILED,
                    error=str(exc),
                )
                step_results.append(step_result)
                return PlaybookRunResult(
                    playbook_id=playbook.id,
                    success=False,
                    steps=step_results,
                    error=str(exc),
                    dry_run=dry_run,
                )
            except Exception as exc:
                step_result = StepResult(
                    step_id=step.id,
                    status=StepStatus.FAILED,
                    error=f"Unexpected error: {exc}",
                )
                step_results.append(step_result)

                if step.on_failure == OnError.STOP:
                    return PlaybookRunResult(
                        playbook_id=playbook.id,
                        success=False,
                        steps=step_results,
                        error=str(exc),
                        dry_run=dry_run,
                    )
                step_index += 1
                continue

            if result.success:
                step_result = StepResult(
                    step_id=step.id,
                    status=StepStatus.SUCCESS,
                    execution_result=result,
                )
                step_results.append(step_result)

                # Expose step outputs to subsequent steps as {{ step_id.key }}
                context[step.id] = result.outputs

                # Routing
                if step.on_success:
                    next_index = playbook.get_step_index(step.on_success)
                    if next_index is not None:
                        step_index = next_index
                        continue
                step_index += 1

            else:
                step_result = StepResult(
                    step_id=step.id,
                    status=StepStatus.FAILED,
                    execution_result=result,
                    error=result.error or result.message,
                )
                step_results.append(step_result)

                if step.on_failure == OnError.STOP:
                    return PlaybookRunResult(
                        playbook_id=playbook.id,
                        success=False,
                        steps=step_results,
                        error=result.error or result.message,
                        dry_run=dry_run,
                    )
                elif step.on_failure == OnError.SKIP:
                    step_result.status = StepStatus.SKIPPED

                step_index += 1

        all_succeeded = all(
            s.status in (StepStatus.SUCCESS, StepStatus.SKIPPED, StepStatus.SKIPPED_CONDITION)
            for s in step_results
        )
        return PlaybookRunResult(
            playbook_id=playbook.id,
            success=all_succeeded,
            steps=step_results,
            dry_run=dry_run,
        )


class TemplateError(Exception):
    """Raised when a template variable cannot be resolved."""


def _resolve_inputs(inputs: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Substitute ``{{ var }}`` and ``{{ step_id.key }}`` in input values.

    Args:
        inputs: Raw step input dict (may contain template strings).
        context: Current execution context (playbook inputs + step outputs).

    Returns:
        New dict with all templates resolved to concrete values.

    Raises:
        :class:`TemplateError`: If a variable cannot be resolved.
    """
    resolved: dict[str, Any] = {}
    for key, value in inputs.items():
        resolved[key] = _resolve_value(value, context)
    return resolved


def _resolve_value(value: Any, context: dict[str, Any]) -> Any:
    """Recursively resolve template expressions in a single value."""
    if isinstance(value, str):
        return _render_template(value, context)
    if isinstance(value, dict):
        return {k: _resolve_value(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_value(v, context) for v in value]
    return value


_TEMPLATE_RE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")


def _render_template(text: str, context: dict[str, Any]) -> Any:
    """Replace ``{{ expr }}`` in *text* with values from *context*.

    If the entire string is a single template expression (e.g. ``"{{ foo }}"``),
    return the resolved value directly (preserving non-string types).
    For strings with embedded templates, return the interpolated string.
    """
    matches = list(_TEMPLATE_RE.finditer(text))
    if not matches:
        return text

    # Single whole-string template — return native type
    if len(matches) == 1 and matches[0].group(0) == text.strip():
        expr = matches[0].group(1)
        return _eval_expr(expr, context, text)

    # Multi-template or partial interpolation — convert to string
    def replacer(m: re.Match[str]) -> str:  # type: ignore[type-arg]
        expr = m.group(1)
        val = _eval_expr(expr, context, text)
        return str(val)

    return _TEMPLATE_RE.sub(replacer, text)


def _eval_expr(expr: str, context: dict[str, Any], original: str) -> Any:
    """Evaluate a template expression like ``"foo"`` or ``"step1.host_id"``."""
    parts = expr.split(".", 1)
    root = parts[0].strip()

    if root not in context:
        raise TemplateError(
            f"Template variable '{root}' in '{original}' is not defined in context. "
            f"Available: {list(context.keys())}"
        )

    value = context[root]
    if len(parts) == 2:
        attr = parts[1].strip()
        if not isinstance(value, dict) or attr not in value:
            raise TemplateError(
                f"Cannot access '{attr}' on context variable '{root}' in '{original}'. "
                f"Available keys: {list(value.keys()) if isinstance(value, dict) else 'N/A'}"
            )
        return value[attr]

    return value
