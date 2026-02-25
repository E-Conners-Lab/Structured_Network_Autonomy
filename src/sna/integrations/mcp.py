"""MCP tool call interceptor — routes all tool calls through the Policy Engine.

This is the primary integration point for AI agents. Every MCP tool call
passes through MCPGateway.intercept() before execution. The gateway:

1. Builds an EvaluationRequest from the tool call
2. Evaluates it against the PolicyEngine
3. Fires notifications on ESCALATE or BLOCK verdicts
4. Returns an MCPInterceptResult the caller uses to proceed or halt

The gateway never executes the tool itself — it only governs whether
the tool SHOULD be executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog

from sna.integrations.notifier import CompositeNotifier
from sna.policy.engine import PolicyEngine
from sna.policy.models import EvaluationRequest, EvaluationResult, Verdict

logger = structlog.get_logger()


@dataclass(frozen=True)
class MCPToolCall:
    """Represents an incoming MCP tool call to be evaluated.

    This is the external-facing input format. The gateway converts it
    to an internal EvaluationRequest for the PolicyEngine.

    Attributes:
        tool_name: The MCP tool being invoked (e.g., "show_interfaces").
        parameters: Tool parameters as key-value pairs.
        device_targets: List of device identifiers the tool targets.
        confidence_score: The AI agent's confidence in this action (0.0–1.0).
        context: Additional context from the agent (model, session, etc.).
        caller_id: Identifier of the calling agent (for logging).
    """

    tool_name: str
    parameters: dict[str, object] = field(default_factory=dict)
    device_targets: list[str] = field(default_factory=list)
    confidence_score: float = 0.0
    context: dict[str, object] = field(default_factory=dict)
    caller_id: str = "unknown"


@dataclass(frozen=True)
class MCPInterceptResult:
    """Result of intercepting an MCP tool call.

    The caller inspects `permitted` to decide whether to execute the tool.
    Full evaluation details are available in `evaluation` for logging
    or passing back to the agent.

    Attributes:
        permitted: True if the action may proceed (PERMIT verdict).
        evaluation: The full EvaluationResult from the PolicyEngine.
        timestamp: When the interception occurred (UTC).
        notifications_sent: Number of notifications successfully dispatched.
    """

    permitted: bool
    evaluation: EvaluationResult
    timestamp: datetime
    notifications_sent: int = 0


class MCPGateway:
    """Gateway that intercepts MCP tool calls and enforces policy.

    All tool calls pass through intercept() before execution. The gateway
    is stateless except for its references to the engine and notifier.

    Args:
        engine: The PolicyEngine instance for evaluation.
        notifier: The CompositeNotifier for escalation/block alerts.
    """

    def __init__(
        self,
        engine: PolicyEngine,
        notifier: CompositeNotifier,
    ) -> None:
        self._engine = engine
        self._notifier = notifier

    @property
    def engine(self) -> PolicyEngine:
        """The PolicyEngine used for evaluation."""
        return self._engine

    @property
    def notifier(self) -> CompositeNotifier:
        """The CompositeNotifier used for alerts."""
        return self._notifier

    async def intercept(self, tool_call: MCPToolCall) -> MCPInterceptResult:
        """Intercept an MCP tool call and evaluate it against policy.

        Flow:
        1. Convert MCPToolCall → EvaluationRequest
        2. Call PolicyEngine.evaluate()
        3. If ESCALATE → send escalation notifications
        4. If BLOCK → send block notifications
        5. Return MCPInterceptResult

        Notification failures are logged but never cause the intercept
        to fail — the verdict stands regardless.

        Args:
            tool_call: The incoming MCP tool call to evaluate.

        Returns:
            An MCPInterceptResult with the verdict and context.
        """
        timestamp = datetime.now(UTC)

        # 1. Convert to internal request
        eval_request = EvaluationRequest(
            tool_name=tool_call.tool_name,
            parameters=tool_call.parameters,
            device_targets=tool_call.device_targets,
            confidence_score=tool_call.confidence_score,
            context=tool_call.context,
        )

        # 2. Evaluate
        result = await self._engine.evaluate(eval_request)

        # 3/4. Notify on ESCALATE or BLOCK
        notifications_sent = 0
        if result.verdict == Verdict.ESCALATE:
            outcomes = await self._notifier.send_escalation(result)
            notifications_sent = sum(1 for o in outcomes if o)
        elif result.verdict == Verdict.BLOCK:
            outcomes = await self._notifier.send_block(result)
            notifications_sent = sum(1 for o in outcomes if o)

        await logger.ainfo(
            "mcp_intercept",
            tool_name=tool_call.tool_name,
            caller_id=tool_call.caller_id,
            verdict=result.verdict.value,
            risk_tier=result.risk_tier.value,
            notifications_sent=notifications_sent,
        )

        # 5. Return result
        return MCPInterceptResult(
            permitted=result.verdict == Verdict.PERMIT,
            evaluation=result,
            timestamp=timestamp,
            notifications_sent=notifications_sent,
        )
