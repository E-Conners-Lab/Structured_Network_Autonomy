"""Core PolicyEngine — evaluates actions and returns PERMIT, ESCALATE, or BLOCK verdicts.

The engine is the central decision-maker. Every MCP tool call passes through
evaluate() before execution. The engine is framework-agnostic — it depends on
SQLAlchemy for persistence but has no knowledge of FastAPI or HTTP.

Critical invariant: if the audit log write fails, the verdict is overridden
to BLOCK. The engine never permits an action it cannot log.
"""

from __future__ import annotations

from uuid import uuid4

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import AuditLog, EscalationRecord
from sna.policy.loader import load_policy, reload_policy
from sna.policy.models import (
    EvaluationRequest,
    EvaluationResult,
    PolicyConfig,
    RiskTier,
    Verdict,
)
from sna.policy.taxonomy import (
    check_scope_escalation,
    classify_tool,
    get_effective_threshold,
    is_hard_blocked,
)

logger = structlog.get_logger()


class PolicyEngine:
    """Evaluates actions against the loaded policy and returns verdicts.

    The engine holds the current policy and EAS in memory, reads/writes
    to the database for audit logging and escalation tracking.

    Args:
        policy: A validated PolicyConfig loaded from YAML.
        session_factory: Async SQLAlchemy session factory for database access.
        initial_eas: The starting Earned Autonomy Score.
    """

    def __init__(
        self,
        policy: PolicyConfig,
        session_factory: async_sessionmaker[AsyncSession],
        initial_eas: float,
    ) -> None:
        self._policy = policy
        self._session_factory = session_factory
        self._eas = initial_eas

    @property
    def policy(self) -> PolicyConfig:
        """The currently loaded policy configuration."""
        return self._policy

    def get_eas(self) -> float:
        """Return the current Earned Autonomy Score."""
        return self._eas

    def set_eas(self, score: float) -> None:
        """Update the Earned Autonomy Score.

        Args:
            score: New EAS value, must be between 0.0 and 1.0.

        Raises:
            ValueError: If score is outside [0.0, 1.0].
        """
        if not 0.0 <= score <= 1.0:
            raise ValueError(f"EAS must be between 0.0 and 1.0, got {score}")
        self._eas = score

    async def evaluate(self, request: EvaluationRequest) -> EvaluationResult:
        """Evaluate an action and return a verdict.

        Decision flow:
        1. Hard block check → BLOCK immediately
        2. Classify tool into risk tier
        3. Check scope (device count) → ESCALATE if exceeded
        4. Compare confidence to effective threshold → ESCALATE if below
        5. Use tier default verdict if confidence is sufficient
        6. Write audit log — failure overrides verdict to BLOCK
        7. Create escalation record if verdict is ESCALATE

        Args:
            request: The action to evaluate.

        Returns:
            An EvaluationResult with the verdict and full context.
        """
        tool_name = request.tool_name
        device_count = len(request.device_targets)

        # Step 1: Hard block check
        if is_hard_blocked(tool_name, self._policy):
            tier = classify_tool(tool_name, self._policy)
            threshold = get_effective_threshold(tier, self._policy, self._eas)
            return await self._finalize(
                request=request,
                verdict=Verdict.BLOCK,
                risk_tier=tier,
                reason="Hard-blocked action — cannot be unlocked at runtime",
                confidence_threshold=threshold,
                device_count=device_count,
            )

        # Step 2: Classify tool
        tier = classify_tool(tool_name, self._policy)
        tier_config = self._policy.action_tiers[tier]

        # Step 3: Get effective threshold
        threshold = get_effective_threshold(tier, self._policy, self._eas)

        # Step 4: Check scope escalation
        if check_scope_escalation(device_count, self._policy):
            return await self._finalize(
                request=request,
                verdict=Verdict.ESCALATE,
                risk_tier=tier,
                reason=(
                    f"Device count ({device_count}) exceeds scope limit "
                    f"({self._policy.scope_limits.escalate_above})"
                ),
                confidence_threshold=threshold,
                device_count=device_count,
                requires_senior_approval=tier_config.requires_senior_approval,
            )

        # Step 5: Compare confidence to threshold
        if request.confidence_score < threshold:
            return await self._finalize(
                request=request,
                verdict=Verdict.ESCALATE,
                risk_tier=tier,
                reason=(
                    f"Confidence ({request.confidence_score:.2f}) below "
                    f"threshold ({threshold:.2f}) for {tier.value}"
                ),
                confidence_threshold=threshold,
                device_count=device_count,
                requires_senior_approval=tier_config.requires_senior_approval,
            )

        # Step 6: Use tier default verdict
        verdict = Verdict(tier_config.default_verdict.value)
        if verdict == Verdict.PERMIT:
            reason = f"Permitted — {tier.value}, confidence ({request.confidence_score:.2f}) meets threshold ({threshold:.2f})"
        elif verdict == Verdict.ESCALATE:
            reason = f"Tier default escalation — {tier.value} requires approval"
        else:
            reason = f"Tier default block — {tier.value}"

        return await self._finalize(
            request=request,
            verdict=verdict,
            risk_tier=tier,
            reason=reason,
            confidence_threshold=threshold,
            device_count=device_count,
            requires_audit=tier_config.requires_audit,
            requires_senior_approval=tier_config.requires_senior_approval,
        )

    async def _finalize(
        self,
        *,
        request: EvaluationRequest,
        verdict: Verdict,
        risk_tier: RiskTier,
        reason: str,
        confidence_threshold: float,
        device_count: int,
        requires_audit: bool = False,
        requires_senior_approval: bool = False,
    ) -> EvaluationResult:
        """Write audit log, create escalation if needed, and return result.

        If the audit log write fails, the verdict is overridden to BLOCK.
        The engine never permits an action it cannot log.
        """
        escalation_id = None

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    # Write audit log
                    audit_entry = AuditLog(
                        tool_name=request.tool_name,
                        parameters=request.parameters if request.parameters else None,
                        device_targets=request.device_targets if request.device_targets else None,
                        device_count=device_count,
                        verdict=verdict.value,
                        risk_tier=risk_tier.value,
                        confidence_score=request.confidence_score,
                        confidence_threshold=confidence_threshold,
                        reason=reason,
                        requires_audit=requires_audit,
                        requires_senior_approval=requires_senior_approval,
                        eas_at_time=self._eas,
                    )
                    session.add(audit_entry)
                    await session.flush()

                    # Create escalation record if verdict is ESCALATE
                    if verdict == Verdict.ESCALATE:
                        escalation_ext_id = str(uuid4())
                        escalation = EscalationRecord(
                            external_id=escalation_ext_id,
                            tool_name=request.tool_name,
                            parameters=request.parameters if request.parameters else None,
                            risk_tier=risk_tier.value,
                            confidence_score=request.confidence_score,
                            reason=reason,
                            device_targets=request.device_targets if request.device_targets else None,
                            device_count=device_count,
                            requires_senior_approval=requires_senior_approval,
                            audit_log_id=audit_entry.id,
                        )
                        session.add(escalation)
                        await session.flush()
                        escalation_id = escalation.external_id

            await logger.ainfo(
                "policy_decision",
                tool_name=request.tool_name,
                verdict=verdict.value,
                risk_tier=risk_tier.value,
                confidence_score=request.confidence_score,
                threshold=confidence_threshold,
                device_count=device_count,
                eas=self._eas,
            )

        except Exception:
            # Audit write failed — fail closed
            await logger.aerror(
                "audit_write_failed",
                tool_name=request.tool_name,
                original_verdict=verdict.value,
                exc_info=True,
            )
            verdict = Verdict.BLOCK
            reason = "Audit write failed — failing safe, action blocked"
            escalation_id = None

        from uuid import UUID

        return EvaluationResult(
            verdict=verdict,
            risk_tier=risk_tier,
            tool_name=request.tool_name,
            reason=reason,
            confidence_score=request.confidence_score,
            confidence_threshold=confidence_threshold,
            device_count=device_count,
            requires_audit=requires_audit,
            requires_senior_approval=requires_senior_approval,
            escalation_id=UUID(escalation_id) if escalation_id else None,
        )

    async def reload(self, file_path: str) -> tuple[PolicyConfig, str | None]:
        """Hot reload the policy from YAML.

        Loads the new policy, computes a diff against the current policy,
        and swaps the active policy. If loading fails, the current policy
        remains unchanged.

        Args:
            file_path: Path to the policy YAML file.

        Returns:
            A tuple of (new_policy, diff_text).

        Raises:
            FileNotFoundError: If the file does not exist.
            yaml.YAMLError: If the YAML is malformed.
            pydantic.ValidationError: If validation fails.
        """
        new_policy, diff_text = await reload_policy(file_path, self._policy)
        self._policy = new_policy
        return new_policy, diff_text

    @classmethod
    async def from_config(
        cls,
        policy_file_path: str,
        session_factory: async_sessionmaker[AsyncSession],
        default_eas: float,
    ) -> PolicyEngine:
        """Factory method — create a PolicyEngine from configuration.

        Loads the policy YAML and initializes the engine.

        Args:
            policy_file_path: Path to the policy YAML file.
            session_factory: Async session factory for database access.
            default_eas: The initial EAS value.

        Returns:
            A fully initialized PolicyEngine.
        """
        policy = await load_policy(policy_file_path)
        return cls(
            policy=policy,
            session_factory=session_factory,
            initial_eas=default_eas,
        )
