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

import aiofiles

from sqlalchemy import select

from sna.db.models import AgentPolicyOverride, AuditLog, EscalationRecord, PolicyVersion
from sna.policy.loader import compute_policy_hash, load_policy, reload_policy
from sna.policy.models import (
    EvaluationRequest,
    EvaluationResult,
    PolicyConfig,
    RiskTier,
    Verdict,
)
from sna.policy.context_rules import evaluate_agent_overrides, evaluate_context_rules, merge_verdicts
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

        # Step 3: Get effective threshold (with dynamic confidence adjustments)
        device_criticality = 0.0
        raw_criticality = request.context.get("device_criticality")
        if isinstance(raw_criticality, (int, float)):
            device_criticality = max(0.0, min(1.0, float(raw_criticality)))

        history_factor = await self._compute_history_factor(request.agent_id)

        threshold = get_effective_threshold(
            tier, self._policy, self._eas,
            device_criticality=device_criticality,
            history_factor=history_factor,
        )

        # Step 3.5: Context rule check (site/role/tag)
        context_verdict, matched_rules = evaluate_context_rules(
            request.context, tool_name, tier, self._policy,
        )
        matched_rule_strs = [
            f"{m.rule_type}:{m.match_value}→{m.verdict.value}" for m in matched_rules
        ]

        # Step 3.6: Agent-specific overrides (can only be more restrictive)
        agent_override_verdict: Verdict | None = None
        if request.agent_id is not None:
            try:
                agent_overrides = await self._fetch_agent_overrides(request.agent_id)
                if agent_overrides:
                    agent_override_verdict, agent_matches = evaluate_agent_overrides(
                        agent_overrides, request.context, tool_name, tier,
                    )
                    matched_rules.extend(agent_matches)
                    matched_rule_strs.extend(
                        f"{m.rule_type}:{m.match_value}→{m.verdict.value}" for m in agent_matches
                    )
            except Exception:
                await logger.awarning("agent_override_fetch_failed", agent_id=request.agent_id)

        # Merge global context verdict with agent override verdict
        final_context_verdict = merge_verdicts(context_verdict, agent_override_verdict)

        if final_context_verdict in (Verdict.BLOCK, Verdict.ESCALATE):
            all_context_matches = matched_rules
            reason_parts = [f"Context rule: {m.reason}" for m in all_context_matches if m.verdict == final_context_verdict]
            return await self._finalize(
                request=request,
                verdict=final_context_verdict,
                risk_tier=tier,
                reason=reason_parts[0] if reason_parts else f"Context rule override → {final_context_verdict.value}",
                confidence_threshold=threshold,
                device_count=device_count,
                requires_senior_approval=tier_config.requires_senior_approval if final_context_verdict == Verdict.ESCALATE else False,
                matched_rules=matched_rule_strs,
            )

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
        matched_rules: list[str] | None = None,
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
            matched_rules=matched_rules or [],
        )

    async def reload(
        self, file_path: str, *, created_by: str = "system",
    ) -> tuple[PolicyConfig, str | None]:
        """Hot reload the policy from YAML and persist a version record.

        Loads the new policy, computes a diff against the current policy,
        persists a PolicyVersion to the database, and swaps the active policy.
        If loading fails, the current policy remains unchanged.

        Args:
            file_path: Path to the policy YAML file.
            created_by: Who triggered the reload.

        Returns:
            A tuple of (new_policy, diff_text).

        Raises:
            FileNotFoundError: If the file does not exist.
            yaml.YAMLError: If the YAML is malformed.
            pydantic.ValidationError: If validation fails.
        """
        new_policy, diff_text = await reload_policy(file_path, self._policy)

        # Read raw YAML for versioning
        async with aiofiles.open(file_path, mode="r", encoding="utf-8") as f:
            raw_yaml = await f.read()

        await self._persist_version(
            policy=new_policy,
            raw_yaml=raw_yaml,
            diff_text=diff_text,
            created_by=created_by,
        )

        self._policy = new_policy
        return new_policy, diff_text

    async def _compute_history_factor(self, agent_id: int | None) -> float:
        """Compute history factor from agent's recent verdict history.

        Returns 0.0 if no agent_id or no history.
        """
        if agent_id is None:
            return 0.0

        dc = self._policy.dynamic_confidence
        if dc.max_history_bonus <= 0.0:
            return 0.0

        try:
            from datetime import UTC, datetime, timedelta

            cutoff = datetime.now(UTC) - timedelta(days=dc.history_window_days)
            async with self._session_factory() as session:
                result = await session.execute(
                    select(AuditLog.verdict, AuditLog.timestamp)
                    .where(
                        AuditLog.agent_id == agent_id,
                        AuditLog.timestamp >= cutoff,
                    )
                )
                rows = result.all()

            if not rows:
                return 0.0

            from sna.policy.confidence import compute_history_factor

            verdicts = [(row[0], row[1]) for row in rows]
            return compute_history_factor(verdicts, dc.history_window_days)
        except Exception:
            return 0.0

    async def _fetch_agent_overrides(self, agent_id: int) -> list[dict]:
        """Fetch active policy overrides for an agent from the database."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(AgentPolicyOverride)
                .where(
                    AgentPolicyOverride.agent_id == agent_id,
                    AgentPolicyOverride.is_active.is_(True),
                )
                .order_by(AgentPolicyOverride.priority.desc())
            )
            overrides = result.scalars().all()
            return [
                {
                    "rule_type": o.rule_type,
                    "rule_json": o.rule_json,
                    "priority": o.priority,
                }
                for o in overrides
            ]

    async def _persist_version(
        self,
        *,
        policy: PolicyConfig,
        raw_yaml: str,
        diff_text: str | None = None,
        created_by: str = "system",
    ) -> PolicyVersion | None:
        """Persist a policy version to the database.

        Returns the created PolicyVersion, or None if persistence fails.
        Version persistence failures are logged but do not block operation.
        """
        try:
            policy_hash = compute_policy_hash(raw_yaml)
            async with self._session_factory() as session:
                async with session.begin():
                    version = PolicyVersion(
                        version_string=policy.version,
                        policy_yaml=raw_yaml,
                        policy_hash=policy_hash,
                        diff_text=diff_text,
                        created_by=created_by,
                    )
                    session.add(version)
                    await session.flush()
                    return version
        except Exception:
            await logger.awarning(
                "policy_version_persist_failed",
                version=policy.version,
                exc_info=True,
            )
            return None

    @classmethod
    async def from_config(
        cls,
        policy_file_path: str,
        session_factory: async_sessionmaker[AsyncSession],
        default_eas: float,
    ) -> PolicyEngine:
        """Factory method — create a PolicyEngine from configuration.

        Loads the policy YAML, persists the initial version, and initializes the engine.

        Args:
            policy_file_path: Path to the policy YAML file.
            session_factory: Async session factory for database access.
            default_eas: The initial EAS value.

        Returns:
            A fully initialized PolicyEngine.
        """
        policy = await load_policy(policy_file_path)
        engine = cls(
            policy=policy,
            session_factory=session_factory,
            initial_eas=default_eas,
        )

        # Persist initial version
        async with aiofiles.open(policy_file_path, mode="r", encoding="utf-8") as f:
            raw_yaml = await f.read()

        await engine._persist_version(
            policy=policy,
            raw_yaml=raw_yaml,
            diff_text=None,
            created_by="system_init",
        )

        return engine
