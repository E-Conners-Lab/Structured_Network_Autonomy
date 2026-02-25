"""POST /evaluate — main policy evaluation endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from sna.api.auth import require_api_key
from sna.api.dependencies import get_engine
from sna.api.schemas import EvaluateRequest, EvaluateResponse
from sna.policy.engine import PolicyEngine
from sna.policy.models import EvaluationRequest

router = APIRouter()


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate_action(
    request: Request,
    body: EvaluateRequest,
    _api_key: str = Depends(require_api_key),
    engine: PolicyEngine = Depends(get_engine),
) -> EvaluateResponse:
    """Evaluate an MCP tool call against the policy engine.

    Classifies the action, checks confidence thresholds and scope limits,
    and returns a PERMIT, ESCALATE, or BLOCK verdict.
    """
    eval_request = EvaluationRequest(
        tool_name=body.tool_name,
        parameters=body.parameters,
        device_targets=body.device_targets,
        confidence_score=body.confidence_score,
        context=body.context,
    )

    result = await engine.evaluate(eval_request)

    return EvaluateResponse(
        verdict=result.verdict,
        risk_tier=result.risk_tier,
        tool_name=result.tool_name,
        reason=result.reason,
        confidence_score=result.confidence_score,
        confidence_threshold=result.confidence_threshold,
        device_count=result.device_count,
        requires_audit=result.requires_audit,
        requires_senior_approval=result.requires_senior_approval,
        escalation_id=result.escalation_id,
    )
