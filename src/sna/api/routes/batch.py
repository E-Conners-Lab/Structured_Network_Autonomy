"""Batch operations API routes.

POST /batch/execute requires admin authentication (high-blast-radius).
Batch size is limited by settings.max_batch_size.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from sna.api.auth import require_admin_key
from sna.api.rate_limit import limiter
from sna.api.schemas import (
    BatchExecuteRequest,
    BatchExecuteResponse,
    DeviceBatchResultResponse,
)
from sna.devices.batch import BatchExecutor, BatchItem, CircularDependencyError
from sna.devices.registry import Platform
from sna.policy.models import EvaluationRequest, Verdict

router = APIRouter(prefix="/batch", tags=["batch"])


@router.post(
    "/execute",
    response_model=BatchExecuteResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_admin_key)],
)
@limiter.limit("5/minute")
async def batch_execute(
    request: Request,
    body: BatchExecuteRequest,
) -> BatchExecuteResponse:
    """Execute a batch of device operations.

    Requires admin API key. Batch size limited by settings.max_batch_size.
    Each item is evaluated against policy before execution.
    """
    settings = request.app.state.settings
    max_batch_size = getattr(settings, "max_batch_size", 10)

    if len(body.items) > max_batch_size:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Batch size {len(body.items)} exceeds limit of {max_batch_size}",
        )

    policy_engine = request.app.state.engine
    batch_executor: BatchExecutor | None = getattr(request.app.state, "batch_executor", None)

    if batch_executor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Batch executor not available",
        )

    # Evaluate policy for EVERY unique tool in the batch
    tool_names = {item.tool_name for item in body.items}
    device_targets = [item.device_target for item in body.items]

    eval_result = None
    for tool_name in sorted(tool_names):
        eval_request = EvaluationRequest(
            tool_name=tool_name,
            parameters={},
            device_targets=device_targets,
            confidence_score=body.confidence_score,
            context=dict(body.context),
        )
        eval_result = await policy_engine.evaluate(eval_request)
        if eval_result.verdict != Verdict.PERMIT:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Batch {eval_result.verdict.value} (tool={tool_name}): {eval_result.reason}",
            )

    if eval_result is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Batch must contain at least one item",
        )

    # Build batch items
    platform_map = {p.value: p for p in Platform}
    batch_items = [
        BatchItem(
            device_target=item.device_target,
            tool_name=item.tool_name,
            params=item.params,
            platform=platform_map.get(item.platform, Platform.IOS_XE),
            depends_on=item.depends_on,
            priority=item.priority,
        )
        for item in body.items
    ]

    try:
        batch_result = await batch_executor.execute_batch(
            items=batch_items,
            evaluation_result=eval_result,
            rollback_on_failure=body.rollback_on_failure,
        )
    except CircularDependencyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    # Build response
    item_responses = []
    for device_result in batch_result.items:
        item_responses.append(DeviceBatchResultResponse(
            device=device_result.device,
            success=(
                device_result.execution_result is not None
                and device_result.execution_result.success
                and not device_result.rolled_back
            ),
            output=device_result.execution_result.output if device_result.execution_result else "",
            rolled_back=device_result.rolled_back,
            error=device_result.error,
            validation_results=[
                {
                    "testcase": vr.testcase_name,
                    "status": vr.status.value,
                    "message": vr.message,
                }
                for vr in device_result.validation_results
            ],
        ))

    return BatchExecuteResponse(
        batch_id=batch_result.batch_id,
        total=batch_result.total,
        succeeded=batch_result.succeeded,
        failed=batch_result.failed,
        rolled_back=batch_result.rolled_back,
        duration_seconds=batch_result.duration_seconds,
        items=item_responses,
    )
