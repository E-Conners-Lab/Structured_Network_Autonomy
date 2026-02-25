"""GET /metrics — Prometheus metrics endpoint (auth required)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from starlette.responses import Response

from sna.api.auth import require_api_key
from sna.observability.metrics import get_metrics_text

router = APIRouter()


@router.get("/metrics")
async def prometheus_metrics(
    request: Request,
    _api_key: str = Depends(require_api_key),
) -> Response:
    """Serve Prometheus metrics. Requires API key authentication."""
    return Response(
        content=get_metrics_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
