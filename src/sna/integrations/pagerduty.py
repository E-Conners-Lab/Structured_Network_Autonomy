"""PagerDuty Events API v2 integration — severity-aware alerting.

BLOCK verdicts trigger critical incidents (page on-call).
ESCALATE verdicts create warning events (notify without paging).

SECURITY: Routing key is never logged. Dedup keys are deterministic
to prevent alert storms.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import httpx
import structlog

from sna.integrations.notifier import Notifier
from sna.policy.models import EvaluationResult

logger = structlog.get_logger()

_PAGERDUTY_API_URL = "https://events.pagerduty.com/v2/enqueue"
_MAX_SUMMARY_LENGTH = 200


class PagerDutyNotifier(Notifier):
    """Sends severity-aware alerts to PagerDuty via Events API v2.

    BLOCK → critical incident (pages on-call).
    ESCALATE → warning event (notifies without paging).

    Args:
        routing_key: The PagerDuty Events API v2 routing key. Treated as a secret.
        api_url: PagerDuty Events API URL (default: production endpoint).
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        routing_key: str,
        api_url: str = _PAGERDUTY_API_URL,
        timeout: float = 10.0,
    ) -> None:
        self._routing_key = routing_key
        self._api_url = api_url
        self._timeout = timeout

    async def send_escalation(self, result: EvaluationResult) -> bool:
        """Send an ESCALATE notification as a warning event."""
        payload = self._build_event(result, severity="warning", prefix="ESCALATION")
        return await self._post(payload)

    async def send_block(self, result: EvaluationResult) -> bool:
        """Send a BLOCK notification as a critical incident."""
        payload = self._build_event(result, severity="critical", prefix="BLOCKED")
        return await self._post(payload)

    def _build_event(
        self, result: EvaluationResult, severity: str, prefix: str
    ) -> dict:
        """Build a PagerDuty Events API v2 event payload."""
        devices = ", ".join(sorted(str(d) for d in (result.matched_rules or [])))
        reason_short = result.reason[:_MAX_SUMMARY_LENGTH]
        summary = f"SNA {prefix}: {result.tool_name} — {reason_short}"

        dedup_key = self._compute_dedup_key(result)

        return {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": summary,
                "source": "sna",
                "severity": severity,
                "component": result.tool_name,
                "custom_details": {
                    "risk_tier": result.risk_tier.value,
                    "confidence_score": result.confidence_score,
                    "device_count": result.device_count,
                    "verdict": result.verdict.value,
                    "reason": result.reason[:_MAX_SUMMARY_LENGTH],
                },
            },
        }

    def _compute_dedup_key(self, result: EvaluationResult) -> str:
        """Compute deterministic dedup key to prevent alert storms.

        Same tool + device count + minute → same dedup key.
        PagerDuty deduplicates events with the same key.
        """
        now = datetime.now(UTC)
        timestamp_minute = now.strftime("%Y-%m-%dT%H:%M")
        raw = f"{result.tool_name}:{result.device_count}:{timestamp_minute}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    async def _post(self, payload: dict) -> bool:
        """POST the event to the PagerDuty Events API."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._api_url,
                    json=payload,
                )
                response.raise_for_status()

            await logger.ainfo(
                "pagerduty_event_sent",
                severity=payload["payload"]["severity"],
                tool_name=payload["payload"]["component"],
            )
            return True

        except httpx.HTTPStatusError as exc:
            await logger.aerror(
                "pagerduty_event_http_error",
                status_code=exc.response.status_code,
            )
            return False

        except httpx.RequestError:
            await logger.aerror(
                "pagerduty_event_request_error",
                exc_info=True,
            )
            return False
