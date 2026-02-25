"""Microsoft Teams webhook integration — sends escalation notifications as Adaptive Cards.

SECURITY: Webhook URL is never logged. All HTTP calls use configured timeout.
"""

from __future__ import annotations

import httpx
import structlog

from sna.integrations.notifier import Notifier
from sna.policy.models import EvaluationResult, Verdict

logger = structlog.get_logger()

# Adaptive Card accent colors
COLOR_ESCALATE = "warning"  # Orange/amber
COLOR_BLOCK = "attention"  # Red


class TeamsNotifier(Notifier):
    """Sends notifications to a Microsoft Teams channel via webhook.

    Messages are formatted as Adaptive Cards with color-coded severity,
    action details, and escalation context.

    Args:
        webhook_url: The Teams incoming webhook URL. Treated as a secret.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        self._webhook_url = webhook_url
        self._timeout = timeout

    async def send_escalation(self, result: EvaluationResult) -> bool:
        """Send an ESCALATE notification as a Teams Adaptive Card."""
        card = self._build_card(result, COLOR_ESCALATE, "Escalation Required")
        return await self._post(card)

    async def send_block(self, result: EvaluationResult) -> bool:
        """Send a BLOCK notification as a Teams Adaptive Card."""
        card = self._build_card(result, COLOR_BLOCK, "Action Blocked")
        return await self._post(card)

    def _build_card(
        self, result: EvaluationResult, style: str, title: str
    ) -> dict:
        """Build a Teams Adaptive Card payload from an evaluation result."""
        facts = [
            {"title": "Tool", "value": result.tool_name},
            {"title": "Verdict", "value": result.verdict.value},
            {"title": "Risk Tier", "value": result.risk_tier.value},
            {
                "title": "Confidence",
                "value": f"{result.confidence_score:.2f} / {result.confidence_threshold:.2f}",
            },
            {"title": "Devices", "value": str(result.device_count)},
            {"title": "Reason", "value": result.reason},
        ]

        if result.requires_senior_approval:
            facts.append({"title": "Senior Approval", "value": "Required"})

        if result.escalation_id:
            facts.append({"title": "Escalation ID", "value": str(result.escalation_id)})

        body = [
            {
                "type": "TextBlock",
                "size": "Large",
                "weight": "Bolder",
                "text": f"SNA — {title}",
                "style": style,
            },
            {
                "type": "FactSet",
                "facts": facts,
            },
        ]

        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body,
                    },
                }
            ],
        }

    async def _post(self, payload: dict) -> bool:
        """POST the payload to the Teams webhook URL."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._webhook_url,
                    json=payload,
                )
                response.raise_for_status()

            await logger.ainfo(
                "teams_notification_sent",
                tool_name=payload["attachments"][0]["content"]["body"][1]["facts"][0]["value"],
            )
            return True

        except httpx.HTTPStatusError as exc:
            await logger.aerror(
                "teams_notification_http_error",
                status_code=exc.response.status_code,
            )
            return False

        except httpx.RequestError:
            await logger.aerror(
                "teams_notification_request_error",
                exc_info=True,
            )
            return False
