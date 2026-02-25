"""Slack webhook integration — sends notifications as Block Kit messages.

SECURITY: Webhook URL is validated via SSRF protection and never logged.
All HTTP calls use configured timeout. Reason is truncated to 1000 chars.
"""

from __future__ import annotations

import httpx
import structlog

from sna.integrations.notifier import Notifier
from sna.policy.models import EvaluationResult

logger = structlog.get_logger()

_MAX_REASON_LENGTH = 1000

# Block Kit color codes
COLOR_ESCALATE = "#FFA500"  # Orange
COLOR_BLOCK = "#FF0000"  # Red


class SlackNotifier(Notifier):
    """Sends notifications to a Slack channel via Incoming Webhook.

    Messages are formatted as Slack Block Kit with color-coded severity,
    action details, and escalation context.

    Args:
        webhook_url: The Slack Incoming Webhook URL. Treated as a secret.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        from sna.utils.url_safety import validate_webhook_url

        validate_webhook_url(webhook_url)
        self._webhook_url = webhook_url
        self._timeout = timeout

    async def send_escalation(self, result: EvaluationResult) -> bool:
        """Send an ESCALATE notification as a Slack Block Kit message."""
        payload = self._build_payload(result, COLOR_ESCALATE, "Escalation Required")
        return await self._post(payload)

    async def send_block(self, result: EvaluationResult) -> bool:
        """Send a BLOCK notification as a Slack Block Kit message."""
        payload = self._build_payload(result, COLOR_BLOCK, "Action Blocked")
        return await self._post(payload)

    def _build_payload(
        self, result: EvaluationResult, color: str, title: str
    ) -> dict:
        """Build a Slack Block Kit attachment payload."""
        reason = result.reason[:_MAX_REASON_LENGTH]

        fields = [
            {"title": "Tool", "value": f"`{result.tool_name}`", "short": True},
            {"title": "Verdict", "value": result.verdict.value, "short": True},
            {"title": "Risk Tier", "value": result.risk_tier.value, "short": True},
            {
                "title": "Confidence",
                "value": f"{result.confidence_score:.2f} / {result.confidence_threshold:.2f}",
                "short": True,
            },
            {"title": "Devices", "value": str(result.device_count), "short": True},
        ]

        if result.requires_senior_approval:
            fields.append({
                "title": "Senior Approval",
                "value": "Required",
                "short": True,
            })

        if result.escalation_id:
            fields.append({
                "title": "Escalation ID",
                "value": f"`{result.escalation_id}`",
                "short": False,
            })

        fields.append({
            "title": "Reason",
            "value": reason,
            "short": False,
        })

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"SNA — {title}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tool:* `{result.tool_name}`"},
                    {"type": "mrkdwn", "text": f"*Verdict:* {result.verdict.value}"},
                    {"type": "mrkdwn", "text": f"*Risk Tier:* {result.risk_tier.value}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence:* {result.confidence_score:.2f} / {result.confidence_threshold:.2f}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reason:* {reason}",
                },
            },
        ]

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks,
                    "fields": fields,
                    "footer": "Structured Network Autonomy",
                }
            ]
        }

    async def _post(self, payload: dict) -> bool:
        """POST the payload to the Slack webhook URL."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._webhook_url,
                    json=payload,
                )
                response.raise_for_status()

            await logger.ainfo(
                "slack_notification_sent",
                destination="slack://***",
            )
            return True

        except httpx.HTTPStatusError as exc:
            await logger.aerror(
                "slack_notification_http_error",
                status_code=exc.response.status_code,
            )
            return False

        except httpx.RequestError:
            await logger.aerror(
                "slack_notification_request_error",
                exc_info=True,
            )
            return False
