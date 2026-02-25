"""Discord webhook integration — sends escalation notifications as rich embeds.

SECURITY: Webhook URL is never logged. All HTTP calls use configured timeout.
"""

from __future__ import annotations

import httpx
import structlog

from sna.integrations.notifier import Notifier
from sna.policy.models import EvaluationResult, Verdict

logger = structlog.get_logger()

# Embed colors (decimal)
COLOR_ESCALATE = 0xFFA500  # Orange
COLOR_BLOCK = 0xFF0000  # Red


class DiscordNotifier(Notifier):
    """Sends notifications to a Discord channel via webhook.

    Messages are formatted as rich embeds with color-coded severity,
    action details, and escalation context.

    Args:
        webhook_url: The Discord webhook URL. Treated as a secret.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        from sna.utils.url_safety import validate_webhook_url

        validate_webhook_url(webhook_url)
        self._webhook_url = webhook_url
        self._timeout = timeout

    async def send_escalation(self, result: EvaluationResult) -> bool:
        """Send an ESCALATE notification as a Discord embed."""
        embed = self._build_embed(result, COLOR_ESCALATE, "Escalation Required")
        return await self._post(embed)

    async def send_block(self, result: EvaluationResult) -> bool:
        """Send a BLOCK notification as a Discord embed."""
        embed = self._build_embed(result, COLOR_BLOCK, "Action Blocked")
        return await self._post(embed)

    def _build_embed(
        self, result: EvaluationResult, color: int, title: str
    ) -> dict:
        """Build a Discord embed payload from an evaluation result."""
        fields = [
            {"name": "Tool", "value": f"`{result.tool_name}`", "inline": True},
            {"name": "Verdict", "value": result.verdict.value, "inline": True},
            {"name": "Risk Tier", "value": result.risk_tier.value, "inline": True},
            {
                "name": "Confidence",
                "value": f"{result.confidence_score:.2f} / {result.confidence_threshold:.2f}",
                "inline": True,
            },
            {"name": "Devices", "value": str(result.device_count), "inline": True},
        ]

        if result.requires_senior_approval:
            fields.append({
                "name": "Senior Approval",
                "value": "Required",
                "inline": True,
            })

        if result.escalation_id:
            fields.append({
                "name": "Escalation ID",
                "value": f"`{result.escalation_id}`",
                "inline": False,
            })

        fields.append({
            "name": "Reason",
            "value": result.reason,
            "inline": False,
        })

        return {
            "embeds": [
                {
                    "title": f"SNA — {title}",
                    "color": color,
                    "fields": fields,
                    "footer": {"text": "Structured Network Autonomy"},
                }
            ]
        }

    async def _post(self, payload: dict) -> bool:
        """POST the payload to the Discord webhook URL."""
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._webhook_url,
                    json=payload,
                )
                response.raise_for_status()

            await logger.ainfo(
                "discord_notification_sent",
                tool_name=payload["embeds"][0]["fields"][0]["value"],
            )
            return True

        except httpx.HTTPStatusError as exc:
            await logger.aerror(
                "discord_notification_http_error",
                status_code=exc.response.status_code,
            )
            return False

        except httpx.RequestError:
            await logger.aerror(
                "discord_notification_request_error",
                exc_info=True,
            )
            return False
