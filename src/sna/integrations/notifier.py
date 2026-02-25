"""Abstract notifier protocol and composite notifier.

Defines the interface that Discord and Teams notifiers implement.
The composite notifier dispatches to all configured backends concurrently.
Failures in one backend never block the others.
"""

from __future__ import annotations

import abc
import asyncio

import structlog

from sna.policy.models import EvaluationResult

logger = structlog.get_logger()


class Notifier(abc.ABC):
    """Abstract base for notification backends."""

    @abc.abstractmethod
    async def send_escalation(self, result: EvaluationResult) -> bool:
        """Send an escalation notification.

        Args:
            result: The evaluation result that triggered the escalation.

        Returns:
            True if the notification was sent successfully, False otherwise.
        """

    @abc.abstractmethod
    async def send_block(self, result: EvaluationResult) -> bool:
        """Send a block notification.

        Args:
            result: The evaluation result that triggered the block.

        Returns:
            True if the notification was sent successfully, False otherwise.
        """


class CompositeNotifier:
    """Dispatches notifications to all configured backends concurrently.

    Failures in one backend are logged but never propagate to callers
    or block other backends from sending.

    Args:
        notifiers: List of Notifier implementations to dispatch to.
    """

    def __init__(self, notifiers: list[Notifier]) -> None:
        self._notifiers = notifiers

    @property
    def backends(self) -> list[Notifier]:
        """Return the list of configured notification backends."""
        return list(self._notifiers)

    async def send_escalation(self, result: EvaluationResult) -> list[bool]:
        """Send escalation notification to all backends.

        Args:
            result: The evaluation result that triggered the escalation.

        Returns:
            List of success/failure booleans, one per backend.
        """
        return await self._dispatch("send_escalation", result)

    async def send_block(self, result: EvaluationResult) -> list[bool]:
        """Send block notification to all backends.

        Args:
            result: The evaluation result that triggered the block.

        Returns:
            List of success/failure booleans, one per backend.
        """
        return await self._dispatch("send_block", result)

    async def _dispatch(self, method: str, result: EvaluationResult) -> list[bool]:
        """Dispatch a notification method to all backends concurrently."""
        if not self._notifiers:
            return []

        tasks = [
            asyncio.create_task(self._safe_send(notifier, method, result))
            for notifier in self._notifiers
        ]
        return list(await asyncio.gather(*tasks))

    async def _safe_send(
        self, notifier: Notifier, method: str, result: EvaluationResult
    ) -> bool:
        """Call a notifier method, catching and logging any exceptions."""
        try:
            fn = getattr(notifier, method)
            return await fn(result)
        except Exception:
            await logger.aerror(
                "notification_failed",
                backend=type(notifier).__name__,
                method=method,
                tool_name=result.tool_name,
                exc_info=True,
            )
            return False


def create_notifier(
    discord_webhook_url: str | None = None,
    teams_webhook_url: str | None = None,
    httpx_timeout: float = 10.0,
) -> CompositeNotifier:
    """Factory — build a CompositeNotifier from configured webhook URLs.

    Only backends with a configured URL are included. If no URLs are
    configured, the composite notifier has no backends (notifications
    are silently skipped).

    Args:
        discord_webhook_url: Discord webhook URL, or None to skip.
        teams_webhook_url: Teams webhook URL, or None to skip.
        httpx_timeout: HTTP request timeout in seconds.

    Returns:
        A CompositeNotifier with the configured backends.
    """
    from sna.integrations.discord import DiscordNotifier
    from sna.integrations.teams import TeamsNotifier

    notifiers: list[Notifier] = []

    if discord_webhook_url:
        notifiers.append(DiscordNotifier(
            webhook_url=discord_webhook_url,
            timeout=httpx_timeout,
        ))

    if teams_webhook_url:
        notifiers.append(TeamsNotifier(
            webhook_url=teams_webhook_url,
            timeout=httpx_timeout,
        ))

    return CompositeNotifier(notifiers)
