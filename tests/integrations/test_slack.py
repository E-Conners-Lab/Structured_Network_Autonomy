"""Tests for Slack webhook notification integration."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from sna.integrations.slack import SlackNotifier, _MAX_REASON_LENGTH
from sna.policy.models import EvaluationResult, RiskTier, Verdict


def _make_result(verdict: Verdict = Verdict.ESCALATE, reason: str = "Test reason") -> EvaluationResult:
    return EvaluationResult(
        verdict=verdict,
        risk_tier=RiskTier.TIER_3_MEDIUM_RISK_WRITE,
        tool_name="configure_vlan",
        reason=reason,
        confidence_score=0.6,
        confidence_threshold=0.8,
        device_count=2,
    )


@pytest.fixture
def slack_notifier():
    """Create a SlackNotifier with mocked URL validation."""
    with patch("sna.utils.url_safety.validate_webhook_url"):
        return SlackNotifier(
            webhook_url="https://hooks.slack.com/services/T00/B00/xxx",
            timeout=5.0,
        )


class TestSlackNotifier:
    """Slack notification tests."""

    async def test_send_escalation_success(self, slack_notifier: SlackNotifier) -> None:
        """Successful escalation notification returns True."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = lambda: None

        with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
            result = await slack_notifier.send_escalation(_make_result())
            assert result is True
            mock_post.assert_called_once()

    async def test_send_block_success(self, slack_notifier: SlackNotifier) -> None:
        """Successful block notification returns True."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = lambda: None

        with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
            result = await slack_notifier.send_block(_make_result(Verdict.BLOCK))
            assert result is True
            # Verify color is red for BLOCK
            payload = mock_post.call_args[1]["json"]
            assert payload["attachments"][0]["color"] == "#FF0000"

    async def test_send_failure_returns_false(self, slack_notifier: SlackNotifier) -> None:
        """HTTP errors should return False, not crash."""
        with patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("Connection refused")):
            result = await slack_notifier.send_escalation(_make_result())
            assert result is False

    async def test_slack_message_format(self, slack_notifier: SlackNotifier) -> None:
        """Verify Block Kit structure (blocks, fields, color)."""
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = lambda: None

        with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
            await slack_notifier.send_escalation(_make_result())
            payload = mock_post.call_args[1]["json"]

            # Verify attachment structure
            assert "attachments" in payload
            attachment = payload["attachments"][0]
            assert attachment["color"] == "#FFA500"
            assert "blocks" in attachment
            assert "fields" in attachment
            assert attachment["footer"] == "Structured Network Autonomy"

            # Verify blocks
            blocks = attachment["blocks"]
            assert blocks[0]["type"] == "header"
            assert "Escalation" in blocks[0]["text"]["text"]

    async def test_not_configured_skipped(self) -> None:
        """create_notifier with no slack URL omits Slack backend."""
        from sna.integrations.notifier import create_notifier

        notifier = create_notifier()
        assert len(notifier.backends) == 0

    async def test_reason_truncated(self, slack_notifier: SlackNotifier) -> None:
        """Reason longer than 1000 chars should be truncated."""
        long_reason = "x" * 2000
        result = _make_result(reason=long_reason)

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = lambda: None

        with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
            await slack_notifier.send_escalation(result)
            payload = mock_post.call_args[1]["json"]
            # Check reason field is truncated
            reason_field = [
                f for f in payload["attachments"][0]["fields"]
                if f.get("title") == "Reason"
            ][0]
            assert len(reason_field["value"]) == _MAX_REASON_LENGTH
