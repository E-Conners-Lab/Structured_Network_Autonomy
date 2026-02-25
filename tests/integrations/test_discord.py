"""Tests for sna.integrations.discord — webhook notifications."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
import pytest

from sna.integrations.discord import COLOR_BLOCK, COLOR_ESCALATE, DiscordNotifier
from sna.policy.models import EvaluationResult, RiskTier, Verdict

WEBHOOK_URL = "https://discord.com/api/webhooks/test/token"
_MOCK_REQUEST = httpx.Request("POST", WEBHOOK_URL)


def _make_result(
    verdict: Verdict = Verdict.ESCALATE,
    senior: bool = False,
) -> EvaluationResult:
    """Create a sample EvaluationResult."""
    return EvaluationResult(
        verdict=verdict,
        risk_tier=RiskTier.TIER_3_MEDIUM_RISK_WRITE,
        tool_name="configure_interface",
        reason="Confidence below threshold",
        confidence_score=0.5,
        confidence_threshold=0.8,
        device_count=3,
        requires_audit=True,
        requires_senior_approval=senior,
        escalation_id=uuid4() if verdict == Verdict.ESCALATE else None,
    )


class TestDiscordNotifier:
    """DiscordNotifier — embed formatting and HTTP posting."""

    async def test_send_escalation_success(self) -> None:
        """Successful escalation sends embed with orange color."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(Verdict.ESCALATE)

        mock_response = httpx.Response(204, request=_MOCK_REQUEST)
        with patch("sna.integrations.discord.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            success = await notifier.send_escalation(result)

        assert success is True
        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs["json"]
        assert payload["embeds"][0]["color"] == COLOR_ESCALATE
        assert "Escalation Required" in payload["embeds"][0]["title"]

    async def test_send_block_success(self) -> None:
        """Successful block sends embed with red color."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(Verdict.BLOCK)

        mock_response = httpx.Response(204, request=_MOCK_REQUEST)
        with patch("sna.integrations.discord.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            success = await notifier.send_block(result)

        assert success is True
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs["json"]
        assert payload["embeds"][0]["color"] == COLOR_BLOCK
        assert "Action Blocked" in payload["embeds"][0]["title"]

    async def test_send_http_error_returns_false(self) -> None:
        """HTTP error response should return False."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()

        mock_response = httpx.Response(
            429,
            request=httpx.Request("POST", WEBHOOK_URL),
        )
        with patch("sna.integrations.discord.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            success = await notifier.send_escalation(result)

        assert success is False

    async def test_send_connection_error_returns_false(self) -> None:
        """Connection failure should return False."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()

        with patch("sna.integrations.discord.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            success = await notifier.send_escalation(result)

        assert success is False

    def test_embed_contains_tool_name(self) -> None:
        """Embed fields should include the tool name."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()
        embed = notifier._build_embed(result, COLOR_ESCALATE, "Test")

        field_values = [f["value"] for f in embed["embeds"][0]["fields"]]
        assert any("configure_interface" in v for v in field_values)

    def test_embed_contains_confidence(self) -> None:
        """Embed fields should include confidence values."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()
        embed = notifier._build_embed(result, COLOR_ESCALATE, "Test")

        field_values = [f["value"] for f in embed["embeds"][0]["fields"]]
        assert any("0.50" in v and "0.80" in v for v in field_values)

    def test_embed_senior_approval_field(self) -> None:
        """Senior approval flag should add a field when True."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(senior=True)
        embed = notifier._build_embed(result, COLOR_ESCALATE, "Test")

        field_names = [f["name"] for f in embed["embeds"][0]["fields"]]
        assert "Senior Approval" in field_names

    def test_embed_no_senior_approval_field(self) -> None:
        """Senior approval flag should NOT add a field when False."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(senior=False)
        embed = notifier._build_embed(result, COLOR_ESCALATE, "Test")

        field_names = [f["name"] for f in embed["embeds"][0]["fields"]]
        assert "Senior Approval" not in field_names

    def test_embed_escalation_id_field(self) -> None:
        """Escalation ID should appear as a field when present."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(Verdict.ESCALATE)
        embed = notifier._build_embed(result, COLOR_ESCALATE, "Test")

        field_names = [f["name"] for f in embed["embeds"][0]["fields"]]
        assert "Escalation ID" in field_names

    def test_embed_no_escalation_id_for_block(self) -> None:
        """Block verdicts should not have an Escalation ID field."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(Verdict.BLOCK)
        embed = notifier._build_embed(result, COLOR_BLOCK, "Test")

        field_names = [f["name"] for f in embed["embeds"][0]["fields"]]
        assert "Escalation ID" not in field_names

    def test_embed_footer(self) -> None:
        """Embed should have the SNA footer."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()
        embed = notifier._build_embed(result, COLOR_ESCALATE, "Test")

        assert embed["embeds"][0]["footer"]["text"] == "Structured Network Autonomy"

    async def test_timeout_passed_to_client(self) -> None:
        """Custom timeout should be passed to httpx client."""
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL, timeout=5.0)
        result = _make_result()

        mock_response = httpx.Response(204, request=_MOCK_REQUEST)
        with patch("sna.integrations.discord.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await notifier.send_escalation(result)

        mock_client_cls.assert_called_once_with(timeout=5.0)
