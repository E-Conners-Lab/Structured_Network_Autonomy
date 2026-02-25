"""Tests for sna.integrations.teams — Teams webhook notifications."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
import pytest

from sna.integrations.teams import COLOR_BLOCK, COLOR_ESCALATE, TeamsNotifier
from sna.policy.models import EvaluationResult, RiskTier, Verdict

WEBHOOK_URL = "https://teams.microsoft.com/webhook/test/token"
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


class TestTeamsNotifier:
    """TeamsNotifier — Adaptive Card formatting and HTTP posting."""

    async def test_send_escalation_success(self) -> None:
        """Successful escalation sends Adaptive Card."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(Verdict.ESCALATE)

        mock_response = httpx.Response(200, request=_MOCK_REQUEST)
        with patch("sna.integrations.teams.httpx.AsyncClient") as mock_client_cls:
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
        card = payload["attachments"][0]["content"]
        assert card["type"] == "AdaptiveCard"
        assert "Escalation Required" in card["body"][0]["text"]

    async def test_send_block_success(self) -> None:
        """Successful block sends Adaptive Card with block title."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(Verdict.BLOCK)

        mock_response = httpx.Response(200, request=_MOCK_REQUEST)
        with patch("sna.integrations.teams.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            success = await notifier.send_block(result)

        assert success is True
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs["json"]
        card = payload["attachments"][0]["content"]
        assert "Action Blocked" in card["body"][0]["text"]

    async def test_send_http_error_returns_false(self) -> None:
        """HTTP error response should return False."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()

        mock_response = httpx.Response(
            429,
            request=httpx.Request("POST", WEBHOOK_URL),
        )
        with patch("sna.integrations.teams.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            success = await notifier.send_escalation(result)

        assert success is False

    async def test_send_connection_error_returns_false(self) -> None:
        """Connection failure should return False."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()

        with patch("sna.integrations.teams.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            success = await notifier.send_escalation(result)

        assert success is False

    def test_card_contains_tool_name(self) -> None:
        """Adaptive Card facts should include the tool name."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()
        card = notifier._build_card(result, COLOR_ESCALATE, "Test")

        facts = card["attachments"][0]["content"]["body"][1]["facts"]
        tool_fact = next(f for f in facts if f["title"] == "Tool")
        assert tool_fact["value"] == "configure_interface"

    def test_card_contains_confidence(self) -> None:
        """Adaptive Card facts should include confidence values."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()
        card = notifier._build_card(result, COLOR_ESCALATE, "Test")

        facts = card["attachments"][0]["content"]["body"][1]["facts"]
        conf_fact = next(f for f in facts if f["title"] == "Confidence")
        assert "0.50" in conf_fact["value"]
        assert "0.80" in conf_fact["value"]

    def test_card_senior_approval_fact(self) -> None:
        """Senior approval should appear as a fact when True."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(senior=True)
        card = notifier._build_card(result, COLOR_ESCALATE, "Test")

        facts = card["attachments"][0]["content"]["body"][1]["facts"]
        fact_titles = [f["title"] for f in facts]
        assert "Senior Approval" in fact_titles

    def test_card_no_senior_approval_fact(self) -> None:
        """Senior approval should NOT appear when False."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(senior=False)
        card = notifier._build_card(result, COLOR_ESCALATE, "Test")

        facts = card["attachments"][0]["content"]["body"][1]["facts"]
        fact_titles = [f["title"] for f in facts]
        assert "Senior Approval" not in fact_titles

    def test_card_escalation_id_fact(self) -> None:
        """Escalation ID should appear when present."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(Verdict.ESCALATE)
        card = notifier._build_card(result, COLOR_ESCALATE, "Test")

        facts = card["attachments"][0]["content"]["body"][1]["facts"]
        fact_titles = [f["title"] for f in facts]
        assert "Escalation ID" in fact_titles

    def test_card_no_escalation_id_for_block(self) -> None:
        """Block verdicts should not have an Escalation ID fact."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result(Verdict.BLOCK)
        card = notifier._build_card(result, COLOR_BLOCK, "Test")

        facts = card["attachments"][0]["content"]["body"][1]["facts"]
        fact_titles = [f["title"] for f in facts]
        assert "Escalation ID" not in fact_titles

    def test_card_schema_structure(self) -> None:
        """Card should have correct Adaptive Card schema structure."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL)
        result = _make_result()
        card = notifier._build_card(result, COLOR_ESCALATE, "Test")

        assert card["type"] == "message"
        attachment = card["attachments"][0]
        assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
        content = attachment["content"]
        assert content["type"] == "AdaptiveCard"
        assert content["version"] == "1.4"
        assert "$schema" in content

    async def test_timeout_passed_to_client(self) -> None:
        """Custom timeout should be passed to httpx client."""
        notifier = TeamsNotifier(webhook_url=WEBHOOK_URL, timeout=5.0)
        result = _make_result()

        mock_response = httpx.Response(200, request=_MOCK_REQUEST)
        with patch("sna.integrations.teams.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await notifier.send_escalation(result)

        mock_client_cls.assert_called_once_with(timeout=5.0)
