"""Tests for PagerDuty Events API v2 notification integration."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from sna.integrations.pagerduty import PagerDutyNotifier
from sna.policy.models import EvaluationResult, RiskTier, Verdict


def _make_result(verdict: Verdict = Verdict.BLOCK, reason: str = "Test reason") -> EvaluationResult:
    return EvaluationResult(
        verdict=verdict,
        risk_tier=RiskTier.TIER_4_HIGH_RISK_WRITE,
        tool_name="configure_bgp_neighbor",
        reason=reason,
        confidence_score=0.4,
        confidence_threshold=0.9,
        device_count=3,
    )


@pytest.fixture
def pd_notifier():
    """Create a PagerDutyNotifier."""
    return PagerDutyNotifier(
        routing_key="test-routing-key-12345",
        api_url="https://events.pagerduty.com/v2/enqueue",
        timeout=5.0,
    )


class TestPagerDutyNotifier:
    """PagerDuty notification tests."""

    async def test_send_block_creates_critical_incident(
        self, pd_notifier: PagerDutyNotifier
    ) -> None:
        """BLOCK verdict creates a critical severity event."""
        mock_response = AsyncMock()
        mock_response.status_code = 202
        mock_response.raise_for_status = lambda: None

        with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
            result = await pd_notifier.send_block(_make_result())
            assert result is True

            payload = mock_post.call_args[1]["json"]
            assert payload["payload"]["severity"] == "critical"
            assert payload["event_action"] == "trigger"
            assert "BLOCKED" in payload["payload"]["summary"]

    async def test_send_escalation_creates_warning(
        self, pd_notifier: PagerDutyNotifier
    ) -> None:
        """ESCALATE verdict creates a warning severity event."""
        mock_response = AsyncMock()
        mock_response.status_code = 202
        mock_response.raise_for_status = lambda: None

        with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
            result = await pd_notifier.send_escalation(
                _make_result(verdict=Verdict.ESCALATE)
            )
            assert result is True

            payload = mock_post.call_args[1]["json"]
            assert payload["payload"]["severity"] == "warning"
            assert "ESCALATION" in payload["payload"]["summary"]

    async def test_dedup_key_deterministic(
        self, pd_notifier: PagerDutyNotifier
    ) -> None:
        """Same inputs produce the same dedup key."""
        result = _make_result()
        key1 = pd_notifier._compute_dedup_key(result)
        key2 = pd_notifier._compute_dedup_key(result)
        assert key1 == key2
        assert len(key1) == 32

    async def test_dedup_key_different_minutes(
        self, pd_notifier: PagerDutyNotifier
    ) -> None:
        """Different timestamp minutes produce different keys."""
        from unittest.mock import patch as sync_patch
        from datetime import datetime, timezone

        result = _make_result()

        with sync_patch("sna.integrations.pagerduty.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 2, 25, 10, 0, tzinfo=timezone.utc)
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            key1 = pd_notifier._compute_dedup_key(result)

        with sync_patch("sna.integrations.pagerduty.datetime") as mock_dt:
            mock_dt.now.return_value = datetime(2026, 2, 25, 10, 1, tzinfo=timezone.utc)
            mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
            key2 = pd_notifier._compute_dedup_key(result)

        assert key1 != key2

    async def test_send_failure_returns_false(
        self, pd_notifier: PagerDutyNotifier
    ) -> None:
        """HTTP errors should return False, not crash."""
        with patch(
            "httpx.AsyncClient.post",
            side_effect=httpx.RequestError("Connection refused"),
        ):
            result = await pd_notifier.send_block(_make_result())
            assert result is False

    async def test_payload_structure(
        self, pd_notifier: PagerDutyNotifier
    ) -> None:
        """Verify PagerDuty Events API v2 payload format."""
        mock_response = AsyncMock()
        mock_response.status_code = 202
        mock_response.raise_for_status = lambda: None

        with patch("httpx.AsyncClient.post", return_value=mock_response) as mock_post:
            await pd_notifier.send_block(_make_result())
            payload = mock_post.call_args[1]["json"]

            # Required top-level fields
            assert "routing_key" in payload
            assert "event_action" in payload
            assert "dedup_key" in payload
            assert "payload" in payload

            # Required payload fields
            pd_payload = payload["payload"]
            assert "summary" in pd_payload
            assert "source" in pd_payload
            assert pd_payload["source"] == "sna"
            assert "severity" in pd_payload
            assert "component" in pd_payload
            assert "custom_details" in pd_payload

    async def test_routing_key_not_logged(
        self, pd_notifier: PagerDutyNotifier
    ) -> None:
        """Routing key should not appear in log output."""
        import io
        import logging

        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(handler)

        mock_response = AsyncMock()
        mock_response.status_code = 202
        mock_response.raise_for_status = lambda: None

        with patch("httpx.AsyncClient.post", return_value=mock_response):
            await pd_notifier.send_block(_make_result())

        logging.getLogger().removeHandler(handler)
        log_output = log_stream.getvalue()
        assert "test-routing-key-12345" not in log_output
