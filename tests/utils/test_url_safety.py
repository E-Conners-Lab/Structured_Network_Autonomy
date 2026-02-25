"""Tests for SSRF protection URL validation."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sna.utils.url_safety import validate_webhook_url


class TestValidateWebhookUrl:
    """SSRF protection tests."""

    def test_valid_https_url(self) -> None:
        """Valid HTTPS URLs should pass validation."""
        # Mock DNS resolution to return a public IP
        with patch("sna.utils.url_safety.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("104.18.0.1", 443)),
            ]
            validate_webhook_url("https://hooks.slack.com/services/xxx")

    def test_rejects_http(self) -> None:
        """HTTP URLs should be rejected."""
        with pytest.raises(ValueError, match="HTTPS"):
            validate_webhook_url("http://hooks.slack.com/services/xxx")

    def test_rejects_private_ip(self) -> None:
        """URLs resolving to RFC-1918 addresses should be rejected."""
        with patch("sna.utils.url_safety.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("10.0.0.1", 443)),
            ]
            with pytest.raises(ValueError, match="blocked address"):
                validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_loopback(self) -> None:
        """URLs resolving to loopback should be rejected."""
        with patch("sna.utils.url_safety.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("127.0.0.1", 443)),
            ]
            with pytest.raises(ValueError, match="blocked address"):
                validate_webhook_url("https://127.0.0.1/webhook")

    def test_rejects_link_local(self) -> None:
        """URLs resolving to link-local/metadata should be rejected."""
        with patch("sna.utils.url_safety.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("169.254.169.254", 443)),
            ]
            with pytest.raises(ValueError, match="blocked address"):
                validate_webhook_url("https://169.254.169.254/latest")

    def test_rejects_ipv6_loopback(self) -> None:
        """URLs resolving to IPv6 loopback should be rejected."""
        with patch("sna.utils.url_safety.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (10, 1, 6, "", ("::1", 443, 0, 0)),
            ]
            with pytest.raises(ValueError, match="blocked address"):
                validate_webhook_url("https://[::1]/webhook")
