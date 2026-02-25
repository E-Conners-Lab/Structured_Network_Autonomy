"""Tests for config.py — API key minimum length enforcement."""

from __future__ import annotations

import pytest

from sna.config import Settings


class TestApiKeyMinLength:
    """API keys must be at least 32 characters."""

    def test_short_api_key_rejected(self) -> None:
        """Key of length 10 should raise ValueError."""
        with pytest.raises(Exception, match="at least 32 characters"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                sna_api_key="short-key!",
                sna_admin_api_key="a" * 32,
            )

    def test_short_admin_key_rejected(self) -> None:
        """Short admin key should also be rejected."""
        with pytest.raises(Exception, match="at least 32 characters"):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                sna_api_key="a" * 32,
                sna_admin_api_key="short",
            )

    def test_valid_api_key_accepted(self) -> None:
        """Key of length 32+ should be accepted."""
        s = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            sna_api_key="a" * 32,
            sna_admin_api_key="b" * 32,
        )
        assert len(s.sna_api_key) == 32
        assert len(s.sna_admin_api_key) == 32

    def test_exactly_32_chars_accepted(self) -> None:
        """Exactly 32 characters should be accepted."""
        key = "abcdefghijklmnopqrstuvwxyz123456"
        assert len(key) == 32
        s = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            sna_api_key=key,
            sna_admin_api_key=key,
        )
        assert s.sna_api_key == key
