"""Tests for dashboard static file serving and CSP headers."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from sna.api.app import create_app
from sna.config import Settings


@pytest.fixture
def dashboard_dir(tmp_path: Path) -> Path:
    """Create a fake dashboard build directory."""
    dist = tmp_path / "dashboard" / "dist"
    dist.mkdir(parents=True)
    (dist / "index.html").write_text("<!DOCTYPE html><html><body>SNA Dashboard</body></html>")
    assets = dist / "assets"
    assets.mkdir()
    (assets / "main.js").write_text("console.log('hello');")
    return dist


def _make_client(settings: Settings) -> AsyncClient:
    """Create an AsyncClient for a given Settings."""
    app = create_app(settings)
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


class TestDashboardServing:
    """Dashboard static file serving."""

    async def test_dashboard_index(self, dashboard_dir: Path) -> None:
        """GET /dashboard/ serves index.html."""
        settings = Settings(
            sna_api_key="a" * 32,
            sna_admin_api_key="b" * 32,
            dashboard_enabled=True,
            dashboard_static_path=str(dashboard_dir),
        )
        async with _make_client(settings) as client:
            response = await client.get("/dashboard/")
            assert response.status_code == 200
            assert "SNA Dashboard" in response.text

    async def test_dashboard_spa_fallback(self, dashboard_dir: Path) -> None:
        """SPA routes (no extension) serve index.html."""
        settings = Settings(
            sna_api_key="a" * 32,
            sna_admin_api_key="b" * 32,
            dashboard_enabled=True,
            dashboard_static_path=str(dashboard_dir),
        )
        async with _make_client(settings) as client:
            response = await client.get("/dashboard/escalations")
            assert response.status_code == 200
            assert "SNA Dashboard" in response.text

    async def test_dashboard_path_traversal_blocked(self, dashboard_dir: Path) -> None:
        """Path traversal attempts are blocked."""
        settings = Settings(
            sna_api_key="a" * 32,
            sna_admin_api_key="b" * 32,
            dashboard_enabled=True,
            dashboard_static_path=str(dashboard_dir),
        )
        async with _make_client(settings) as client:
            response = await client.get("/dashboard/../../etc/passwd")
            assert response.status_code in (400, 404)

    async def test_csp_headers_on_dashboard(self, dashboard_dir: Path) -> None:
        """Dashboard responses include CSP headers."""
        settings = Settings(
            sna_api_key="a" * 32,
            sna_admin_api_key="b" * 32,
            dashboard_enabled=True,
            dashboard_static_path=str(dashboard_dir),
        )
        async with _make_client(settings) as client:
            response = await client.get("/dashboard/")
            csp = response.headers.get("content-security-policy", "")
            assert "default-src 'self'" in csp
            assert "script-src 'self'" in csp

    async def test_dashboard_disabled(self) -> None:
        """When dashboard_enabled=False, /dashboard returns 404."""
        settings = Settings(
            sna_api_key="a" * 32,
            sna_admin_api_key="b" * 32,
            dashboard_enabled=False,
        )
        async with _make_client(settings) as client:
            response = await client.get("/dashboard/")
            assert response.status_code == 404

    async def test_dashboard_missing_dir(self) -> None:
        """When dashboard dir doesn't exist, no crash at startup."""
        settings = Settings(
            sna_api_key="a" * 32,
            sna_admin_api_key="b" * 32,
            dashboard_enabled=True,
            dashboard_static_path="/nonexistent/path",
        )
        app = create_app(settings)
        assert app is not None

    async def test_dashboard_nonexistent_file(self, dashboard_dir: Path) -> None:
        """Requesting a nonexistent file returns 404."""
        settings = Settings(
            sna_api_key="a" * 32,
            sna_admin_api_key="b" * 32,
            dashboard_enabled=True,
            dashboard_static_path=str(dashboard_dir),
        )
        async with _make_client(settings) as client:
            response = await client.get("/dashboard/nonexistent.js")
            assert response.status_code == 404
