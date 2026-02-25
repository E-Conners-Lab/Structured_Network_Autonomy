"""Tests for CLI entrypoint."""

from __future__ import annotations

from typer.testing import CliRunner

from sna.cli import app

runner = CliRunner()


class TestCLI:
    """CLI command tests."""

    def test_cli_help(self) -> None:
        """CLI should display help text."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Structured Network Autonomy" in result.stdout

    def test_serve_help(self) -> None:
        result = runner.invoke(app, ["serve", "--help"])
        assert result.exit_code == 0
        assert "host" in result.stdout
        assert "port" in result.stdout

    def test_evaluate_help(self) -> None:
        result = runner.invoke(app, ["evaluate", "--help"])
        assert result.exit_code == 0
        assert "tool-name" in result.stdout.lower() or "TOOL_NAME" in result.stdout

    def test_migrate_help(self) -> None:
        result = runner.invoke(app, ["migrate", "--help"])
        assert result.exit_code == 0
        assert "revision" in result.stdout

    def test_mcp_serve_help(self) -> None:
        result = runner.invoke(app, ["mcp-serve", "--help"])
        assert result.exit_code == 0
