"""Integration tests for the Typer CLI commands."""

from __future__ import annotations

from typer.testing import CliRunner

from redforge.cli.commands import app

runner = CliRunner()


class TestListProbesCommand:
    def test_list_probes_exits_zero(self):
        result = runner.invoke(app, ["list-probes"])
        assert result.exit_code == 0

    def test_list_probes_shows_owasp_ids(self):
        result = runner.invoke(app, ["list-probes"])
        for i in range(1, 11):
            owasp = f"LLM{i:02d}" if i < 10 else "LLM10"
            assert owasp in result.output or f"LLM0{i}" in result.output

    def test_list_probes_shows_ten_probes(self):
        result = runner.invoke(app, ["list-probes"])
        assert "10" in result.output


class TestScanCommand:
    def test_scan_requires_authorization(self):
        result = runner.invoke(app, ["scan", "--provider", "ollama"])
        assert result.exit_code != 0

    def test_scan_invalid_authorization(self):
        result = runner.invoke(
            app,
            ["scan", "--provider", "ollama", "--authorization", "hacker"]
        )
        assert result.exit_code != 0

    def test_scan_dry_run_exits_zero(self, monkeypatch):
        """Dry run with a mock adapter should exit 0 (no live API calls)."""
        import sys
        sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))
        from tests.conftest import MockAdapter
        monkeypatch.setattr("redforge.adapters.get_adapter", lambda p, c: MockAdapter())

        result = runner.invoke(
            app,
            ["scan", "--provider", "ollama", "--authorization", "owned", "--dry-run", "--no-store"],
        )
        # Dry run produces no findings → exit 0
        assert result.exit_code == 0, f"Got: {result.output}\n{result.exception}"


class TestServeCommand:
    def test_serve_help(self):
        result = runner.invoke(app, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--port" in result.output


class TestBannerContent:
    def test_authorization_warning_present(self):
        result = runner.invoke(app, ["list-probes"])
        assert "authorized" in result.output.lower() or "permission" in result.output.lower()
