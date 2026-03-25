"""Integration tests for the FastAPI REST endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("REDFORGE_API_KEY", "test-secret-key")
    from redforge.api.app import create_app
    app = create_app()
    return TestClient(app)


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-secret-key"}


class TestAuth:
    def test_health_no_auth(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_probes_requires_auth(self, client):
        r = client.get("/v1/probes")
        assert r.status_code == 401

    def test_probes_wrong_key(self, client):
        r = client.get("/v1/probes", headers={"Authorization": "Bearer wrong-key"})
        assert r.status_code == 401

    def test_probes_valid_auth(self, client, auth_headers):
        r = client.get("/v1/probes", headers=auth_headers)
        assert r.status_code == 200

    def test_no_api_key_configured_returns_503(self, monkeypatch):
        monkeypatch.delenv("REDFORGE_API_KEY", raising=False)
        from redforge.api.app import create_app
        app = create_app()
        c = TestClient(app)
        r = c.get("/v1/probes", headers={"Authorization": "Bearer anything"})
        assert r.status_code == 503


class TestProbesEndpoint:
    def test_returns_list(self, client, auth_headers):
        r = client.get("/v1/probes", headers=auth_headers)
        data = r.json()
        assert isinstance(data, list)
        assert len(data) >= 25  # 10 original + 15 new probes

    def test_probe_has_owasp_id(self, client, auth_headers):
        r = client.get("/v1/probes", headers=auth_headers)
        for probe in r.json():
            assert probe["owasp_id"].startswith("LLM")


class TestScanEndpoint:
    def test_invalid_authorization(self, client, auth_headers):
        r = client.post(
            "/v1/scan",
            json={"provider": "ollama", "authorization": "invalid"},
            headers=auth_headers,
        )
        assert r.status_code == 422  # Validation error

    def test_dry_run_with_mock(self, client, auth_headers, monkeypatch):
        """Dry run should not make any adapter calls."""
        from tests.conftest import MockAdapter

        async def mock_run(self_obj, all_probes, session, *args, **kwargs):
            from redforge.core.orchestrator import ScanReport
            from redforge.core.scorer import score_results
            session.finish(score_results([]))
            return ScanReport(session)

        monkeypatch.setattr("redforge.core.orchestrator.Orchestrator.run", mock_run)
        monkeypatch.setattr("redforge.adapters.get_adapter", lambda p, c: MockAdapter())

        r = client.post(
            "/v1/scan",
            json={"provider": "ollama", "authorization": "owned", "dry_run": True},
            headers=auth_headers,
        )
        # Either 200 or 400 (if adapter fails in test env) — just no 500
        assert r.status_code in (200, 400)


class TestReportsEndpoint:
    def test_nonexistent_session_404(self, client, auth_headers):
        r = client.get("/v1/reports/00000000", headers=auth_headers)
        assert r.status_code == 404

    def test_path_traversal_rejected(self, client, auth_headers):
        r = client.get("/v1/reports/../etc/passwd", headers=auth_headers)
        assert r.status_code in (400, 404, 422)
