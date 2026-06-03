from fastapi.testclient import TestClient

import src.api.routes as routes_module
from src.main import app


def test_forensics_routes_require_api_key_when_configured(monkeypatch):
    monkeypatch.setattr(routes_module, "API_KEY", "test-secret")
    client = TestClient(app)

    assert client.get("/forensics/999999").status_code == 401
    assert client.post("/mitigate/999999").status_code == 401


def test_forensics_routes_accept_valid_api_key(monkeypatch):
    monkeypatch.setattr(routes_module, "API_KEY", "test-secret")
    client = TestClient(app)

    response = client.get("/forensics/999999", headers={"X-API-Key": "test-secret"})

    assert response.status_code == 404
