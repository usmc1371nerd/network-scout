from pathlib import Path

from app import FRONTEND_DIST_DIR, MAX_DEVICES, app


def test_frontend_distribution_resolves_from_unified_repository():
    repository = Path(__file__).resolve().parents[2]
    assert FRONTEND_DIST_DIR == repository / "frontend" / "dist"


def test_command_api_rejects_non_object_json():
    client = app.test_client()
    response = client.post("/api/run-command", json=[])
    assert response.status_code == 400


def test_command_api_rejects_excessive_topology():
    client = app.test_client()
    response = client.post(
        "/api/run-command",
        json={"command": "help", "devices": [{}] * (MAX_DEVICES + 1), "connections": []},
    )
    assert response.status_code == 413


def test_command_api_allows_documented_development_origin_only():
    client = app.test_client()
    allowed = client.post(
        "/api/run-command",
        json={"command": "help", "devices": [], "connections": []},
        headers={"Origin": "http://127.0.0.1:3000"},
    )
    denied = client.post(
        "/api/run-command",
        json={"command": "help", "devices": [], "connections": []},
        headers={"Origin": "https://attacker.example"},
    )
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:3000"
    assert "Access-Control-Allow-Origin" not in denied.headers
