from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID
from fastapi.testclient import TestClient
from conftest import load_module

api = load_module("sentinelflow_api", "api/app.py")


class FakeDB:
    def __init__(self):
        self.calls = []

    def execute(self, query, values):
        self.calls.append((query, values))
        if "events_by_user_day" in query:
            return [SimpleNamespace(
                event_id=UUID("d65a5c79-6e65-45bf-a624-f27bc5536f4f"),
                event_time=datetime(2026, 9, 22, 12, 34, tzinfo=timezone.utc),
                user_id="alice", device_id="laptop-1", event_type="LOGIN_FAILED",
                ip="10.0.0.8", country="DE", bytes=0, metadata="{}",
            )]
        if "investigations_by_user" in query:
            return [SimpleNamespace(
                incident_id=UUID("8a6b7070-25f9-4d4b-93b5-29a42554eb53"),
                created_at=datetime(2026, 9, 22, 12, 35, tzinfo=timezone.utc),
                user_id="alice", severity="HIGH", confidence=.8,
                conclusion="suspicious", evidence='["signal"]',
                recommended_actions='["review"]', agent_mode="deterministic-tools",
            )]
        if "agent_tool_calls_by_incident" in query:
            return [SimpleNamespace(
                call_id=UUID("d65a5c79-6e65-45bf-a624-f27bc5536f4f"),
                started_at=datetime(2026, 9, 22, 12, 34, tzinfo=timezone.utc),
                completed_at=datetime(2026, 9, 22, 12, 34, 0, 10000, tzinfo=timezone.utc),
                tool_name="get_user_activity", duration_ms=10, status="success",
                input_json='{"user_id":"alice"}',
                result_summary='{"type":"list","count":12}', error=None,
            )]
        return []


def test_rest_health_does_not_require_database(monkeypatch):
    client = TestClient(api.app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_graphql_queries_cassandra_and_caps_limit(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(api, "_db", fake)
    client = TestClient(api.app)
    query = '''query($u:String!,$incident:String!){
      eventsByUser(userId:$u, limit:999){ eventId eventType userId ip }
      investigationsByUser(userId:$u, limit:999){ incidentId severity confidence agentMode }
      toolCallsByIncident(incidentId:$incident, limit:999){ callId toolName status durationMs }
    }'''
    response = client.post("/graphql", json={"query": query, "variables": {
        "u": "alice",
        "incident": "8a6b7070-25f9-4d4b-93b5-29a42554eb53",
    }})
    assert response.status_code == 200
    body = response.json()
    assert "errors" not in body
    assert body["data"]["eventsByUser"][0]["eventType"] == "LOGIN_FAILED"
    assert body["data"]["investigationsByUser"][0]["severity"] == "HIGH"
    assert body["data"]["toolCallsByIncident"][0]["toolName"] == "get_user_activity"
    assert fake.calls[0][1][-1] == 500
    assert fake.calls[1][1][-1] == 100
    assert fake.calls[2][1][-1] == 500
