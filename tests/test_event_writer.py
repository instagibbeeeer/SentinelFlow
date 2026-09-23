import json
from datetime import timezone
from conftest import load_module

writer = load_module("sentinelflow_writer", "event-writer/writer.py")


class Future:
    def __init__(self):
        self.awaited = False

    def result(self):
        self.awaited = True
        return None


class FakeDB:
    def __init__(self):
        self.prepared = []
        self.async_calls = []
        self.sync_calls = []

    def prepare(self, query):
        name = query.split("INSERT INTO ", 1)[1].splitlines()[0].strip()
        self.prepared.append(name)
        return name

    def execute_async(self, query, values):
        future = Future()
        self.async_calls.append((query, values, future))
        return future

    def execute(self, query, values):
        self.sync_calls.append((query, values))


def sample_event():
    return {
        "event_id": "d65a5c79-6e65-45bf-a624-f27bc5536f4f",
        "timestamp": "2026-09-22T12:34:56Z",
        "user_id": "alice",
        "device_id": "laptop-1",
        "event_type": "LOGIN_FAILED",
        "ip": "10.0.0.8",
        "country": "DE",
        "bytes": 0,
        "metadata": {"method": "password"},
    }


def test_dt_accepts_zulu_time():
    parsed = writer.dt("2026-09-22T12:34:56Z")
    assert parsed.tzinfo == timezone.utc


def test_event_is_denormalized_to_user_ip_and_device_tables():
    db = FakeDB()
    p = writer.Persister(db)
    p.persist_event(sample_event())
    assert [q for q, _, _ in db.async_calls] == [
        "events_by_user_day", "events_by_ip_day", "events_by_device_day"
    ]
    assert all(f.awaited for _, _, f in db.async_calls)
    user_values = db.async_calls[0][1]
    assert user_values[0] == "alice"
    assert json.loads(user_values[-1]) == {"method": "password"}


def test_alert_persistence_converts_ids_numbers_and_times():
    db = FakeDB()
    p = writer.Persister(db)
    p.persist_alert({
        "user_id": "alice",
        "alert_time": "2026-09-22T12:35:00Z",
        "alert_id": "d65a5c79-6e65-45bf-a624-f27bc5536f4f",
        "risk_score": "0.91",
        "reason": "failed logins",
        "window_start": "2026-09-22T12:34:30Z",
        "window_end": "2026-09-22T12:35:00Z",
    })
    query, values = db.sync_calls[0]
    assert query == "alerts_by_user"
    assert values[0] == "alice"
    assert values[3] == .91


def test_incident_is_written_to_both_investigation_views():
    db = FakeDB()
    p = writer.Persister(db)
    p.persist_incident({
        "incident_id": "d65a5c79-6e65-45bf-a624-f27bc5536f4f",
        "user_id": "alice",
        "created_at": "2026-09-22T12:36:00Z",
        "severity": "HIGH",
        "confidence": .82,
        "conclusion": "suspicious",
        "evidence": ["signal"],
        "recommended_actions": ["review"],
        "agent_mode": "deterministic-tools",
    })
    assert [q for q, _, _ in db.async_calls] == ["investigations_by_incident", "investigations_by_user"]
    assert all(f.awaited for _, _, f in db.async_calls)
