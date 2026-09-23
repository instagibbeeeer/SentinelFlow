from conftest import load_module

agent = load_module("sentinelflow_agent", "agent/agent.py")


def fake_gql(query, variables):
    if "eventsByUser" in query:
        return {"eventsByUser": [
            {"eventType": "LOGIN_FAILED", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 0},
            {"eventType": "LOGIN_SUCCESS", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 0},
            {"eventType": "PRIVILEGE_CHANGE", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 0},
            {"eventType": "FILE_DOWNLOAD", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 2_000_000_000},
        ] + [
            {"eventType": "LOGIN_FAILED", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 0}
            for _ in range(7)
        ]}
    if "eventsByIp" in query:
        return {"eventsByIp": [
            {"userId": "victim"},
            {"userId": "other-user"},
        ]}
    if "eventsByDevice" in query:
        return {"eventsByDevice": [{"userId": "victim", "deviceId": variables["d"]}]}
    raise AssertionError("unexpected query")


def test_collect_evidence_pivots_user_to_ip_and_device():
    evidence = agent.collect_evidence({"user_id": "victim"}, gql_fn=fake_gql)
    assert len(evidence["user_events"]) == 11
    assert {e["userId"] for e in evidence["ip_events"]} == {"victim", "other-user"}
    assert evidence["device_events"][0]["deviceId"] == "laptop-1"


def test_deterministic_reason_combines_signals():
    evidence = agent.collect_evidence({"user_id": "victim"}, gql_fn=fake_gql)
    result = agent.deterministic_reason({"user_id": "victim", "risk_score": .95}, evidence)
    assert result["severity"] == "CRITICAL"
    assert result["confidence"] > .8
    assert "8 failed logins" in result["evidence"]
    assert "privilege escalation" in result["evidence"]
    assert "2.0 GB downloaded" in result["evidence"]
    assert "source IP touched 2 users" in result["evidence"]
    assert result["agent_mode"] == "deterministic-tools"


def test_llm_reason_uses_deterministic_fallback_without_key(monkeypatch):
    monkeypatch.setattr(agent, "OPENAI_API_KEY", "")
    fallback = {"severity": "HIGH"}
    assert agent.llm_reason({}, {}, fallback) is fallback


def test_investigate_builds_incident(monkeypatch):
    monkeypatch.setattr(agent, "OPENAI_API_KEY", "")
    incident = agent.investigate({"user_id": "victim", "risk_score": .95}, gql_fn=fake_gql)
    assert incident["incident_id"]
    assert incident["created_at"].endswith("+00:00")
    assert incident["user_id"] == "victim"
    assert incident["severity"] == "CRITICAL"
