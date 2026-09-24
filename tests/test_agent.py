from conftest import load_module

agent_tools_module = load_module("agent_tools", "agent/agent_tools.py")
agent = load_module("sentinelflow_agent", "agent/agent.py")


class FakeTools:
    def __init__(self):
        self.incident_id = None
        self.calls = []
        self.trace = []

    def set_incident_id(self, incident_id):
        self.incident_id = incident_id

    def _record(self, name):
        self.calls.append(name)
        self.trace.append({
            "call_id": "d65a5c79-6e65-45bf-a624-f27bc5536f4f",
            "tool_name": name,
            "incident_id": self.incident_id,
            "started_at": "2026-09-24T07:00:00+00:00",
            "completed_at": "2026-09-24T07:00:00.001000+00:00",
            "duration_ms": 1,
            "status": "success",
            "input": {},
            "result_summary": {"type": "list", "count": 1},
            "error": None,
        })

    def get_alert_context(self, alert):
        self._record("get_alert_context")
        return dict(alert)

    def get_user_activity(self, user_id, limit=100):
        self._record("get_user_activity")
        return [
            {"eventType": "LOGIN_FAILED", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 0},
            {"eventType": "LOGIN_SUCCESS", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 0},
            {"eventType": "PRIVILEGE_CHANGE", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 0},
            {"eventType": "FILE_DOWNLOAD", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 2_000_000_000},
        ] + [
            {"eventType": "LOGIN_FAILED", "ip": "9.9.9.9", "deviceId": "laptop-1", "bytes": 0}
            for _ in range(7)
        ]

    def get_ip_activity(self, ip, limit=100):
        self._record("get_ip_activity")
        return [{"userId": "victim"}, {"userId": "other-user"}]

    def get_device_activity(self, device_id, limit=100):
        self._record("get_device_activity")
        return [{"userId": "victim", "deviceId": device_id}]

    def get_previous_incidents(self, user_id, limit=10):
        self._record("get_previous_incidents")
        return []

    def snapshot_trace(self):
        return list(self.trace)


def test_collect_evidence_uses_named_tools_in_investigation_order():
    tools = FakeTools()
    evidence = agent.collect_evidence({"user_id": "victim", "risk_score": .95}, tools)
    assert len(evidence["user_events"]) == 11
    assert {event["userId"] for event in evidence["ip_events"]} == {"victim", "other-user"}
    assert evidence["device_events"][0]["deviceId"] == "laptop-1"
    assert tools.calls == [
        "get_alert_context",
        "get_user_activity",
        "get_ip_activity",
        "get_device_activity",
        "get_previous_incidents",
    ]


def test_deterministic_reason_combines_signals():
    evidence = agent.collect_evidence({"user_id": "victim", "risk_score": .95}, FakeTools())
    result = agent.deterministic_reason({"user_id": "victim", "risk_score": .95}, evidence)
    assert result["severity"] == "CRITICAL"
    assert result["confidence"] > .8
    assert "8 failed logins" in result["evidence"]
    assert "privilege escalation" in result["evidence"]
    assert "2.0 GB downloaded" in result["evidence"]
    assert "source IP touched 2 users" in result["evidence"]
    assert result["agent_mode"] == "deterministic-tools"


def test_previous_investigation_becomes_a_reasoning_signal():
    tools = FakeTools()
    original = tools.get_previous_incidents

    def prior(user_id, limit=10):
        original(user_id, limit)
        return [{"incidentId": "old"}]

    tools.get_previous_incidents = prior
    evidence = agent.collect_evidence({"user_id": "victim", "risk_score": .8}, tools)
    result = agent.deterministic_reason({"user_id": "victim", "risk_score": .8}, evidence)
    assert "1 previous investigations for user" in result["evidence"]


def test_llm_reason_uses_deterministic_fallback_without_key(monkeypatch):
    monkeypatch.setattr(agent, "OPENAI_API_KEY", "")
    fallback = {"severity": "HIGH"}
    assert agent.llm_reason({}, {}, fallback) is fallback


def test_investigate_builds_incident_and_attaches_tool_trace(monkeypatch):
    monkeypatch.setattr(agent, "OPENAI_API_KEY", "")
    tools = FakeTools()
    incident = agent.investigate({"user_id": "victim", "risk_score": .95}, tools=tools)
    assert incident["incident_id"]
    assert incident["created_at"].endswith("+00:00")
    assert incident["user_id"] == "victim"
    assert incident["severity"] == "CRITICAL"
    assert len(incident["tool_trace"]) == 5
    assert all(call["incident_id"] == incident["incident_id"] for call in incident["tool_trace"])
