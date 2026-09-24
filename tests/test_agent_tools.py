from conftest import load_module

agent_tools = load_module("sentinelflow_agent_tools", "agent/agent_tools.py")


class FakeClient:
    def __init__(self):
        self.calls = []

    def execute(self, query, variables):
        self.calls.append((query, variables))
        if "eventsByUser" in query:
            return {"eventsByUser": [{"eventType": "LOGIN_FAILED"}]}
        if "eventsByIp" in query:
            return {"eventsByIp": [{"userId": "alice"}]}
        if "eventsByDevice" in query:
            return {"eventsByDevice": [{"deviceId": "laptop-1"}]}
        if "investigationsByUser" in query:
            return {"investigationsByUser": [{"incidentId": "old-incident"}]}
        raise AssertionError("unexpected query")


class BrokenClient:
    def execute(self, query, variables):
        raise RuntimeError("graphql unavailable")


def test_explicit_tools_hide_graphql_queries_and_record_success_trace():
    client = FakeClient()
    tools = agent_tools.AgentTools("http://unused/graphql", client=client, incident_id="inc-1")

    assert tools.get_user_activity("alice") == [{"eventType": "LOGIN_FAILED"}]
    assert tools.get_ip_activity("10.0.0.8") == [{"userId": "alice"}]
    assert tools.get_device_activity("laptop-1") == [{"deviceId": "laptop-1"}]
    assert tools.get_previous_incidents("alice") == [{"incidentId": "old-incident"}]

    trace = tools.snapshot_trace()
    assert [entry["tool_name"] for entry in trace] == [
        "get_user_activity",
        "get_ip_activity",
        "get_device_activity",
        "get_previous_incidents",
    ]
    assert all(entry["incident_id"] == "inc-1" for entry in trace)
    assert all(entry["status"] == "success" for entry in trace)
    assert all(entry["call_id"] for entry in trace)
    assert all(entry["completed_at"] for entry in trace)
    assert trace[0]["result_summary"]["count"] == 1


def test_alert_context_is_also_an_audited_tool_call():
    tools = agent_tools.AgentTools("http://unused/graphql", client=FakeClient(), incident_id="inc-1")
    result = tools.get_alert_context({
        "alert_id": "a-1",
        "user_id": "alice",
        "risk_score": .9,
        "reason": "failed logins",
        "secret_extra_field": "must not be copied",
    })
    assert result["alert_id"] == "a-1"
    assert "secret_extra_field" not in result
    assert tools.trace[0]["tool_name"] == "get_alert_context"
    assert tools.trace[0]["status"] == "success"


def test_failed_tool_call_is_audited_before_error_is_reraised():
    tools = agent_tools.AgentTools("http://unused/graphql", client=BrokenClient(), incident_id="inc-2")
    try:
        tools.get_user_activity("alice")
    except RuntimeError as exc:
        assert "graphql unavailable" in str(exc)
    else:
        raise AssertionError("tool call should have failed")

    trace = tools.snapshot_trace()
    assert len(trace) == 1
    assert trace[0]["status"] == "error"
    assert trace[0]["error"] == "graphql unavailable"
