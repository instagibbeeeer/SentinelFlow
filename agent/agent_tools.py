import json
import time
import uuid
from datetime import datetime, timezone

import requests


USER_ACTIVITY_QUERY = '''query($u:String!,$limit:Int!){
  eventsByUser(userId:$u,limit:$limit){eventId eventTime eventType ip deviceId country bytes metadata}
}'''
IP_ACTIVITY_QUERY = '''query($ip:String!,$limit:Int!){
  eventsByIp(ip:$ip,limit:$limit){eventId eventTime eventType userId deviceId country bytes metadata}
}'''
DEVICE_ACTIVITY_QUERY = '''query($d:String!,$limit:Int!){
  eventsByDevice(deviceId:$d,limit:$limit){eventId eventTime eventType userId ip country bytes metadata}
}'''
PREVIOUS_INCIDENTS_QUERY = '''query($u:String!,$limit:Int!){
  investigationsByUser(userId:$u,limit:$limit){incidentId createdAt severity confidence conclusion evidence recommendedActions agentMode}
}'''


class GraphQLClient:
    def __init__(self, url: str, timeout: int = 10):
        self.url = url
        self.timeout = timeout

    def execute(self, query: str, variables: dict):
        response = requests.post(
            self.url,
            json={"query": query, "variables": variables},
            timeout=self.timeout,
        )
        response.raise_for_status()
        body = response.json()
        if body.get("errors"):
            raise RuntimeError(body["errors"])
        return body["data"]


def _utcnow():
    return datetime.now(timezone.utc)


def _result_summary(result):
    if isinstance(result, list):
        return {"type": "list", "count": len(result)}
    if isinstance(result, dict):
        summary = {"type": "object", "keys": sorted(result.keys())}
        for key, value in result.items():
            if isinstance(value, list):
                summary[f"{key}_count"] = len(value)
        return summary
    return {"type": type(result).__name__}


class AgentTools:
    """Audited tool facade between the investigator and SentinelFlow data APIs."""

    def __init__(self, graphql_url: str, client=None, incident_id: str | None = None):
        self.client = client or GraphQLClient(graphql_url)
        self.incident_id = incident_id
        self.trace = []

    def set_incident_id(self, incident_id: str):
        self.incident_id = incident_id

    def _call(self, tool_name: str, args: dict, fn):
        call_id = str(uuid.uuid4())
        started = _utcnow()
        start_clock = time.perf_counter()
        base = {
            "call_id": call_id,
            "tool_name": tool_name,
            "incident_id": self.incident_id,
            "started_at": started.isoformat(),
            "input": args,
        }
        print(json.dumps({"event": "agent_tool_started", **base}), flush=True)

        try:
            result = fn()
            completed = _utcnow()
            record = {
                **base,
                "completed_at": completed.isoformat(),
                "duration_ms": max(0, round((time.perf_counter() - start_clock) * 1000)),
                "status": "success",
                "result_summary": _result_summary(result),
                "error": None,
            }
            self.trace.append(record)
            print(json.dumps({"event": "agent_tool_completed", **record}), flush=True)
            return result
        except Exception as exc:
            completed = _utcnow()
            record = {
                **base,
                "completed_at": completed.isoformat(),
                "duration_ms": max(0, round((time.perf_counter() - start_clock) * 1000)),
                "status": "error",
                "result_summary": None,
                "error": str(exc),
            }
            self.trace.append(record)
            print(json.dumps({"event": "agent_tool_failed", **record}), flush=True)
            raise

    def get_alert_context(self, alert: dict):
        safe_alert = {
            "alert_id": alert.get("alert_id"),
            "alert_time": alert.get("alert_time"),
            "user_id": alert.get("user_id"),
            "risk_score": alert.get("risk_score"),
            "reason": alert.get("reason"),
            "window_start": alert.get("window_start"),
            "window_end": alert.get("window_end"),
        }
        return self._call(
            "get_alert_context",
            {"alert_id": alert.get("alert_id"), "user_id": alert.get("user_id")},
            lambda: safe_alert,
        )

    def get_user_activity(self, user_id: str, limit: int = 100):
        return self._call(
            "get_user_activity",
            {"user_id": user_id, "limit": limit},
            lambda: self.client.execute(
                USER_ACTIVITY_QUERY,
                {"u": user_id, "limit": limit},
            )["eventsByUser"],
        )

    def get_ip_activity(self, ip: str, limit: int = 100):
        return self._call(
            "get_ip_activity",
            {"ip": ip, "limit": limit},
            lambda: self.client.execute(
                IP_ACTIVITY_QUERY,
                {"ip": ip, "limit": limit},
            )["eventsByIp"],
        )

    def get_device_activity(self, device_id: str, limit: int = 100):
        return self._call(
            "get_device_activity",
            {"device_id": device_id, "limit": limit},
            lambda: self.client.execute(
                DEVICE_ACTIVITY_QUERY,
                {"d": device_id, "limit": limit},
            )["eventsByDevice"],
        )

    def get_previous_incidents(self, user_id: str, limit: int = 10):
        return self._call(
            "get_previous_incidents",
            {"user_id": user_id, "limit": limit},
            lambda: self.client.execute(
                PREVIOUS_INCIDENTS_QUERY,
                {"u": user_id, "limit": limit},
            )["investigationsByUser"],
        )

    def snapshot_trace(self):
        return [dict(item) for item in self.trace]
