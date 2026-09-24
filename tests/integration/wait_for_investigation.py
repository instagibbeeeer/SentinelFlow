#!/usr/bin/env python3
import json
import sys
import time
import urllib.error
import urllib.request

URL = "http://127.0.0.1:8000/graphql"
INVESTIGATION_QUERY = '''query($u:String!){
  eventsByUser(userId:$u,limit:100){eventType ip bytes}
  investigationsByUser(userId:$u,limit:20){incidentId severity confidence conclusion evidence recommendedActions agentMode}
}'''
TOOL_TRACE_QUERY = '''query($incident:String!){
  toolCallsByIncident(incidentId:$incident,limit:100){callId toolName status durationMs inputJson resultSummary error}
}'''


def graphql(query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode()
    request = urllib.request.Request(URL, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode())


deadline = time.time() + 240
last = None
while time.time() < deadline:
    try:
        last = graphql(INVESTIGATION_QUERY, {"u": "user-07"})
        data = last.get("data") or {}
        events = data.get("eventsByUser") or []
        incidents = data.get("investigationsByUser") or []
        if len(events) >= 17 and incidents:
            incident = incidents[0]
            trace_body = graphql(TOOL_TRACE_QUERY, {"incident": incident["incidentId"]})
            trace = (trace_body.get("data") or {}).get("toolCallsByIncident") or []
            names = {call["toolName"] for call in trace if call["status"] == "success"}
            required = {
                "get_alert_context",
                "get_user_activity",
                "get_ip_activity",
                "get_device_activity",
                "get_previous_incidents",
            }
            if required.issubset(names):
                print(json.dumps({
                    "event_count": len(events),
                    "investigation": incident,
                    "tool_calls": trace,
                }, indent=2))
                sys.exit(0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        last = {"error": str(exc)}
    time.sleep(5)

print("Timed out waiting for the full event + investigation + tool trace flow", file=sys.stderr)
print(json.dumps(last, indent=2), file=sys.stderr)
sys.exit(1)