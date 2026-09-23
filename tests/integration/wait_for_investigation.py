#!/usr/bin/env python3
import json
import sys
import time
import urllib.error
import urllib.request

URL = "http://127.0.0.1:8000/graphql"
QUERY = '''query($u:String!){
  eventsByUser(userId:$u,limit:100){eventType ip bytes}
  investigationsByUser(userId:$u,limit:20){severity confidence conclusion evidence recommendedActions agentMode}
}'''


def query():
    body = json.dumps({"query": QUERY, "variables": {"u": "user-07"}}).encode()
    request = urllib.request.Request(URL, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode())


deadline = time.time() + 240
last = None
while time.time() < deadline:
    try:
        last = query()
        data = last.get("data") or {}
        events = data.get("eventsByUser") or []
        incidents = data.get("investigationsByUser") or []
        if len(events) >= 17 and incidents:
            print(json.dumps({"event_count": len(events), "investigation": incidents[0]}, indent=2))
            sys.exit(0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        last = {"error": str(exc)}
    time.sleep(5)

print("Timed out waiting for the full event + investigation flow", file=sys.stderr)
print(json.dumps(last, indent=2), file=sys.stderr)
sys.exit(1)
