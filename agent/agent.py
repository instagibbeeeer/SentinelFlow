import json
import os
import time
import uuid
from datetime import datetime, timezone

from kafka import KafkaConsumer, KafkaProducer

from agent_tools import AgentTools

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
GRAPHQL = os.getenv("GRAPHQL_URL", "http://localhost:8000/graphql")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")


def collect_evidence(alert, tools):
    alert_context = tools.get_alert_context(alert)
    user_events = tools.get_user_activity(alert["user_id"], limit=100)

    suspicious_ips = []
    suspicious_devices = []
    for event in user_events:
        if event["eventType"] in {"LOGIN_FAILED", "LOGIN_SUCCESS", "PRIVILEGE_CHANGE"}:
            if event.get("ip") and event["ip"] not in suspicious_ips:
                suspicious_ips.append(event["ip"])
            if event.get("deviceId") and event["deviceId"] not in suspicious_devices:
                suspicious_devices.append(event["deviceId"])

    ip_events = tools.get_ip_activity(suspicious_ips[0], limit=100) if suspicious_ips else []
    device_events = tools.get_device_activity(suspicious_devices[0], limit=100) if suspicious_devices else []
    previous_incidents = tools.get_previous_incidents(alert["user_id"], limit=10)

    return {
        "alert_context": alert_context,
        "user_events": user_events,
        "ip_events": ip_events,
        "device_events": device_events,
        "previous_incidents": previous_incidents,
    }


def deterministic_reason(alert, evidence):
    user_events = evidence["user_events"]
    failed = sum(event["eventType"] == "LOGIN_FAILED" for event in user_events)
    privilege_changes = sum(event["eventType"] == "PRIVILEGE_CHANGE" for event in user_events)
    download_bytes = sum(
        int(event.get("bytes") or 0)
        for event in user_events
        if event["eventType"] == "FILE_DOWNLOAD"
    )
    cross_users = len({event.get("userId") for event in evidence["ip_events"] if event.get("userId")})
    previous_incidents = len(evidence.get("previous_incidents", []))

    signals = []
    if failed >= 8:
        signals.append(f"{failed} failed logins")
    if privilege_changes:
        signals.append("privilege escalation")
    if download_bytes > 1_000_000_000:
        signals.append(f"{download_bytes / 1e9:.1f} GB downloaded")
    if cross_users > 1:
        signals.append(f"source IP touched {cross_users} users")
    if previous_incidents:
        signals.append(f"{previous_incidents} previous investigations for user")

    confidence = min(.99, .55 + .08 * len(signals))
    severity = "CRITICAL" if alert["risk_score"] >= .9 else "HIGH"
    conclusion = (
        "Likely credential compromise with post-authentication abuse"
        if len(signals) >= 2
        else "Suspicious account activity requiring review"
    )
    actions = [
        "revoke active sessions",
        "temporarily disable account",
        "block suspicious source IP",
        "preserve relevant audit logs",
    ]
    return {
        "severity": severity,
        "confidence": confidence,
        "conclusion": conclusion,
        "evidence": signals,
        "recommended_actions": actions,
        "agent_mode": "deterministic-tools",
    }


def llm_reason(alert, evidence, fallback):
    if not OPENAI_API_KEY:
        return fallback
    try:
        from openai import OpenAI

        client = OpenAI(api_key=OPENAI_API_KEY)
        prompt = {
            "alert": alert,
            "evidence": evidence,
            "required_schema": {
                "severity": "HIGH|CRITICAL",
                "confidence": "0..1",
                "conclusion": "string",
                "evidence": ["string"],
                "recommended_actions": ["string"],
            },
        }
        response = client.responses.create(
            model=OPENAI_MODEL,
            instructions=(
                "You are a SOC investigation agent. Analyze only supplied telemetry. "
                "Return concise JSON only. Never claim an action was executed."
            ),
            input=json.dumps(prompt),
        )
        parsed = json.loads(response.output_text)
        parsed["agent_mode"] = "llm+tools"
        return parsed
    except Exception as exc:
        print(f"LLM fallback: {exc}", flush=True)
        return fallback


def investigate(alert, tools=None):
    incident_id = str(uuid.uuid4())
    tools = tools or AgentTools(GRAPHQL, incident_id=incident_id)
    tools.set_incident_id(incident_id)

    evidence = collect_evidence(alert, tools)
    result = llm_reason(alert, evidence, deterministic_reason(alert, evidence))
    return {
        "incident_id": incident_id,
        "user_id": alert["user_id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tool_trace": tools.snapshot_trace(),
        **result,
    }


def main():
    consumer = KafkaConsumer(
        "security-alerts",
        bootstrap_servers=BOOTSTRAP,
        group_id="investigator-agent",
        auto_offset_reset="latest",
        value_deserializer=lambda b: json.loads(b.decode()),
    )
    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        value_serializer=lambda value: json.dumps(value).encode(),
    )
    last_investigated = {}

    for msg in consumer:
        alert = msg.value
        now = time.time()
        if now - last_investigated.get(alert["user_id"], 0) < 30:
            continue
        try:
            incident = investigate(alert)
            producer.send("agent-actions", key=alert["user_id"].encode(), value=incident)
            producer.flush()
            last_investigated[alert["user_id"]] = now
            print(json.dumps(incident, indent=2), flush=True)
        except Exception as exc:
            print(f"Investigation failed: {exc}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
