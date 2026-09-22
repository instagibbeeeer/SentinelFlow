import json, os, time, uuid
from datetime import datetime, timezone
import requests
from kafka import KafkaConsumer, KafkaProducer

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
GRAPHQL = os.getenv("GRAPHQL_URL", "http://localhost:8000/graphql")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")



def gql(query, variables):
    r = requests.post(GRAPHQL, json={"query":query,"variables":variables}, timeout=10)
    r.raise_for_status(); body=r.json()
    if body.get("errors"): raise RuntimeError(body["errors"])
    return body["data"]

USER_Q = '''query($u:String!){ eventsByUser(userId:$u,limit:100){eventId eventTime eventType ip deviceId country bytes metadata} }'''
IP_Q = '''query($ip:String!){ eventsByIp(ip:$ip,limit:100){eventId eventTime eventType userId deviceId country bytes metadata} }'''
DEVICE_Q = '''query($d:String!){ eventsByDevice(deviceId:$d,limit:100){eventId eventTime eventType userId ip country bytes metadata} }'''

def collect_evidence(alert):
    # Tool 1: user timeline is always useful.
    user_events = gql(USER_Q, {"u": alert["user_id"]})["eventsByUser"]
    suspicious_ips = []
    suspicious_devices = []
    for e in user_events:
        if e["eventType"] in {"LOGIN_FAILED","LOGIN_SUCCESS","PRIVILEGE_CHANGE"}:
            if e.get("ip") and e["ip"] not in suspicious_ips: suspicious_ips.append(e["ip"])
            if e.get("deviceId") and e["deviceId"] not in suspicious_devices: suspicious_devices.append(e["deviceId"])
    # Tool 2/3: dynamically pivot on the most recent identities seen in the user timeline.
    ip_events = gql(IP_Q, {"ip": suspicious_ips[0]})["eventsByIp"] if suspicious_ips else []
    device_events = gql(DEVICE_Q, {"d": suspicious_devices[0]})["eventsByDevice"] if suspicious_devices else []
    return {"user_events":user_events, "ip_events":ip_events, "device_events":device_events}

def deterministic_reason(alert, ev):
    ue = ev["user_events"]
    failed = sum(x["eventType"]=="LOGIN_FAILED" for x in ue)
    priv = sum(x["eventType"]=="PRIVILEGE_CHANGE" for x in ue)
    big = sum(int(x.get("bytes") or 0) for x in ue if x["eventType"]=="FILE_DOWNLOAD")
    cross_users = len({x.get("userId") for x in ev["ip_events"] if x.get("userId")})
    signals=[]
    if failed >= 8: signals.append(f"{failed} failed logins")
    if priv: signals.append("privilege escalation")
    if big > 1_000_000_000: signals.append(f"{big/1e9:.1f} GB downloaded")
    if cross_users > 1: signals.append(f"source IP touched {cross_users} users")
    confidence=min(.99, .55 + .08*len(signals))
    severity="CRITICAL" if alert["risk_score"]>=.9 else "HIGH"
    conclusion="Likely credential compromise with post-authentication abuse" if len(signals)>=2 else "Suspicious account activity requiring review"
    actions=["revoke active sessions","temporarily disable account","block suspicious source IP","preserve relevant audit logs"]
    return {"severity":severity,"confidence":confidence,"conclusion":conclusion,"evidence":signals,"recommended_actions":actions,"agent_mode":"deterministic-tools"}

def llm_reason(alert, evidence, fallback):
    if not OPENAI_API_KEY: return fallback
    try:
        from openai import OpenAI
        client=OpenAI(api_key=OPENAI_API_KEY)
        prompt={"alert":alert,"evidence":evidence,"required_schema":{"severity":"HIGH|CRITICAL","confidence":"0..1","conclusion":"string","evidence":["string"],"recommended_actions":["string"]}}
        response=client.responses.create(model=OPENAI_MODEL,
            instructions="You are a SOC investigation agent. Analyze only supplied telemetry. Return concise JSON only. Never claim an action was executed.",
            input=json.dumps(prompt))
        parsed=json.loads(response.output_text)
        parsed["agent_mode"]="llm+tools"
        return parsed
    except Exception as e:
        print(f"LLM fallback: {e}", flush=True); return fallback

def investigate(alert):
    evidence=collect_evidence(alert)
    result=llm_reason(alert,evidence,deterministic_reason(alert,evidence))
    incident={"incident_id":str(uuid.uuid4()),"user_id":alert["user_id"],"created_at":datetime.now(timezone.utc).isoformat(), **result}
    return incident
def main():
    consumer = KafkaConsumer("security-alerts", bootstrap_servers=BOOTSTRAP, group_id="investigator-agent",
                         auto_offset_reset="latest", value_deserializer=lambda b: json.loads(b.decode()))
    producer = KafkaProducer(bootstrap_servers=BOOTSTRAP, value_serializer=lambda v: json.dumps(v).encode())
    last_investigated = {}
    for msg in consumer:
        alert=msg.value
        now=time.time()
        if now - last_investigated.get(alert["user_id"], 0) < 30:
            continue
        try:
            incident=investigate(alert)
            producer.send("agent-actions", key=alert["user_id"].encode(), value=incident)
            producer.flush()
            last_investigated[alert["user_id"]]=now
            print(json.dumps(incident,indent=2),flush=True)
        except Exception as e:
            print(f"Investigation failed: {e}",flush=True); time.sleep(2)
 if __name__ == "__main__":
    main()       
