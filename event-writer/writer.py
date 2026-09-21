import json, os, time, uuid
from datetime import datetime
from kafka import KafkaConsumer
from cassandra.cluster import Cluster

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
HOSTS = os.getenv("CASSANDRA_HOSTS", "localhost").split(",")

def connect():
    while True:
        try:
            cluster = Cluster(HOSTS)
            return cluster, cluster.connect("sentinelflow")
        except Exception as e:
            print(f"Cassandra not ready: {e}", flush=True)
            time.sleep(5)

cluster, db = connect()
q_user = db.prepare("""INSERT INTO events_by_user_day
(user_id,event_date,event_time,event_id,event_type,device_id,ip,country,bytes,metadata)
VALUES (?,?,?,?,?,?,?,?,?,?)""")
q_ip = db.prepare("""INSERT INTO events_by_ip_day
(ip,event_date,event_time,event_id,user_id,device_id,event_type,country,bytes,metadata)
VALUES (?,?,?,?,?,?,?,?,?,?)""")
q_device = db.prepare("""INSERT INTO events_by_device_day
(device_id,event_date,event_time,event_id,user_id,ip,event_type,country,bytes,metadata)
VALUES (?,?,?,?,?,?,?,?,?,?)""")
q_alert = db.prepare("""INSERT INTO alerts_by_user
(user_id,alert_time,alert_id,risk_score,reason,window_start,window_end)
VALUES (?,?,?,?,?,?,?)""")
q_incident = db.prepare("""INSERT INTO investigations_by_incident
(incident_id,user_id,created_at,severity,confidence,conclusion,evidence,recommended_actions,agent_mode)
VALUES (?,?,?,?,?,?,?,?,?)""")
q_incident_user = db.prepare("""INSERT INTO investigations_by_user
(user_id,created_at,incident_id,severity,confidence,conclusion,evidence,recommended_actions,agent_mode)
VALUES (?,?,?,?,?,?,?,?,?)""")

def dt(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def persist_event(e):
    ts = dt(e["timestamp"]); eid = uuid.UUID(e["event_id"])
    meta = json.dumps(e.get("metadata", {}), separators=(",", ":"))
    futures = [
        db.execute_async(q_user, (e["user_id"], ts.date(), ts, eid, e["event_type"], e["device_id"], e["ip"], e.get("country"), int(e.get("bytes",0)), meta)),
        db.execute_async(q_ip, (e["ip"], ts.date(), ts, eid, e["user_id"], e["device_id"], e["event_type"], e.get("country"), int(e.get("bytes",0)), meta)),
        db.execute_async(q_device, (e["device_id"], ts.date(), ts, eid, e["user_id"], e["ip"], e["event_type"], e.get("country"), int(e.get("bytes",0)), meta)),
    ]
    for f in futures: f.result()

def persist_alert(a):
    db.execute(q_alert, (a["user_id"], dt(a["alert_time"]), uuid.UUID(a["alert_id"]), float(a["risk_score"]), a["reason"], dt(a["window_start"]), dt(a["window_end"])))

def persist_incident(i):
    vals=(uuid.UUID(i["incident_id"]), i["user_id"], dt(i["created_at"]), i["severity"], float(i["confidence"]), i["conclusion"], json.dumps(i.get("evidence",[])), json.dumps(i.get("recommended_actions",[])), i.get("agent_mode","unknown"))
    vals_user=(i["user_id"], dt(i["created_at"]), uuid.UUID(i["incident_id"]), i["severity"], float(i["confidence"]), i["conclusion"], json.dumps(i.get("evidence",[])), json.dumps(i.get("recommended_actions",[])), i.get("agent_mode","unknown"))
    db.execute_async(q_incident, vals).result()
    db.execute_async(q_incident_user, vals_user).result()

consumer = KafkaConsumer("security-events", "security-alerts", "agent-actions",
    bootstrap_servers=BOOTSTRAP, group_id="cassandra-persister",
    auto_offset_reset="earliest", enable_auto_commit=True,
    value_deserializer=lambda b: json.loads(b.decode()))

for msg in consumer:
    try:
        if msg.topic == "security-events": persist_event(msg.value)
        elif msg.topic == "security-alerts": persist_alert(msg.value)
        elif msg.topic == "agent-actions": persist_incident(msg.value)
    except Exception as e:
        print(f"Persist failed for {msg.topic}: {e}", flush=True)
