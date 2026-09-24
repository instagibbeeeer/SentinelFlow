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


def dt(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Persister:
    def __init__(self, db):
        self.db = db
        self.q_user = db.prepare("""INSERT INTO events_by_user_day
        (user_id,event_date,event_time,event_id,event_type,device_id,ip,country,bytes,metadata)
        VALUES (?,?,?,?,?,?,?,?,?,?)""")
        self.q_ip = db.prepare("""INSERT INTO events_by_ip_day
        (ip,event_date,event_time,event_id,user_id,device_id,event_type,country,bytes,metadata)
        VALUES (?,?,?,?,?,?,?,?,?,?)""")
        self.q_device = db.prepare("""INSERT INTO events_by_device_day
        (device_id,event_date,event_time,event_id,user_id,ip,event_type,country,bytes,metadata)
        VALUES (?,?,?,?,?,?,?,?,?,?)""")
        self.q_alert = db.prepare("""INSERT INTO alerts_by_user
        (user_id,alert_time,alert_id,risk_score,reason,window_start,window_end)
        VALUES (?,?,?,?,?,?,?)""")
        self.q_incident = db.prepare("""INSERT INTO investigations_by_incident
        (incident_id,user_id,created_at,severity,confidence,conclusion,evidence,recommended_actions,agent_mode)
        VALUES (?,?,?,?,?,?,?,?,?)""")
        self.q_incident_user = db.prepare("""INSERT INTO investigations_by_user
        (user_id,created_at,incident_id,severity,confidence,conclusion,evidence,recommended_actions,agent_mode)
        VALUES (?,?,?,?,?,?,?,?,?)""")
        self.q_tool_call = db.prepare("""INSERT INTO agent_tool_calls_by_incident
        (incident_id,started_at,call_id,tool_name,completed_at,duration_ms,status,input_json,result_summary,error)
        VALUES (?,?,?,?,?,?,?,?,?,?)""")

    def persist_event(self, e):
        ts = dt(e["timestamp"])
        eid = uuid.UUID(e["event_id"])
        meta = json.dumps(e.get("metadata", {}), separators=(",", ":"))
        futures = [
            self.db.execute_async(self.q_user, (e["user_id"], ts.date(), ts, eid, e["event_type"], e["device_id"], e["ip"], e.get("country"), int(e.get("bytes", 0)), meta)),
            self.db.execute_async(self.q_ip, (e["ip"], ts.date(), ts, eid, e["user_id"], e["device_id"], e["event_type"], e.get("country"), int(e.get("bytes", 0)), meta)),
            self.db.execute_async(self.q_device, (e["device_id"], ts.date(), ts, eid, e["user_id"], e["ip"], e["event_type"], e.get("country"), int(e.get("bytes", 0)), meta)),
        ]
        for future in futures:
            future.result()

    def persist_alert(self, a):
        self.db.execute(self.q_alert, (
            a["user_id"], dt(a["alert_time"]), uuid.UUID(a["alert_id"]), float(a["risk_score"]),
            a["reason"], dt(a["window_start"]), dt(a["window_end"]),
        ))

    def persist_incident(self, i):
        incident_id = uuid.UUID(i["incident_id"])
        created_at = dt(i["created_at"])
        evidence = json.dumps(i.get("evidence", []))
        actions = json.dumps(i.get("recommended_actions", []))
        vals = (incident_id, i["user_id"], created_at, i["severity"], float(i["confidence"]), i["conclusion"], evidence, actions, i.get("agent_mode", "unknown"))
        vals_user = (i["user_id"], created_at, incident_id, i["severity"], float(i["confidence"]), i["conclusion"], evidence, actions, i.get("agent_mode", "unknown"))
        self.db.execute_async(self.q_incident, vals).result()
        self.db.execute_async(self.q_incident_user, vals_user).result()
        for call in i.get("tool_trace", []):
            tool_values = (
                incident_id,
                dt(call["started_at"]),
                uuid.UUID(call["call_id"]),
                call["tool_name"],
                dt(call["completed_at"]),
                int(call.get("duration_ms", 0)),
                call["status"],
                json.dumps(call.get("input", {}), separators=(",", ":")),
                json.dumps(call.get("result_summary"), separators=(",", ":")),
                call.get("error"),
            )
            self.db.execute_async(self.q_tool_call, tool_values).result()


def main():
    cluster, db = connect()
    persister = Persister(db)
    consumer = KafkaConsumer(
        "security-events", "security-alerts", "agent-actions",
        bootstrap_servers=BOOTSTRAP,
        group_id="cassandra-persister",
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda b: json.loads(b.decode()),
    )
    try:
        for msg in consumer:
            try:
                if msg.topic == "security-events":
                    persister.persist_event(msg.value)
                elif msg.topic == "security-alerts":
                    persister.persist_alert(msg.value)
                elif msg.topic == "agent-actions":
                    persister.persist_incident(msg.value)
            except Exception as e:
                print(f"Persist failed for {msg.topic}: {e}", flush=True)
    finally:
        cluster.shutdown()


if __name__ == "__main__":
    main()