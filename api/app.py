import json, os, time
from datetime import date, datetime, timezone, timedelta
from typing import Optional
import strawberry
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from strawberry.fastapi import GraphQLRouter
from cassandra.cluster import Cluster

HOSTS = os.getenv("CASSANDRA_HOSTS", "localhost").split(",")

def connect():
    while True:
        try:
            c = Cluster(HOSTS); return c, c.connect("sentinelflow")
        except Exception as e:
            print(f"Cassandra not ready: {e}", flush=True); time.sleep(5)

@strawberry.type
class Event:
    event_id: str
    event_time: datetime
    user_id: str
    device_id: str
    event_type: str
    ip: str
    country: Optional[str]
    bytes: int
    metadata: str


@strawberry.type
class Investigation:
    incident_id: str
    created_at: datetime
    user_id: str
    severity: str
    confidence: float
    conclusion: str
    evidence: str
    recommended_actions: str
    agent_mode: str

@strawberry.type
class Health:
    status: str
    cassandra_hosts: list[str]

def rows_to_events(rows):
    out=[]
    for r in rows:
        out.append(Event(event_id=str(r.event_id), event_time=r.event_time, user_id=getattr(r,'user_id',''),
                         device_id=getattr(r,'device_id',''), event_type=r.event_type, ip=getattr(r,'ip',''),
                         country=getattr(r,'country',None), bytes=int(getattr(r,'bytes',0) or 0), metadata=getattr(r,'metadata','{}')))
    return out

@strawberry.type
class Query:
    @strawberry.field
    def health(self) -> Health:
        return Health(status="ok", cassandra_hosts=HOSTS)

    @strawberry.field
    def events_by_user(self, user_id: str, event_date: Optional[date] = None, limit: int = 100) -> list[Event]:
        d = event_date or datetime.now(timezone.utc).date()
        rows = db.execute("SELECT * FROM events_by_user_day WHERE user_id=%s AND event_date=%s LIMIT %s", (user_id,d,min(limit,500)))
        return rows_to_events(rows)

    @strawberry.field
    def events_by_ip(self, ip: str, event_date: Optional[date] = None, limit: int = 100) -> list[Event]:
        d = event_date or datetime.now(timezone.utc).date()
        rows = db.execute("SELECT * FROM events_by_ip_day WHERE ip=%s AND event_date=%s LIMIT %s", (ip,d,min(limit,500)))
        return rows_to_events(rows)

    @strawberry.field
    def events_by_device(self, device_id: str, event_date: Optional[date] = None, limit: int = 100) -> list[Event]:
        d = event_date or datetime.now(timezone.utc).date()
        rows = db.execute("SELECT * FROM events_by_device_day WHERE device_id=%s AND event_date=%s LIMIT %s", (device_id,d,min(limit,500)))
        return rows_to_events(rows)

    @strawberry.field
    def investigations_by_user(self, user_id: str, limit: int = 20) -> list[Investigation]:
        rows = db.execute("SELECT * FROM investigations_by_user WHERE user_id=%s LIMIT %s", (user_id,min(limit,100)))
        return [Investigation(incident_id=str(r.incident_id), created_at=r.created_at, user_id=r.user_id, severity=r.severity, confidence=float(r.confidence), conclusion=r.conclusion, evidence=r.evidence, recommended_actions=r.recommended_actions, agent_mode=r.agent_mode) for r in rows]
cluster, db = connect()
schema = strawberry.Schema(query=Query)
app = FastAPI(title="SentinelFlow API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(GraphQLRouter(schema), prefix="/graphql")

@app.get("/")
def root(): return {"name":"SentinelFlow", "graphql":"/graphql"}
@app.get("/health")
def health(): return {"status":"ok", "cassandra_hosts":HOSTS}
