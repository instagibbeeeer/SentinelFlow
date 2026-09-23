import json, os, random, sys, time, uuid
from datetime import datetime, timezone
from kafka import KafkaProducer

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
EPS = float(os.getenv("EVENTS_PER_SECOND", "5"))
USERS = [f"user-{i:02d}" for i in range(1, 21)] 
DEVICES = {u: f"laptop-{i:02d}" for i, u in enumerate(USERS, 1)}
IPS = [f"10.0.0.{i}" for i in range(10, 40)] #there parser will break if u use other subnet ips
COUNTRIES = ["DE", "DE", "DE", "FR", "NL"]

def producer():
    return KafkaProducer(bootstrap_servers=BOOTSTRAP, value_serializer=lambda v: json.dumps(v).encode())

def event(user, event_type, ip=None, device=None, country="DE", bytes_=0, **metadata):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user,
        "device_id": device or DEVICES.get(user, "unknown-device"),
        "event_type": event_type,
        "ip": ip or random.choice(IPS),
        "country": country,
        "bytes": int(bytes_),
        "metadata": metadata,
    }

def send(p, e):
    p.send("security-events", key=e["user_id"].encode(), value=e)
    print(json.dumps(e), flush=True)

def normal(p):
    while True:
        u = random.choice(USERS)
        typ = random.choices(["LOGIN_SUCCESS", "PROCESS_START", "FILE_DOWNLOAD"], [0.35, 0.5, 0.15])[0]
        size = random.randint(10_000, 20_000_000) if typ == "FILE_DOWNLOAD" else 0
        send(p, event(u, typ, bytes_=size, country=random.choice(COUNTRIES)))
        time.sleep(1 / max(EPS, .1))

def attack(p, user="user-07"):
    evil_ip = "185.222.44.91"
    print(f"Launching credential-compromise scenario against {user}", flush=True)
    for _ in range(14):
        send(p, event(user, "LOGIN_FAILED", ip=evil_ip, country="DE", device="unknown-device"))
        time.sleep(.15)
    send(p, event(user, "LOGIN_SUCCESS", ip=evil_ip, country="DE", device="unknown-device"))
    time.sleep(.5)
    send(p, event(user, "PRIVILEGE_CHANGE", ip=evil_ip, country="CN", old_role="employee", new_role="admin"))
    time.sleep(.5)
    send(p, event(user, "FILE_DOWNLOAD", ip=evil_ip, country="PH", bytes_=5_100_000_000, filename="customer_export.zip"))
    p.flush()

if __name__ == "__main__":
    p = producer()
    mode = sys.argv[1] if len(sys.argv) > 1 else "normal"
    attack(p) if mode == "attack" else normal(p)
