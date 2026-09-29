import os
import time
from ssl import CERT_REQUIRED, PROTOCOL_TLS_CLIENT, SSLContext
from cassandra.cluster import Cluster


def create_cluster():
    mode = os.getenv("DATASTORE_MODE", "cassandra").lower()
    if mode != "keyspaces":
        hosts = [h.strip() for h in os.getenv("CASSANDRA_HOSTS", "localhost").split(",") if h.strip()]
        return Cluster(hosts)

    from cassandra_sigv4.auth import SigV4AuthProvider

    region = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "eu-central-1"))
    endpoint = os.getenv("KEYSPACES_ENDPOINT", f"cassandra.{region}.amazonaws.com")
    ca_bundle = os.environ.get("KEYSPACES_CA_BUNDLE", "/app/certs/keyspaces-bundle.pem")

    ssl_context = SSLContext(PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(ca_bundle)
    ssl_context.verify_mode = CERT_REQUIRED

    # Todo: comeback when setting up aws
    auth_provider = SigV4AuthProvider()
    return Cluster(
        [endpoint],
        port=9142,
        ssl_context=ssl_context,
        auth_provider=auth_provider,
        protocol_version=4,
        connect_timeout=15,
    )


def connect(keyspace="sentinelflow", retry=True):
    while True:
        try:
            cluster = create_cluster()
            return cluster, cluster.connect(keyspace)
        except Exception as exc:
            if not retry:
                raise
            print(f"Datastore not ready: {exc}", flush=True)
            time.sleep(5)
