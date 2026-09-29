import os
import socket
from kafka import KafkaAdminClient, KafkaConsumer, KafkaProducer


def kafka_auth_kwargs():
#authmodE/Transport
    mode = os.getenv("KAFKA_AUTH_MODE", "plaintext").lower()
    if mode != "msk_iam":
        return {}

    from aws_msk_iam_sasl_signer import MSKAuthTokenProvider

    region = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "eu-central-1"))

    class TokenProvider:
        def token(self):
            token, _ = MSKAuthTokenProvider.generate_auth_token(region)
            return token

    return {
        "security_protocol": "SASL_SSL",
        "sasl_mechanism": "OAUTHBEARER",
        "sasl_oauth_token_provider": TokenProvider(),
        "client_id": os.getenv("KAFKA_CLIENT_ID", socket.gethostname()),
    }


def bootstrap_servers():
    return os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


def make_producer(**kwargs):
    opts = {
        "bootstrap_servers": bootstrap_servers(),
        "value_serializer": lambda v: __import__("json").dumps(v).encode(),
    }
    opts.update(kafka_auth_kwargs())
    opts.update(kwargs)
    return KafkaProducer(**opts)


def make_consumer(*topics, **kwargs):
    opts = {
        "bootstrap_servers": bootstrap_servers(),
        "value_deserializer": lambda b: __import__("json").loads(b.decode()),
    }
    opts.update(kafka_auth_kwargs())
    opts.update(kwargs)
    return KafkaConsumer(*topics, **opts)


def make_admin(**kwargs):
    opts = {"bootstrap_servers": bootstrap_servers()}
    opts.update(kafka_auth_kwargs())
    opts.update(kwargs)
    return KafkaAdminClient(**opts)
