import importlib.util
from pathlib import Path

p = Path(__file__).parents[1] / "cluster" / "telemetry" / "sshd_to_kafka.py"
spec = importlib.util.spec_from_file_location("sshd_to_kafka", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def test_failed_password():
    assert mod.normalize("Failed password for invalid user bob from 10.50.0.99 port 55821 ssh2")[:3] == ("LOGIN_FAILED", "bob", "10.50.0.99")

def test_gssapi_success():
    assert mod.normalize("Accepted gssapi-with-mic for alice from 10.50.0.10 port 42424 ssh2") == ("LOGIN_SUCCESS", "alice", "10.50.0.10", "gssapi-with-mic")
