from pathlib import Path
import re
import yaml

ROOT = Path(__file__).parents[1]


def test_compose_contains_complete_docker_stack():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    services = compose["services"]
    expected = {
        "kafka-1", "kafka-2", "kafka-3", "kafka-init",
        "cassandra-1", "cassandra-2", "cassandra-3", "cassandra-init",
        "event-writer", "spark-master", "spark-worker-1", "spark-worker-2",
        "spark-job", "api", "agent", "simulator",
    }
    assert expected == set(services)


def test_kafka_is_three_brokers_and_topics_are_replicated_three_times():
    compose_text = (ROOT / "docker-compose.yml").read_text()
    compose = yaml.safe_load(compose_text)
    for idx in range(1, 4):
        service = compose["services"][f"kafka-{idx}"]
        assert service["environment"]["KAFKA_NODE_ID"] == idx
    assert compose_text.count("--replication-factor 3") == 3
    assert "security-events" in compose_text
    assert "security-alerts" in compose_text
    assert "agent-actions" in compose_text


def test_cassandra_is_three_nodes_with_three_replica_keyspace():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    assert all(f"cassandra-{i}" in compose["services"] for i in range(1, 4))
    schema = (ROOT / "cassandra/schema.cql").read_text()
    assert "'dc1': 3" in schema
    for table in [
        "events_by_user_day", "events_by_ip_day", "events_by_device_day",
        "alerts_by_user", "investigations_by_incident", "investigations_by_user",
        "agent_tool_calls_by_incident",
    ]:
        assert re.search(rf"CREATE TABLE IF NOT EXISTS\s+{table}\b", schema)


def test_dashboard_targets_graphql_api():
    html = (ROOT / "dashboard/index.html").read_text()
    assert ":8000/graphql" in html
    assert "eventsByUser" in html
    assert "investigationsByUser" in html


def test_agent_graphql_is_encapsulated_behind_tool_layer():
    agent = (ROOT / "agent/agent.py").read_text()
    tools = (ROOT / "agent/agent_tools.py").read_text()
    assert "eventsByUser" not in agent
    assert "eventsByIp" not in agent
    assert "eventsByDevice" not in agent
    assert "investigationsByUser" not in agent
    for tool_name in [
        "get_alert_context",
        "get_user_activity",
        "get_ip_activity",
        "get_device_activity",
        "get_previous_incidents",
    ]:
        assert f"def {tool_name}" in tools
