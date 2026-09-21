The streaming job reads `security-events`, computes rolling per-user features, and emits `security-alerts`.
If your Spark image does not contain `kafka-python-ng`, use the included fallback `streaming_alerts_no_python_kafka.py` pattern or build a small derived image. The root README contains the recommended command.
