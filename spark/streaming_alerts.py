import os, json, uuid
from datetime import datetime, timezone
from pyspark.sql import SparkSession, functions as F, types as T
from kafka import KafkaProducer

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")

schema = T.StructType([
    T.StructField("event_id", T.StringType()),
    T.StructField("timestamp", T.StringType()),
    T.StructField("user_id", T.StringType()),
    T.StructField("device_id", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("ip", T.StringType()),
    T.StructField("country", T.StringType()),
    T.StructField("bytes", T.LongType()),
    T.StructField("metadata", T.MapType(T.StringType(), T.StringType())),
])

spark = (SparkSession.builder.appName("SentinelFlowAlerts").getOrCreate())
spark.sparkContext.setLogLevel("WARN")

raw = (spark.readStream.format("kafka")
       .option("kafka.bootstrap.servers", BOOTSTRAP)
       .option("subscribe", "security-events")
       .option("startingOffsets", "latest")
       .load())

events = (raw.select(F.from_json(F.col("value").cast("string"), schema).alias("e"))
          .select("e.*")
          .withColumn("event_ts", F.to_timestamp("timestamp"))
          .withWatermark("event_ts", "2 minutes"))

features = (events.groupBy(F.window("event_ts", "30 seconds", "10 seconds"), "user_id")
    .agg(
        F.sum(F.when(F.col("event_type") == "LOGIN_FAILED", 1).otherwise(0)).alias("failed_logins"),
        F.sum(F.when(F.col("event_type") == "PRIVILEGE_CHANGE", 1).otherwise(0)).alias("privilege_changes"),
        F.sum(F.when(F.col("event_type") == "FILE_DOWNLOAD", F.col("bytes")).otherwise(0)).alias("download_bytes"),
        F.approx_count_distinct("ip").alias("unique_ips"),
        F.approx_count_distinct("country").alias("countries"),
    )
    .withColumn("risk_score", F.least(F.lit(1.0),
        F.col("failed_logins") * F.lit(.055) +
        F.col("privilege_changes") * F.lit(.25) +
        F.when(F.col("download_bytes") > 1_000_000_000, .30).otherwise(0.0) +
        F.when(F.col("countries") > 1, .10).otherwise(0.0)))
    .filter(F.col("risk_score") >= .65))

def emit_alerts(batch_df, batch_id):
    rows = batch_df.collect()
    if not rows: return
    producer = KafkaProducer(bootstrap_servers=BOOTSTRAP, value_serializer=lambda v: json.dumps(v).encode())
    for r in rows:
        reasons = []
        if r.failed_logins >= 8: reasons.append(f"{r.failed_logins} failed logins")
        if r.privilege_changes: reasons.append("privilege change")
        if r.download_bytes > 1_000_000_000: reasons.append(f"large download {r.download_bytes} bytes")
        if r.countries > 1: reasons.append("multiple countries")
        alert = {
            "alert_id": str(uuid.uuid4()), "user_id": r.user_id,
            "alert_time": datetime.now(timezone.utc).isoformat(),
            "risk_score": float(r.risk_score), "reason": ", ".join(reasons) or "stream anomaly",
            "window_start": r.window.start.isoformat(), "window_end": r.window.end.isoformat(),
        }
        producer.send("security-alerts", key=r.user_id.encode(), value=alert)
    producer.flush(); producer.close()

query = (features.writeStream.outputMode("update").foreachBatch(emit_alerts)
         .option("checkpointLocation", "/tmp/sentinelflow-checkpoints")
         .trigger(processingTime="5 seconds").start())
query.awaitTermination()
