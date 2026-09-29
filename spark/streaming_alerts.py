import os
from pyspark.sql import SparkSession, functions as F, types as T
from risk import (
    ALERT_THRESHOLD,
    FAILED_LOGIN_WEIGHT,
    LARGE_DOWNLOAD_BYTES,
    LARGE_DOWNLOAD_WEIGHT,
    MULTI_COUNTRY_WEIGHT,
    PRIVILEGE_CHANGE_WEIGHT,
)

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
CHECKPOINT = os.getenv("SPARK_CHECKPOINT_LOCATION", "/tmp/sentinelflow-checkpoints")
KAFKA_AUTH_MODE = os.getenv("KAFKA_AUTH_MODE", "plaintext").lower()

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


def with_kafka_options(writer_or_reader):
    obj = writer_or_reader.option("kafka.bootstrap.servers", BOOTSTRAP)
    if KAFKA_AUTH_MODE == "msk_iam":
        obj = (obj
            .option("kafka.security.protocol", "SASL_SSL")
            .option("kafka.sasl.mechanism", "AWS_MSK_IAM")
            .option("kafka.sasl.jaas.config", "software.amazon.msk.auth.iam.IAMLoginModule required;")
            .option("kafka.sasl.client.callback.handler.class", "software.amazon.msk.auth.iam.IAMClientCallbackHandler"))
    return obj


def build_features(events):
    return (events.groupBy(F.window("event_ts", "30 seconds", "10 seconds"), "user_id")
        .agg(
            F.sum(F.when(F.col("event_type") == "LOGIN_FAILED", 1).otherwise(0)).alias("failed_logins"),
            F.sum(F.when(F.col("event_type") == "PRIVILEGE_CHANGE", 1).otherwise(0)).alias("privilege_changes"),
            F.sum(F.when(F.col("event_type") == "FILE_DOWNLOAD", F.col("bytes")).otherwise(0)).alias("download_bytes"),
            F.approx_count_distinct("ip").alias("unique_ips"),
            F.approx_count_distinct("country").alias("countries"),
        )
        .withColumn("risk_score", F.least(F.lit(1.0),
            F.col("failed_logins") * F.lit(FAILED_LOGIN_WEIGHT) +
            F.col("privilege_changes") * F.lit(PRIVILEGE_CHANGE_WEIGHT) +
            F.when(F.col("download_bytes") > LARGE_DOWNLOAD_BYTES, LARGE_DOWNLOAD_WEIGHT).otherwise(0.0) +
            F.when(F.col("countries") > 1, MULTI_COUNTRY_WEIGHT).otherwise(0.0)))
        .filter(F.col("risk_score") >= ALERT_THRESHOLD))


def emit_alerts(batch_df, batch_id):
    if batch_df.rdd.isEmpty():
        return

    reason_parts = F.array_compact(F.array(
        F.when(F.col("failed_logins") > 0, F.concat(F.col("failed_logins").cast("string"), F.lit(" failed login(s)"))),
        F.when(F.col("privilege_changes") > 0, F.lit("privilege change")),
        F.when(F.col("download_bytes") > LARGE_DOWNLOAD_BYTES, F.lit("large download")),
        F.when(F.col("countries") > 1, F.lit("multiple countries")),
    ))

    alerts = (batch_df
        .withColumn("alert_id", F.expr("uuid()"))
        .withColumn("alert_time", F.current_timestamp())
        .withColumn("reason", F.concat_ws(", ", reason_parts))
        .withColumn("window_start", F.col("window.start"))
        .withColumn("window_end", F.col("window.end"))
        .select(
            F.col("user_id").cast("string").alias("key"),
            F.to_json(F.struct(
                F.col("alert_id"),
                F.col("user_id"),
                F.date_format("alert_time", "yyyy-MM-dd'T'HH:mm:ss.SSSXXX").alias("alert_time"),
                F.col("risk_score"),
                F.col("reason"),
                F.date_format("window_start", "yyyy-MM-dd'T'HH:mm:ss.SSSXXX").alias("window_start"),
                F.date_format("window_end", "yyyy-MM-dd'T'HH:mm:ss.SSSXXX").alias("window_end"),
            )).alias("value")
        ))

    writer = alerts.write.format("kafka")
    writer = with_kafka_options(writer)
    writer.option("topic", "security-alerts").save()


def main():
    spark = SparkSession.builder.appName("SentinelFlowAlerts").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    raw_reader = spark.readStream.format("kafka")
    raw = (with_kafka_options(raw_reader)
           .option("subscribe", "security-events")
           .option("startingOffsets", "latest")
           .load())
    events = (raw.select(F.from_json(F.col("value").cast("string"), schema).alias("e"))
              .select("e.*")
              .withColumn("event_ts", F.to_timestamp("timestamp"))
              .withWatermark("event_ts", "2 minutes"))
    features = build_features(events)
    query = (features.writeStream.outputMode("update").foreachBatch(emit_alerts)
             .option("checkpointLocation", CHECKPOINT)
             .trigger(processingTime="5 seconds").start())
    query.awaitTermination()


if __name__ == "__main__":
    main()