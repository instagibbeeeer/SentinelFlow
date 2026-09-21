#!/usr/bin/env bash
set -e
until cqlsh cassandra-1 -e "SELECT release_version FROM system.local" >/dev/null 2>&1; do sleep 5; done
# Wait until all 3 nodes have joined before using RF=3.
for i in $(seq 1 60); do
  NODES=$(nodetool -h cassandra-1 status 2>/dev/null | awk '/^UN/{count++} END{print count+0}')
  [ "$NODES" -ge 3 ] && break
  sleep 5
done
cqlsh cassandra-1 -f /schema.cql
