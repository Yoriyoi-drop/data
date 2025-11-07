#!/bin/bash

# MongoDB Sharded Cluster Setup Script
# Run this after all MongoDB instances are running

echo "Setting up MongoDB sharded cluster for 100M+ logs/day..."

# Wait for MongoDB to be ready
sleep 10

# Initialize config server replica set
echo "Initializing config server replica set..."
mongosh --host mongo-config:27019 --eval '
rs.initiate({
  _id: "configReplSet",
  configsvr: true,
  members: [
    { _id: 0, host: "mongo-config-0:27019" },
    { _id: 1, host: "mongo-config-1:27019" },
    { _id: 2, host: "mongo-config-2:27019" }
  ]
})
'

# Initialize shard replica sets
echo "Initializing shard1 replica set..."
mongosh --host mongo-shard1-0:27017 --eval '
rs.initiate({
  _id: "shard1",
  members: [
    { _id: 0, host: "mongo-shard1-0:27017" },
    { _id: 1, host: "mongo-shard1-1:27017" },
    { _id: 2, host: "mongo-shard1-2:27017" }
  ]
})
'

echo "Initializing shard2 replica set..."
mongosh --host mongo-shard2-0:27017 --eval '
rs.initiate({
  _id: "shard2",
  members: [
    { _id: 0, host: "mongo-shard2-0:27017" },
    { _id: 1, host: "mongo-shard2-1:27017" },
    { _id: 2, host: "mongo-shard2-2:27017" }
  ]
})
'

echo "Initializing shard3 replica set..."
mongosh --host mongo-shard3-0:27017 --eval '
rs.initiate({
  _id: "shard3",
  members: [
    { _id: 0, host: "mongo-shard3-0:27017" },
    { _id: 1, host: "mongo-shard3-1:27017" },
    { _id: 2, host: "mongo-shard3-2:27017" }
  ]
})
'

# Wait for replica sets to be ready
echo "Waiting for replica sets to initialize..."
sleep 30

# Add shards to cluster via mongos
echo "Adding shards to cluster..."
mongosh --host mongos:27017 --eval '
sh.addShard("shard1/mongo-shard1-0:27017,mongo-shard1-1:27017,mongo-shard1-2:27017")
sh.addShard("shard2/mongo-shard2-0:27017,mongo-shard2-1:27017,mongo-shard2-2:27017")
sh.addShard("shard3/mongo-shard3-0:27017,mongo-shard3-1:27017,mongo-shard3-2:27017")
'

# Enable sharding on database
echo "Enabling sharding on infinite_security database..."
mongosh --host mongos:27017 --eval '
sh.enableSharding("infinite_security")
'

# Create time-series collection
echo "Creating time-series collection..."
mongosh --host mongos:27017 --eval '
use infinite_security
db.createCollection("threat_logs", {
  timeseries: {
    timeField: "timestamp",
    metaField: "meta",
    granularity: "seconds"
  },
  expireAfterSeconds: 60*60*24*30
})
'

# Create indexes for optimal query performance
echo "Creating indexes..."
mongosh --host mongos:27017 --eval '
use infinite_security
db.threat_logs.createIndex({ "meta.source_id": 1 })
db.threat_logs.createIndex({ "meta.attack_type": 1, "meta.severity": 1, "timestamp": -1 })
db.threat_logs.createIndex({ "meta.source_ip": 1, "timestamp": -1 })
db.threat_logs.createIndex({ "meta.severity": 1, "timestamp": -1 }, { 
  partialFilterExpression: { "meta.severity": { $in: ["high", "critical"] } } 
})
'

# Shard the collection
echo "Sharding threat_logs collection..."
mongosh --host mongos:27017 --eval '
sh.shardCollection("infinite_security.threat_logs", { "meta.source_id": "hashed" })
'

# Create Kafka topic
echo "Creating Kafka topic..."
docker exec kafka1 kafka-topics --create \
  --topic threat-logs \
  --bootstrap-server localhost:9092 \
  --partitions 12 \
  --replication-factor 3 \
  --config retention.ms=604800000 \
  --config segment.ms=86400000

# Show cluster status
echo "Cluster status:"
mongosh --host mongos:27017 --eval '
sh.status()
'

echo "Setup complete! Cluster ready for 100M+ logs/day"
echo "Monitor with: mongosh --host mongos:27017 --eval 'db.serverStatus()'"