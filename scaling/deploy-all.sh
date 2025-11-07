#!/bin/bash

echo "🚀 Deploying 100M+ logs/day MongoDB pipeline..."

# Create namespace
kubectl create namespace infinite-security || true

# Deploy MongoDB sharded cluster
echo "📊 Deploying MongoDB sharded cluster..."
kubectl apply -f mongo-sharded-k8s.yaml -n infinite-security

# Wait for MongoDB to be ready
echo "⏳ Waiting for MongoDB cluster..."
kubectl wait --for=condition=ready pod -l app=mongo-shard1 -n infinite-security --timeout=300s
kubectl wait --for=condition=ready pod -l app=mongo-config -n infinite-security --timeout=300s
kubectl wait --for=condition=ready pod -l app=mongos -n infinite-security --timeout=300s

# Setup MongoDB cluster
echo "🔧 Setting up MongoDB sharding and indexes..."
kubectl exec -it deployment/mongos -n infinite-security -- bash -c "
mongosh --eval '
// Initialize config server
rs.initiate({
  _id: \"configReplSet\",
  configsvr: true,
  members: [
    { _id: 0, host: \"mongo-config-0:27019\" },
    { _id: 1, host: \"mongo-config-1:27019\" },
    { _id: 2, host: \"mongo-config-2:27019\" }
  ]
})
'

sleep 30

mongosh --eval '
// Add shards
sh.addShard(\"shard1/mongo-shard1-0:27017,mongo-shard1-1:27017,mongo-shard1-2:27017\")
sh.addShard(\"shard2/mongo-shard2-0:27017,mongo-shard2-1:27017,mongo-shard2-2:27017\")
sh.addShard(\"shard3/mongo-shard3-0:27017,mongo-shard3-1:27017,mongo-shard3-2:27017\")

// Enable sharding
sh.enableSharding(\"infinite_security\")

// Create time-series collection
use infinite_security
db.createCollection(\"threat_logs\", {
  timeseries: {
    timeField: \"timestamp\",
    metaField: \"meta\",
    granularity: \"seconds\"
  },
  expireAfterSeconds: 60*60*24*30
})

// Create indexes
db.threat_logs.createIndex({ \"meta.source_id\": 1 })
db.threat_logs.createIndex({ \"meta.attack_type\": 1, \"meta.severity\": 1, \"timestamp\": -1 })
db.threat_logs.createIndex({ \"meta.source_ip\": 1, \"timestamp\": -1 })

// Shard collection
sh.shardCollection(\"infinite_security.threat_logs\", { \"meta.source_id\": \"hashed\" })
'
"

# Deploy Kafka cluster
echo "📨 Deploying Kafka cluster..."
docker-compose -f kafka-compose.yml up -d

# Wait for Kafka
echo "⏳ Waiting for Kafka..."
sleep 30

# Create Kafka topic
echo "📝 Creating Kafka topic..."
docker exec kafka1 kafka-topics --create \
  --topic threat-logs \
  --bootstrap-server localhost:9092 \
  --partitions 12 \
  --replication-factor 3 \
  --config retention.ms=604800000

# Deploy monitoring
echo "📈 Deploying monitoring stack..."
docker-compose -f prometheus-grafana.yml up -d

# Deploy ingest consumers
echo "🔄 Deploying ingest consumers..."

# Python consumer
kubectl create configmap python-consumer --from-file=python-ingest-consumer.py -n infinite-security
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: python-consumer
  namespace: infinite-security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: python-consumer
  template:
    metadata:
      labels:
        app: python-consumer
    spec:
      containers:
      - name: consumer
        image: python:3.11-slim
        command: ["python", "/app/python-ingest-consumer.py"]
        volumeMounts:
        - name: code
          mountPath: /app
        env:
        - name: MONGO_URI
          value: "mongodb://mongos:27017"
        - name: KAFKA_BROKERS
          value: "kafka1:29092,kafka2:29092,kafka3:29092"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1"
      volumes:
      - name: code
        configMap:
          name: python-consumer
EOF

# Go consumer
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: go-consumer
  namespace: infinite-security
spec:
  replicas: 2
  selector:
    matchLabels:
      app: go-consumer
  template:
    metadata:
      labels:
        app: go-consumer
    spec:
      containers:
      - name: consumer
        image: golang:1.21-alpine
        command: ["go", "run", "/app/go-ingest-consumer.go"]
        volumeMounts:
        - name: code
          mountPath: /app
        env:
        - name: MONGO_URI
          value: "mongodb://mongos:27017"
        - name: KAFKA_BROKERS
          value: "kafka1:29092,kafka2:29092,kafka3:29092"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: code
        configMap:
          name: go-consumer
EOF

# Deploy archival job as CronJob
echo "🗄️ Setting up archival job..."
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: archival-job
  namespace: infinite-security
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: archival
            image: python:3.11-slim
            command: ["python", "/app/archival_job.py"]
            volumeMounts:
            - name: code
              mountPath: /app
            env:
            - name: MONGO_URI
              value: "mongodb://mongos:27017"
            - name: MINIO_ENDPOINT
              value: "minio:9000"
            - name: MINIO_ACCESS_KEY
              value: "minioadmin"
            - name: MINIO_SECRET_KEY
              value: "minioadmin"
          restartPolicy: OnFailure
          volumes:
          - name: code
            configMap:
              name: archival-job
EOF

echo "✅ Deployment complete!"
echo ""
echo "🔗 Access points:"
echo "  - MongoDB: kubectl port-forward svc/mongos 27017:27017 -n infinite-security"
echo "  - Kafka UI: http://localhost:8080"
echo "  - Grafana: http://localhost:3000 (admin/admin123)"
echo "  - Prometheus: http://localhost:9090"
echo ""
echo "📊 Monitor with:"
echo "  kubectl get pods -n infinite-security"
echo "  kubectl logs -f deployment/python-consumer -n infinite-security"
echo ""
echo "🧪 Test ingest:"
echo "  python test_producer.py"