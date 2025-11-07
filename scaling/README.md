# 🚀 100M+ Logs/Day MongoDB Pipeline

Complete production-ready pipeline for ingesting and processing 100+ million security logs per day.

## 📊 Architecture Overview

```
Security Agents → Kafka (12 partitions) → Bulk Consumers → MongoDB Sharded Cluster → Hot/Warm/Cold Storage
                                      ↓
                              Monitoring (Prometheus/Grafana)
```

## 🏗️ Components

- **Kafka Cluster**: 3-node cluster with 12 partitions for high throughput
- **MongoDB Sharded**: 3 shards × 3 replicas = 9 data nodes + config servers + mongos routers
- **Bulk Consumers**: Python/Go/Rust/C++ consumers with batched writes
- **Monitoring**: Prometheus + Grafana dashboards
- **Archival**: Daily Parquet export to MinIO/S3 with automatic cleanup

## 📈 Performance Targets

- **Throughput**: 100M logs/day (~1,157/sec average, 10K/sec peak)
- **Storage**: ~50GB/day compressed, 30-day hot retention
- **Latency**: <200ms P99 write latency
- **Availability**: 99.9% uptime with replica sets

## 🚀 Quick Start

```bash
# 1. Deploy infrastructure
chmod +x deploy-all.sh
./deploy-all.sh

# 2. Test with sample data
python test_producer.py quick

# 3. Run sustained load test
python test_producer.py sustained

# 4. Monitor performance
# Grafana: http://localhost:3000 (admin/admin123)
# Kafka UI: http://localhost:8080
```

## 📁 File Structure

```
scaling/
├── kafka-compose.yml           # Kafka cluster setup
├── mongo-sharded-k8s.yaml     # MongoDB sharded cluster
├── python-ingest-consumer.py  # Python bulk consumer
├── go-ingest-consumer.go       # Go bulk consumer  
├── rust-ingest-consumer.rs     # Rust bulk consumer
├── cpp-ingest-consumer.cpp     # C++ bulk consumer
├── archival_job.py            # Daily archival to Parquet
├── prometheus-grafana.yml      # Monitoring stack
├── index_and_shard_setup.sh   # MongoDB initialization
├── test_producer.py           # Load testing tool
└── deploy-all.sh              # Complete deployment
```

## 🔧 Configuration

### MongoDB Tuning
- WiredTiger compression: `zstd`
- Cache size: 50% of RAM
- Time-series collections with 30-day TTL
- Hashed sharding on `meta.source_id`

### Kafka Tuning
- 12 partitions for parallel processing
- 7-day retention
- Snappy compression
- Batch size: 16KB

### Consumer Tuning
- Batch size: 1000 documents
- Flush interval: 500ms
- Unordered bulk writes
- Connection pooling

## 📊 Monitoring

Key metrics to watch:
- **Ingest rate**: ops/sec via MongoDB metrics
- **Write latency**: P99 < 200ms
- **Replication lag**: < 30 seconds
- **Disk usage**: < 80% capacity
- **Kafka consumer lag**: < 1000 messages

## 🗄️ Storage Management

### Hot Tier (0-30 days)
- NVMe storage on MongoDB cluster
- Full indexing for fast queries
- Real-time monitoring and alerting

### Cold Tier (30+ days)
- Parquet files in MinIO/S3
- Date-partitioned: `year=2024/month=01/day=15/`
- Compressed with Snappy
- Queryable via Spark/Presto

### Archival Process
```bash
# Manual archival
python archival_job.py

# Automated via CronJob (daily at 2 AM)
kubectl get cronjob archival-job -n infinite-security
```

## 🧪 Load Testing

### Test Scenarios
```bash
# Baseline test
python test_producer.py load_test

# Sustained 100M/day simulation
python test_producer.py sustained

# Multi-threaded high throughput
python test_producer.py multi
```

### Expected Results
- **1K/sec**: Baseline performance, low latency
- **5K/sec**: Normal peak load, acceptable latency
- **10K/sec**: Stress test, monitor for bottlenecks

## 🔒 Security

- TLS encryption for all MongoDB connections
- Kafka SASL authentication (production)
- Network policies in Kubernetes
- Encrypted backups and archival
- Audit logging enabled

## 📋 Operational Playbook

### Daily Operations
1. Check Grafana dashboards for anomalies
2. Verify archival job completion
3. Monitor disk usage trends
4. Review error logs

### Weekly Operations
1. Backup verification
2. Performance trend analysis
3. Capacity planning review
4. Security audit logs

### Emergency Procedures
1. **High latency**: Scale consumers, check indexes
2. **Disk full**: Trigger emergency archival
3. **Replication lag**: Check network, restart lagging nodes
4. **Consumer lag**: Scale consumer replicas

## 💰 Cost Estimation

### Infrastructure (monthly)
- **MongoDB cluster**: 9 × 16vCPU/64GB/4TB ≈ $15K-25K
- **Kafka cluster**: 3 × 8vCPU/32GB/1TB ≈ $3K-5K
- **Storage**: 6TB hot + archival ≈ $2K-4K
- **Total**: ~$20K-35K/month

### Optimization Tips
- Use spot instances for non-critical consumers
- Implement intelligent archival policies
- Optimize indexes based on query patterns
- Consider read replicas for analytics

## 🚨 Alerts Configuration

Critical alerts:
- Write latency P99 > 500ms
- Replication lag > 60s
- Disk usage > 85%
- Consumer lag > 5000 messages
- MongoDB node down
- Kafka broker down

## 📞 Support

For issues:
1. Check Grafana dashboards
2. Review application logs: `kubectl logs -f deployment/python-consumer -n infinite-security`
3. MongoDB status: `mongosh --host mongos:27017 --eval 'db.serverStatus()'`
4. Kafka status: Check Kafka UI at http://localhost:8080