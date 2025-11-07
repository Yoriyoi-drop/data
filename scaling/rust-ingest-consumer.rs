use mongodb::{Client, Collection, options::{ClientOptions, InsertManyOptions}};
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::{interval, Duration};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

#[derive(Debug, Serialize, Deserialize)]
struct ThreatLogMeta {
    source_id: String,
    source_ip: String,
    attack_type: String,
    severity: String,
    shard_key: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ThreatLogFields {
    raw: Value,
    score: f64,
    agent_votes: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct ThreatLog {
    timestamp: DateTime<Utc>,
    meta: ThreatLogMeta,
    fields: ThreatLogFields,
}

struct BulkIngestConsumer {
    client: Client,
    collection: Collection<ThreatLog>,
    consumer: StreamConsumer,
    batch_size: usize,
    batch: Vec<ThreatLog>,
}

impl BulkIngestConsumer {
    async fn new(mongo_uri: &str, kafka_brokers: &str, topic: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // MongoDB connection
        let client_options = ClientOptions::parse(mongo_uri).await?;
        let client = Client::with_options(client_options)?;
        let collection = client
            .database("infinite_security")
            .collection::<ThreatLog>("threat_logs");

        // Kafka consumer
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", "rust-ingest-workers")
            .set("bootstrap.servers", kafka_brokers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "true")
            .set("auto.offset.reset", "latest")
            .create()?;

        consumer.subscribe(&[topic])?;

        Ok(BulkIngestConsumer {
            client,
            collection,
            consumer,
            batch_size: 1000,
            batch: Vec::with_capacity(1000),
        })
    }

    async fn insert_batch(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.batch.is_empty() {
            return Ok(());
        }

        let options = InsertManyOptions::builder().ordered(false).build();
        let result = self.collection.insert_many(&self.batch, options).await?;
        
        println!("Inserted {} documents", result.inserted_ids.len());
        self.batch.clear();
        Ok(())
    }

    fn transform_message(&self, payload: &[u8]) -> Result<ThreatLog, Box<dyn std::error::Error>> {
        let raw_log: HashMap<String, Value> = serde_json::from_slice(payload)?;
        
        let timestamp = raw_log
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let source_id = raw_log
            .get("source_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let mut hasher = DefaultHasher::new();
        source_id.hash(&mut hasher);
        let shard_key = hasher.finish() % 1000;

        let threat_log = ThreatLog {
            timestamp,
            meta: ThreatLogMeta {
                source_id,
                source_ip: raw_log
                    .get("source_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.0.0.0")
                    .to_string(),
                attack_type: raw_log
                    .get("attack_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                severity: raw_log
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("low")
                    .to_string(),
                shard_key,
            },
            fields: ThreatLogFields {
                raw: raw_log.get("raw").cloned().unwrap_or(Value::Null),
                score: raw_log
                    .get("score")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0),
                agent_votes: raw_log.get("agent_votes").cloned().unwrap_or(Value::Null),
            },
        };

        Ok(threat_log)
    }

    async fn consume_loop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut flush_interval = interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                msg = self.consumer.recv() => {
                    match msg {
                        Ok(m) => {
                            if let Some(payload) = m.payload() {
                                match self.transform_message(payload) {
                                    Ok(threat_log) => {
                                        self.batch.push(threat_log);
                                        
                                        if self.batch.len() >= self.batch_size {
                                            if let Err(e) = self.insert_batch().await {
                                                eprintln!("Batch insert error: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => eprintln!("Transform error: {}", e),
                                }
                            }
                        }
                        Err(e) => eprintln!("Kafka error: {}", e),
                    }
                }
                _ = flush_interval.tick() => {
                    if !self.batch.is_empty() {
                        if let Err(e) = self.insert_batch().await {
                            eprintln!("Periodic flush error: {}", e);
                        }
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut consumer = BulkIngestConsumer::new(
        "mongodb://mongos:27017",
        "kafka1:29092,kafka2:29092,kafka3:29092",
        "threat-logs",
    ).await?;

    println!("Starting Rust bulk ingest consumer...");
    consumer.consume_loop().await?;

    Ok(())
}