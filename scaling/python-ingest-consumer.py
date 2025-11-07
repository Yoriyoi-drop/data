import asyncio
import json
import time
from datetime import datetime
from typing import List, Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient
from kafka import KafkaConsumer
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BulkIngestConsumer:
    def __init__(self, mongo_uri: str, kafka_brokers: List[str], topic: str):
        self.client = AsyncIOMotorClient(mongo_uri, maxPoolSize=200)
        self.db = self.client["infinite_security"]
        self.coll = self.db["threat_logs"]
        self.consumer = KafkaConsumer(
            topic,
            bootstrap_servers=kafka_brokers,
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            auto_offset_reset='latest',
            enable_auto_commit=True,
            group_id='ingest-workers',
            max_poll_records=2000,
            fetch_max_wait_ms=500
        )
        self.batch_size = 1000
        self.flush_interval = 0.5
        self.batch = []
        self.last_flush = time.time()
        
    async def insert_batch(self, batch: List[Dict[str, Any]]):
        if not batch:
            return
        
        try:
            # Transform to time-series format
            docs = []
            for item in batch:
                doc = {
                    "timestamp": datetime.fromisoformat(item.get("timestamp", datetime.utcnow().isoformat())),
                    "meta": {
                        "source_id": item.get("source_id", "unknown"),
                        "source_ip": item.get("source_ip", "0.0.0.0"),
                        "attack_type": item.get("attack_type", "unknown"),
                        "severity": item.get("severity", "low"),
                        "shard_key": hash(item.get("source_id", "")) % 1000
                    },
                    "fields": {
                        "raw": item.get("raw", {}),
                        "score": item.get("score", 0.0),
                        "agent_votes": item.get("agent_votes", {})
                    }
                }
                docs.append(doc)
            
            result = await self.coll.insert_many(docs, ordered=False)
            logger.info(f"Inserted {len(result.inserted_ids)} documents")
            
        except Exception as e:
            logger.error(f"Insert error: {e}")
            # Could implement retry logic or dead letter queue here
    
    async def should_flush(self) -> bool:
        return (len(self.batch) >= self.batch_size or 
                time.time() - self.last_flush > self.flush_interval)
    
    async def flush_batch(self):
        if self.batch:
            await self.insert_batch(self.batch)
            self.batch = []
            self.last_flush = time.time()
    
    async def consume_loop(self):
        logger.info("Starting consumer loop")
        
        while True:
            try:
                # Poll messages
                msg_pack = self.consumer.poll(timeout_ms=100)
                
                for tp, messages in msg_pack.items():
                    for message in messages:
                        self.batch.append(message.value)
                        
                        if await self.should_flush():
                            await self.flush_batch()
                
                # Periodic flush even if batch not full
                if time.time() - self.last_flush > self.flush_interval:
                    await self.flush_batch()
                    
            except Exception as e:
                logger.error(f"Consumer error: {e}")
                await asyncio.sleep(1)

async def main():
    consumer = BulkIngestConsumer(
        mongo_uri="mongodb://mongos:27017",
        kafka_brokers=["kafka1:29092", "kafka2:29092", "kafka3:29092"],
        topic="threat-logs"
    )
    
    # Setup time-series collection if not exists
    try:
        await consumer.db.create_collection("threat_logs", {
            "timeseries": {
                "timeField": "timestamp",
                "metaField": "meta",
                "granularity": "seconds"
            },
            "expireAfterSeconds": 60*60*24*30  # 30 days TTL
        })
        logger.info("Created time-series collection")
    except Exception as e:
        logger.info(f"Collection exists or error: {e}")
    
    # Create indexes
    await consumer.coll.create_index([("meta.source_id", 1)])
    await consumer.coll.create_index([("meta.attack_type", 1), ("meta.severity", 1), ("timestamp", -1)])
    
    await consumer.consume_loop()

if __name__ == "__main__":
    asyncio.run(main())