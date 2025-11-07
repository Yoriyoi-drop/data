import asyncio
import pandas as pd
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from minio import Minio
import pyarrow as pa
import pyarrow.parquet as pq
import logging
from typing import List, Dict, Any, Optional, Tuple
import os
import tempfile
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ArchivalJob:
    def __init__(self, mongo_uri: str, minio_endpoint: str, access_key: str, secret_key: str):
        try:
            self.client = AsyncIOMotorClient(mongo_uri)
            self.db = self.client["infinite_security"]
            self.coll = self.db["threat_logs"]
            
            self.minio_client = Minio(
                minio_endpoint,
                access_key=access_key,
                secret_key=secret_key,
                secure=False
            )
            self.bucket = "infinite-security-archive"
            
            # Ensure bucket exists
            if not self.minio_client.bucket_exists(self.bucket):
                self.minio_client.make_bucket(self.bucket)
                
        except Exception as e:
            logger.error(f"Failed to initialize ArchivalJob: {e}")
            raise
    
    async def export_day_to_parquet(self, target_date: datetime) -> Optional[Tuple[str, str, int]]:
        """Export one day of logs to Parquet format"""
        try:
            start_time = target_date.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
            end_time = start_time + timedelta(days=1)
            
            logger.info(f"Exporting logs from {start_time} to {end_time}")
            
            # Query logs for the day with batch processing
            cursor = self.coll.find({
                "timestamp": {
                    "$gte": start_time,
                    "$lt": end_time
                }
            }).batch_size(1000)
            
            # Process in batches to avoid memory issues
            flattened = []
            async for doc in cursor:
                try:
                    flat_doc = {
                        "timestamp": doc.get("timestamp"),
                        "source_id": doc.get("meta", {}).get("source_id", "unknown"),
                        "source_ip": doc.get("meta", {}).get("source_ip", "0.0.0.0"),
                        "attack_type": doc.get("meta", {}).get("attack_type", "unknown"),
                        "severity": doc.get("meta", {}).get("severity", "low"),
                        "score": doc.get("fields", {}).get("score", 0.0),
                        "raw_data": str(doc.get("fields", {}).get("raw", {})),
                        "agent_votes": str(doc.get("fields", {}).get("agent_votes", {}))
                    }
                    flattened.append(flat_doc)
                except Exception as e:
                    logger.warning(f"Error processing document: {e}")
                    continue
            
            if not flattened:
                logger.info(f"No logs found for {target_date.date()}")
                return None
            
            # Create DataFrame and Parquet file
            df = pd.DataFrame(flattened)
            
            # Use secure temporary file
            with tempfile.NamedTemporaryFile(suffix='.parquet', delete=False) as tmp_file:
                local_path = tmp_file.name
            
            filename = f"threat_logs_{target_date.strftime('%Y_%m_%d')}.parquet"
            
            # Write Parquet
            table = pa.Table.from_pandas(df)
            pq.write_table(table, local_path, compression='snappy')
            
            logger.info(f"Created Parquet file: {local_path} ({len(flattened)} records)")
            return local_path, filename, len(flattened)
            
        except Exception as e:
            logger.error(f"Error exporting logs for {target_date.date()}: {e}")
            raise
    
    def upload_to_minio(self, local_path: str, filename: str, target_date: datetime):
        """Upload Parquet file to MinIO with date partitioning"""
        try:
            object_name = f"year={target_date.year}/month={target_date.month:02d}/day={target_date.day:02d}/{filename}"
            
            # Verify file exists before upload
            if not Path(local_path).exists():
                raise FileNotFoundError(f"Local file not found: {local_path}")
            
            self.minio_client.fput_object(
                self.bucket,
                object_name,
                local_path,
                content_type="application/octet-stream"
            )
            
            logger.info(f"Uploaded to MinIO: {object_name}")
            
        except Exception as e:
            logger.error(f"Error uploading to MinIO: {e}")
            raise
        finally:
            # Clean up local file
            try:
                if Path(local_path).exists():
                    os.remove(local_path)
            except Exception as e:
                logger.warning(f"Failed to remove local file {local_path}: {e}")
    
    async def delete_archived_logs(self, target_date: datetime, record_count: int):
        """Delete logs from MongoDB after successful archival"""
        try:
            start_time = target_date.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
            end_time = start_time + timedelta(days=1)
            
            result = await self.coll.delete_many({
                "timestamp": {
                    "$gte": start_time,
                    "$lt": end_time
                }
            })
            
            if result.deleted_count != record_count:
                logger.warning(f"Deleted {result.deleted_count} logs from MongoDB (expected: {record_count})")
            else:
                logger.info(f"Successfully deleted {result.deleted_count} logs from MongoDB")
                
        except Exception as e:
            logger.error(f"Error deleting archived logs: {e}")
            raise
    
    async def archive_old_logs(self, days_to_keep: int = 30):
        """Archive logs older than specified days"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            end_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            
            # Find the earliest log date to avoid infinite loop
            earliest_log = await self.coll.find_one(
                {}, sort=[("timestamp", 1)]
            )
            
            if not earliest_log:
                logger.info("No logs found to archive")
                return
                
            start_date = earliest_log["timestamp"].replace(hour=0, minute=0, second=0, microsecond=0)
            current_date = max(start_date, cutoff_date.replace(hour=0, minute=0, second=0, microsecond=0))
            
            archived_count = 0
            failed_count = 0
            
            while current_date < end_date:
                try:
                    result = await self.export_day_to_parquet(current_date)
                    
                    if result:
                        local_path, filename, record_count = result
                        self.upload_to_minio(local_path, filename, current_date)
                        await self.delete_archived_logs(current_date, record_count)
                        archived_count += record_count
                        logger.info(f"Successfully archived {record_count} logs for {current_date.date()}")
                    
                except Exception as e:
                    logger.error(f"Error archiving {current_date.date()}: {e}")
                    failed_count += 1
                    # Continue with next date instead of breaking
                finally:
                    current_date += timedelta(days=1)
            
            logger.info(f"Archival completed: {archived_count} logs archived, {failed_count} days failed")
            
        except Exception as e:
            logger.error(f"Critical error in archive_old_logs: {e}")
            raise
    
    async def get_storage_stats(self):
        """Get current storage statistics"""
        try:
            total_docs = await self.coll.count_documents({})
            
            # Get size by day for last 7 days
            stats = []
            for i in range(7):
                date = datetime.now(timezone.utc) - timedelta(days=i)
                start_time = date.replace(hour=0, minute=0, second=0, microsecond=0)
                end_time = start_time + timedelta(days=1)
                
                count = await self.coll.count_documents({
                    "timestamp": {"$gte": start_time, "$lt": end_time}
                })
                
                stats.append({
                    "date": date.date(),
                    "count": count
                })
            
            logger.info(f"Total documents: {total_docs}")
            for stat in stats:
                logger.info(f"{stat['date']}: {stat['count']} logs")
                
        except Exception as e:
            logger.error(f"Error getting storage stats: {e}")
            raise

async def main():
    try:
        # Get credentials from environment variables
        mongo_uri = os.getenv("MONGO_URI", "mongodb://mongos:27017")
        minio_endpoint = os.getenv("MINIO_ENDPOINT", "minio:9000")
        access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
        days_to_keep = int(os.getenv("DAYS_TO_KEEP", "30"))
        
        archival = ArchivalJob(
            mongo_uri=mongo_uri,
            minio_endpoint=minio_endpoint,
            access_key=access_key,
            secret_key=secret_key
        )
        
        # Get current stats
        await archival.get_storage_stats()
        
        # Archive logs older than specified days
        await archival.archive_old_logs(days_to_keep=days_to_keep)
        
        logger.info("Archival job completed successfully")
        
    except Exception as e:
        logger.error(f"Archival job failed: {e}")
        raise
    finally:
        # Ensure MongoDB connection is closed
        if 'archival' in locals():
            archival.client.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Archival job interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        exit(1)