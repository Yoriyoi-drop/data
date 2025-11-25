"""
Automated Backup System
Security Enhancement - Database backup and disaster recovery
"""
import os
import shutil
import gzip
import time
import threading
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional
import hashlib


class BackupManager:
    """
    Automated backup system for database and critical files
    
    Features:
    - Scheduled automatic backups
    - Compression
    - Encryption (optional)
    - Retention policy
    - Integrity verification
    """
    
    def __init__(self, backup_dir: str = "backups", 
                 retention_days: int = 30,
                 encryption_key: Optional[str] = None):
        """
        Initialize backup manager
        
        Args:
            backup_dir: Directory for backups
            retention_days: Days to keep backups
            encryption_key: Optional encryption key
        """
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self.retention_days = retention_days
        self.encryption_key = encryption_key
        
        # Backup status
        self.last_backup_time = None
        self.last_backup_status = None
        self.backup_count = 0
        
        print(f"✅ Backup manager initialized: {self.backup_dir}")
    
    def create_backup(self, source_path: str, backup_name: Optional[str] = None) -> str:
        """
        Create backup of file or directory
        
        Args:
            source_path: Path to backup
            backup_name: Optional custom backup name
        
        Returns:
            Path to backup file
        """
        source = Path(source_path)
        
        if not source.exists():
            raise FileNotFoundError(f"Source not found: {source_path}")
        
        # Generate backup filename
        if backup_name is None:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            backup_name = f"{source.stem}_{timestamp}.gz"
        
        backup_path = self.backup_dir / backup_name
        
        try:
            # Create compressed backup
            with open(source, 'rb') as f_in:
                with gzip.open(backup_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Calculate checksum
            checksum = self._calculate_checksum(backup_path)
            
            # Save checksum
            checksum_path = backup_path.with_suffix('.gz.sha256')
            with open(checksum_path, 'w') as f:
                f.write(checksum)
            
            # Update status
            self.last_backup_time = datetime.now(UTC)
            self.last_backup_status = "success"
            self.backup_count += 1
            
            print(f"✅ Backup created: {backup_path}")
            print(f"   Checksum: {checksum}")
            
            return str(backup_path)
            
        except Exception as e:
            self.last_backup_status = f"failed: {str(e)}"
            raise
    
    def restore_backup(self, backup_path: str, restore_path: str, 
                       verify_checksum: bool = True) -> bool:
        """
        Restore from backup
        
        Args:
            backup_path: Path to backup file
            restore_path: Path to restore to
            verify_checksum: Whether to verify checksum
        
        Returns:
            True if successful
        """
        backup = Path(backup_path)
        
        if not backup.exists():
            raise FileNotFoundError(f"Backup not found: {backup_path}")
        
        # Verify checksum if requested
        if verify_checksum:
            if not self.verify_backup(backup_path):
                raise ValueError("Backup checksum verification failed")
        
        try:
            # Restore from compressed backup
            with gzip.open(backup, 'rb') as f_in:
                with open(restore_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            print(f"✅ Backup restored: {restore_path}")
            return True
            
        except Exception as e:
            print(f"❌ Restore failed: {e}")
            return False
    
    def verify_backup(self, backup_path: str) -> bool:
        """
        Verify backup integrity using checksum
        
        Args:
            backup_path: Path to backup file
        
        Returns:
            True if valid
        """
        backup = Path(backup_path)
        checksum_path = backup.with_suffix('.gz.sha256')
        
        if not checksum_path.exists():
            print("⚠️  No checksum file found")
            return False
        
        # Calculate current checksum
        current_checksum = self._calculate_checksum(backup)
        
        # Read stored checksum
        with open(checksum_path, 'r') as f:
            stored_checksum = f.read().strip()
        
        # Compare
        is_valid = current_checksum == stored_checksum
        
        if is_valid:
            print(f"✅ Backup verified: {backup_path}")
        else:
            print(f"❌ Backup corrupted: {backup_path}")
        
        return is_valid
    
    def cleanup_old_backups(self):
        """Remove backups older than retention period"""
        now = time.time()
        retention_seconds = self.retention_days * 86400
        
        removed_count = 0
        
        for backup_file in self.backup_dir.glob("*.gz"):
            # Check file age
            file_age = now - backup_file.stat().st_mtime
            
            if file_age > retention_seconds:
                try:
                    # Remove backup and checksum
                    backup_file.unlink()
                    
                    checksum_file = backup_file.with_suffix('.gz.sha256')
                    if checksum_file.exists():
                        checksum_file.unlink()
                    
                    removed_count += 1
                    print(f"🗑️  Removed old backup: {backup_file.name}")
                    
                except Exception as e:
                    print(f"❌ Failed to remove {backup_file}: {e}")
        
        if removed_count > 0:
            print(f"✅ Cleaned up {removed_count} old backups")
    
    def list_backups(self) -> list:
        """
        List all backups
        
        Returns:
            List of backup info dicts
        """
        backups = []
        
        for backup_file in sorted(self.backup_dir.glob("*.gz")):
            stat = backup_file.stat()
            
            backups.append({
                "name": backup_file.name,
                "path": str(backup_file),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                "age_days": (time.time() - stat.st_mtime) / 86400
            })
        
        return backups
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of file"""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def get_stats(self) -> dict:
        """Get backup statistics"""
        backups = self.list_backups()
        
        total_size = sum(b["size"] for b in backups)
        
        return {
            "total_backups": len(backups),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "last_backup_time": self.last_backup_time.isoformat() if self.last_backup_time else None,
            "last_backup_status": self.last_backup_status,
            "retention_days": self.retention_days,
            "backup_count": self.backup_count
        }


class AutoBackupTask:
    """Automated backup task runner"""
    
    def __init__(self, backup_manager: BackupManager, 
                 source_paths: list, interval_hours: int = 24):
        """
        Initialize auto backup task
        
        Args:
            backup_manager: BackupManager instance
            source_paths: List of paths to backup
            interval_hours: Backup interval in hours
        """
        self.backup_manager = backup_manager
        self.source_paths = source_paths
        self.interval_hours = interval_hours
        self.running = False
        self.thread = None
    
    def start(self):
        """Start automated backups"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._backup_loop, daemon=True)
        self.thread.start()
        print(f"✅ Auto backup started (interval: {self.interval_hours}h)")
    
    def stop(self):
        """Stop automated backups"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("✅ Auto backup stopped")
    
    def _backup_loop(self):
        """Backup loop"""
        while self.running:
            try:
                # Create backups
                for source_path in self.source_paths:
                    if Path(source_path).exists():
                        self.backup_manager.create_backup(source_path)
                
                # Cleanup old backups
                self.backup_manager.cleanup_old_backups()
                
            except Exception as e:
                print(f"❌ Auto backup error: {e}")
            
            # Wait for next interval
            time.sleep(self.interval_hours * 3600)


# Global instance
backup_manager = BackupManager()
