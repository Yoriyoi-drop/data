"""
Backup Manager for PostgreSQL

Provides utilities to create daily backups of the PostgreSQL database, store them in a
mounted volume, and rotate old backups. The implementation uses `pg_dump` and
expects the `POSTGRES_*` environment variables to be set (as in the Docker
compose file).
"""

import os
import subprocess
import datetime
import pathlib
import logging
from typing import List

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class PostgresBackupManager:
    def __init__(self, backup_dir: str = "/backups"):
        self.backup_dir = pathlib.Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.db_name = os.getenv("POSTGRES_DB", "ai_security")
        self.db_user = os.getenv("POSTGRES_USER", "admin")
        self.db_password = os.getenv("POSTGRES_PASSWORD", "admin")
        self.host = os.getenv("POSTGRES_HOST", "postgres")
        self.port = os.getenv("POSTGRES_PORT", "5432")
        # Ensure pg_dump can authenticate via env vars
        os.environ["PGPASSWORD"] = self.db_password

    def _backup_file_name(self) -> str:
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        return f"{self.db_name}_{timestamp}.sql.gz"

    def create_backup(self) -> pathlib.Path:
        """Create a compressed dump of the database.

        Returns the path to the created backup file.
        """
        backup_path = self.backup_dir / self._backup_file_name()
        cmd = [
            "pg_dump",
            "-h", self.host,
            "-p", self.port,
            "-U", self.db_user,
            "-d", self.db_name,
            "-Fc",  # custom format (compressed)
            "-f", str(backup_path),
        ]
        logger.info(f"Running backup command: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info(f"Backup created at {backup_path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Backup failed: {e.stderr.decode()}")
            raise
        return backup_path

    def list_backups(self) -> List[pathlib.Path]:
        """Return a list of backup files sorted newest first."""
        backups = sorted(self.backup_dir.glob("*.sql.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
        return backups

    def prune_backups(self, keep_latest: int = 7) -> None:
        """Delete old backups, keeping only the newest *keep_latest* files.
        """
        backups = self.list_backups()
        to_delete = backups[keep_latest:]
        for path in to_delete:
            try:
                path.unlink()
                logger.info(f"Deleted old backup: {path}")
            except Exception as exc:
                logger.warning(f"Failed to delete {path}: {exc}")

    def restore_backup(self, backup_file: str) -> None:
        """Restore a backup file into the database.

        **Warning**: This will drop the existing database and replace it with the
        contents of the backup.
        """
        backup_path = pathlib.Path(backup_file)
        if not backup_path.is_file():
            raise FileNotFoundError(f"Backup file not found: {backup_file}")
        cmd = [
            "pg_restore",
            "-h", self.host,
            "-p", self.port,
            "-U", self.db_user,
            "-d", self.db_name,
            "-c",  # clean (drop) before restore
            str(backup_path),
        ]
        logger.info(f"Restoring backup from {backup_path}")
        subprocess.run(cmd, check=True)
        logger.info("Restore completed")

# Global instance for convenience
backup_manager = PostgresBackupManager()
