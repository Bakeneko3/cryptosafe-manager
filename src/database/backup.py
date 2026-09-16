from pathlib import Path


class BackupManager:
    """Placeholder for database backup and restore functionality."""

    def backup(self, source: str | Path, destination: str | Path) -> None:
        raise NotImplementedError(
            "Database backup will be implemented in Sprint 8."
        )

    def restore(self, source: str | Path, destination: str | Path) -> None:
        raise NotImplementedError(
            "Database restore will be implemented in Sprint 8."
        )