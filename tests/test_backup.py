import pytest

from src.database.backup import BackupManager


def test_backup_is_not_implemented():
    manager = BackupManager()

    with pytest.raises(NotImplementedError):
        manager.backup("source.db", "backup.db")


def test_restore_is_not_implemented():
    manager = BackupManager()

    with pytest.raises(NotImplementedError):
        manager.restore("backup.db", "source.db")