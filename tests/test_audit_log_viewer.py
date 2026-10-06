"""Smoke tests for src/gui/audit_log_viewer.py (GUI-1..GUI-3)."""

from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")

from src.core.audit.audit_logger import AuditLogger
from src.core.crypto.key_derivation import KeyDerivation
from src.core.events import EventBus
from src.core.key_manager import KeyManager
from src.database.db import Database


STRONG = "Correct-Horse-Battery-42!"


@pytest.fixture(scope="session")
def _tk_root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"no display available: {exc}")
    r.withdraw()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def root(_tk_root):
    yield _tk_root


@pytest.fixture
def fast_kd() -> KeyDerivation:
    return KeyDerivation(
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
        hash_len=32,
        salt_len=16,
        pbkdf2_iterations=1000,
    )


@pytest.fixture
def db(tmp_path: Path) -> Database:
    d = Database(tmp_path / "viewer.db")
    yield d
    d.close()


@pytest.fixture
def km(db: Database, fast_kd: KeyDerivation) -> KeyManager:
    m = KeyManager(db, key_derivation=fast_kd)
    m.create_vault(STRONG)
    return m


@pytest.fixture
def populated(db: Database, km: KeyManager) -> Database:
    bus = EventBus()
    logger = AuditLogger(db, bus, key_manager=km)
    logger.log_event("test_one", source="test", severity="INFO")
    logger.log_event("test_two", source="test", severity="WARN")
    return db


def test_viewer_constructs(root, populated: Database, km: KeyManager) -> None:
    from src.gui.audit_log_viewer import AuditLogViewer

    v = AuditLogViewer(root, populated, km)
    assert v is not None
    v.destroy()


def test_viewer_loads_entries(root, populated: Database, km: KeyManager) -> None:
    from src.gui.audit_log_viewer import AuditLogViewer

    v = AuditLogViewer(root, populated, km)
    assert len(v._entries) >= 3  # genesis + 2
    v.destroy()


def test_viewer_filter_by_severity(root, populated: Database, km: KeyManager) -> None:
    from src.gui.audit_log_viewer import AuditLogViewer

    v = AuditLogViewer(root, populated, km)
    v.severity_var.set("WARN")
    v._apply_filter()

    rows = v.table.get_children()
    # At least "test_two" is WARN.
    values = [v.table.item(r)["values"] for r in rows]
    assert any("test_two" in str(r) for r in values)
    v.destroy()


def test_viewer_filter_by_type(root, populated: Database, km: KeyManager) -> None:
    from src.gui.audit_log_viewer import AuditLogViewer

    v = AuditLogViewer(root, populated, km)
    v.type_var.set("test_one")
    v._apply_filter()

    rows = v.table.get_children()
    assert len(rows) == 1
    v.destroy()


def test_viewer_search(root, populated: Database, km: KeyManager) -> None:
    from src.gui.audit_log_viewer import AuditLogViewer

    v = AuditLogViewer(root, populated, km)
    v.search_var.set("test_two")
    v._apply_filter()

    rows = v.table.get_children()
    assert len(rows) >= 1
    v.destroy()


def test_viewer_verify_report_set(root, populated: Database, km: KeyManager) -> None:
    from src.gui.audit_log_viewer import AuditLogViewer

    v = AuditLogViewer(root, populated, km)
    report = v._verifier.verify_all()
    assert report.verified is True
    v.destroy()