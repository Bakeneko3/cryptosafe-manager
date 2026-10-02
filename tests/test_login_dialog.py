"""Smoke tests for src/gui/login_dialog.py (AUTH-1)."""

from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")

from src.core.crypto.key_derivation import KeyDerivation
from src.core.key_manager import KeyManager
from src.database.db import Database


STRONG = "Correct-Horse-Battery-42!"


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    r.withdraw()
    yield r
    r.destroy()


@pytest.fixture
def km(tmp_path: Path) -> KeyManager:
    kd = KeyDerivation(
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
        hash_len=32,
        salt_len=16,
        pbkdf2_iterations=1000,
    )
    db = Database(tmp_path / "login.db")
    manager = KeyManager(db, key_derivation=kd)
    manager.create_vault(STRONG)
    manager.lock()
    yield manager
    db.close()


def test_dialog_constructs_without_error(root, km: KeyManager) -> None:
    from src.gui.login_dialog import LoginDialog

    dlg = LoginDialog(root, km)
    assert dlg.key_manager is km
    assert dlg.result is False
    dlg._on_cancel()


def test_successful_unlock_sets_result_true(root, km: KeyManager) -> None:
    from src.gui.login_dialog import LoginDialog

    dlg = LoginDialog(root, km)
    dlg.password_entry.set(STRONG)
    dlg._on_submit()

    assert dlg.result is True
    assert km.cache.unlocked is True


def test_wrong_password_keeps_dialog_open(root, km: KeyManager) -> None:
    from src.gui.login_dialog import LoginDialog

    dlg = LoginDialog(root, km)
    dlg.password_entry.set("Wrong-Password-99!")
    dlg._on_submit()

    assert dlg.result is False
    assert km.cache.unlocked is False
    dlg._on_cancel()


def test_cancel_sets_result_false(root, km: KeyManager) -> None:
    from src.gui.login_dialog import LoginDialog

    dlg = LoginDialog(root, km)
    dlg._on_cancel()
    assert dlg.result is False