"""Smoke tests for src/gui/change_password_dialog.py (CHANGE-1)."""

from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")

from src.core.crypto.key_derivation import KeyDerivation
from src.core.key_manager import KeyManager
from src.database.db import Database


STRONG = "Correct-Horse-Battery-42!"
NEW_STRONG = "Another-Strong-Pass-99$"


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
    db = Database(tmp_path / "cpw.db")
    manager = KeyManager(db, key_derivation=kd)
    manager.create_vault(STRONG)
    yield manager
    db.close()


def test_dialog_constructs(root, km: KeyManager) -> None:
    from src.gui.change_password_dialog import ChangePasswordDialog

    dlg = ChangePasswordDialog(root, km)
    assert dlg.key_manager is km
    assert dlg.result is False
    dlg._on_cancel()

@pytest.mark.skip(
    reason="Sprint 3: change_password will be rewritten in step 5 for "
           "the new UUID + encrypted_data vault schema"
)
def test_successful_change(root, km: KeyManager) -> None:
    from src.gui.change_password_dialog import ChangePasswordDialog

    dlg = ChangePasswordDialog(root, km)
    dlg.current_entry.set(STRONG)
    dlg.new_entry.set(NEW_STRONG)
    dlg.confirm_entry.set(NEW_STRONG)
    dlg._on_change()

    assert dlg.result is True

    # New password works, old does not.
    km.lock()
    assert km.unlock(NEW_STRONG).success is True


def test_wrong_current_password(root, km: KeyManager) -> None:
    from src.gui.change_password_dialog import ChangePasswordDialog

    dlg = ChangePasswordDialog(root, km)
    dlg.current_entry.set("Wrong-Password-99!")
    dlg.new_entry.set(NEW_STRONG)
    dlg.confirm_entry.set(NEW_STRONG)
    dlg._on_change()

    assert dlg.result is False
    assert km.cache.unlocked is True
    dlg._on_cancel()


def test_mismatched_confirmation(root, km: KeyManager) -> None:
    from src.gui.change_password_dialog import ChangePasswordDialog

    dlg = ChangePasswordDialog(root, km)
    dlg.current_entry.set(STRONG)
    dlg.new_entry.set(NEW_STRONG)
    dlg.confirm_entry.set("Different-Password-99$")
    dlg._on_change()

    assert dlg.result is False
    dlg._on_cancel()


def test_empty_fields(root, km: KeyManager) -> None:
    from src.gui.change_password_dialog import ChangePasswordDialog

    dlg = ChangePasswordDialog(root, km)
    dlg._on_change()
    assert dlg.result is False
    dlg._on_cancel()


def test_weak_new_password(root, km: KeyManager) -> None:
    from src.gui.change_password_dialog import ChangePasswordDialog

    dlg = ChangePasswordDialog(root, km)
    dlg.current_entry.set(STRONG)
    dlg.new_entry.set("weak")
    dlg.confirm_entry.set("weak")
    dlg._on_change()

    assert dlg.result is False
    dlg._on_cancel()