from src.core.state_manager import StateManager


def test_state_starts_locked():
    manager = StateManager()

    assert manager.is_locked()


def test_unlock_changes_state():
    manager = StateManager()

    manager.unlock()

    assert not manager.is_locked()
    assert manager.state.last_activity is not None


def test_lock_clears_clipboard():
    manager = StateManager()

    manager.unlock()
    manager.set_clipboard_content(b"secret")

    manager.lock()

    assert manager.is_locked()
    assert manager.get_clipboard_content() is None
    assert manager.state.clipboard_cleared_at is not None


def test_clipboard_content_can_be_set_and_cleared():
    manager = StateManager()

    manager.set_clipboard_content(b"secret")

    assert manager.get_clipboard_content() == b"secret"

    manager.clear_clipboard()

    assert manager.get_clipboard_content() is None