#!/usr/bin/env python
"""
Entry point for CryptoSafe Manager.

Usage:
    python run.py

Equivalent to:
    python -m src.gui.main_window
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from src.gui.main_window import MainWindow
    except ImportError as exc:
        print(
            f"Failed to import CryptoSafe Manager: {exc}\n"
            "Make sure you are running from the project root and that "
            "dependencies are installed (`pip install -r requirements.txt`).",
            file=sys.stderr,
        )
        return 1

    app = MainWindow()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())