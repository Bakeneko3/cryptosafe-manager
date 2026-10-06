# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for CryptoSafe Manager.

Build:
    pyinstaller CryptoSafeManager.spec

Output:
    dist/CryptoSafeManager/CryptoSafeManager.exe

Notes:
    - Uses onedir mode (faster startup than onefile).
    - Bundles pyzbar's libzbar DLL when available.
    - Includes the tkinter, PIL, pystray, and cryptography hooks
      that PyInstaller ships with.
"""

import os
import sys
from pathlib import Path


block_cipher = None


# --- Locate pyzbar's native library, if present ----------------------- #

def _pyzbar_binaries():
    """
    Return a list of (source, dest_dir) tuples for pyzbar's DLL/SO.
    Returns an empty list if pyzbar (or its native library) is not
    available in the current environment.
    """
    try:
        import pyzbar
    except ImportError:
        return []

    pkg_dir = Path(pyzbar.__file__).parent

    # Common locations across platforms.
    candidates = [
        pkg_dir / "libzbar-64.dll",
        pkg_dir / "libzbar.dll",
        pkg_dir / "libzbar.so",
        pkg_dir / "libzbar.dylib",
    ]
    found = [(str(p), ".") for p in candidates if p.exists()]
    return found


binaries = _pyzbar_binaries()


# --- Analysis ---------------------------------------------------------- #

a = Analysis(
    ["run.py"],
    pathex=[str(Path.cwd())],
    binaries=binaries,
    datas=[],
    hiddenimports=[
        "pystray._win32",
        "pystray._base",
        "PIL._tkinter_finder",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tests",
        "pytest",
        "pytest_cov",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)


# --- EXE --------------------------------------------------------------- #

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CryptoSafeManager",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,   # GUI app: no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)


# --- COLLECT ----------------------------------------------------------- #

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CryptoSafeManager",
)