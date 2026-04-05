"""
PyInstaller spec for PGP Vault Desktop EXE
Run: pyinstaller desktop/pgpvault.spec
Output: desktop/dist/pgpvault.exe

NOTE: Paths below are relative to the spec file location so any user
downloading the repo can build from their own machine without editing.
Replace TEMP_PGP_DIR, TEMP_PGP_DB, and TEMP_SENDER_ID with your actual
values BEFORE building if you want them hardcoded — otherwise the EXE
will auto-detect GPG and prompt for settings on first run.
"""

import sys
from pathlib import Path

# Resolve paths relative to THIS spec file (desktop/pgpvault.spec)
# so the build works from any clone location.
SPEC_DIR = Path(__file__).parent.resolve()
REPO_DIR = SPEC_DIR.parent

block_cipher = None

a = Analysis(
    [str(REPO_DIR / 'pgp_webui.py')],
    pathex=[str(REPO_DIR)],
    binaries=[],
    datas=[],
    hiddenimports=[
        'flask', 'flask_cors', 'markupsafe', 'jinja2', 'werkzeug',
        'itsdangerous', 'click', 'blinker', 'zeroconf', 'ifaddr',
    ],
    win_no_prefer_redirects=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='pgpvault',
    debug=False,
    strip=False,
    upx=True,
    console=True,
    icon=None,
    version=None,
    exclude_binaries=False,
    distpath=SPEC_DIR / 'dist',
    workpath=SPEC_DIR / 'build',
)
