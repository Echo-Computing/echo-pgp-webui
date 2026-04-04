"""
PyInstaller spec for PGP Vault Desktop EXE
Run: pyinstaller desktop/pgpvault.spec
Output: desktop/dist/pgpvault/
"""

import sys
from pathlib import Path

block_cipher = None
# Hardcoded project root — PyInstaller doesn't provide __file__ in spec scope
SRC = Path(r'D:\pgp_publish\pgp_webui.py')
DIST = Path(r'D:\pgp_publish\desktop\dist')
WORK = Path(r'D:\pgp_publish\desktop\build')

a = Analysis(
    [str(SRC)],
    pathex=[],
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
    distpath=DIST,
    workpath=WORK,
)
