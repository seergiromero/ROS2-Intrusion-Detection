"""Pytest bootstrap for the standalone baseline capture tool.

Makes the in-tree packages importable so tests can exercise both the capture
tool and the rids_introspector / rids_detector modules it depends on, even when
the workspace has not been installed / sourced.
"""

import sys
from pathlib import Path

_WS_ROOT = Path(__file__).resolve().parent.parent

for sub in ("scripts", "rids_introspector", "rids_detector"):
    path = _WS_ROOT / sub
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
