#!/usr/bin/env python3
"""Convenience launcher so the server can be run without installing it.

    .venv/bin/python3-capped run.py

Equivalent to ``python3 -m pktgen_mcp.server`` once the package is importable.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from pktgen_mcp.server import main  # noqa: E402

if __name__ == "__main__":
    main()
