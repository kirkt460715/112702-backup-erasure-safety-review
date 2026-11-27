"""兼容入口：审计实现位于 :mod:`audit`。

用法::

    python3 records_audit.py --format text
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit import *  # noqa: E402,F401,F403
from audit import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
