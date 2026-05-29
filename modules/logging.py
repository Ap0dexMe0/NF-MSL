"""
logging.py — Colored logging setup for the NF-MSL project.
"""

from __future__ import annotations

import logging
from typing import Optional

try:
    import coloredlogs
    COLOREDLOGS_AVAILABLE = True
except ImportError:
    COLOREDLOGS_AVAILABLE = False


def setup_logger(
    name: str,
    level: int = logging.INFO,
    fmt: Optional[str] = None,
) -> logging.Logger:
    """Create and return a logger with optional colored output.

    If coloredlogs is installed, the logger will use colored output.
    Otherwise, falls back to standard logging with the specified format.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    if fmt is None:
        fmt = "%(name)s - %(levelname)s - %(message)s"

    if COLOREDLOGS_AVAILABLE:
        coloredlogs.install(
            level=level,
            fmt=fmt,
            logger=logger,
            reconfigure=True,
        )
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
        logger.setLevel(level)

    return logger