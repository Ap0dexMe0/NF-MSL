"""
logging.py — Centralized colored logging for the NF-MSL project.

All loggers in this project propagate to the root logger, which is configured
once with coloredlogs. Named loggers (platform runners, MSL modules) only need
their level set — they inherit formatting and color from the root handler.

Set the MSL_DEBUG=1 environment variable to enable DEBUG-level output.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

try:
    import coloredlogs
    _COLOREDLOGS = True
except ImportError:
    _COLOREDLOGS = False

_ROOT_CONFIGURED = False

# ---------------------------------------------------------------------------
# Color scheme
# ---------------------------------------------------------------------------

LEVEL_STYLES: dict = {
    "debug":    {"color": "blue"},
    "info":     {"color": "green"},
    "warning":  {"color": "yellow",  "bold": True},
    "error":    {"color": "red",     "bold": True},
    "critical": {"color": "magenta", "bold": True},
}

FIELD_STYLES: dict = {
    "name":      {"color": "cyan",  "bold": True},
    "levelname": {"color": "white", "bold": True},
    "asctime":   {"color": "white"},
    "message":   {},
}

DEFAULT_FMT = "%(name)s - %(levelname)s - %(message)s"

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup_logger(
    name: str,
    level: int = logging.INFO,
    fmt: Optional[str] = None,
) -> logging.Logger:
    """Return a named logger, configuring the root handler on first call.

    All loggers propagate to a single root handler so that module-level
    loggers (``_log = logging.getLogger(__name__)``) automatically inherit
    the same coloredlogs formatting without extra setup.
    """
    global _ROOT_CONFIGURED

    if not _ROOT_CONFIGURED:
        root_level = logging.DEBUG if os.getenv("MSL_DEBUG") else logging.INFO
        _fmt = fmt or DEFAULT_FMT

        if _COLOREDLOGS:
            coloredlogs.install(
                level=root_level,
                fmt=_fmt,
                level_styles=LEVEL_STYLES,
                field_styles=FIELD_STYLES,
            )
        else:
            logging.basicConfig(level=root_level, format=_fmt)

        _ROOT_CONFIGURED = True

    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger
