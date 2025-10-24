"""Cerebro - Security System of Record."""

from __future__ import annotations

import warnings

warnings.filterwarnings(
    "ignore",
    message="'crypt' is deprecated and slated for removal in Python 3.13",
    category=DeprecationWarning,
    module="passlib.utils",
)

__version__ = "0.1.0"
