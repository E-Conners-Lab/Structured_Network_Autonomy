"""Shared rate limiter instance for use across route modules.

The limiter is created once and imported by both app.py (to attach to app.state
and register the exception handler) and route files (to use @limiter.limit()).
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
