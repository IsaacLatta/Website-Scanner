from __future__  import annotations

import asyncio
from typing import Optional
from pathlib import Path

# Unlimited for tests
DEFAULT_MAX_CONCURRENCY = 10_000 

PROJECT_ROOT=Path(__file__).resolve().parents[2]

_g_limiter: Optional[asyncio.Semaphore] = None

def init_global_limiter(max_concurrency: int) -> None:
    if max_concurrency <= 0:
        raise ValueError("max_concurrency cannot be negative.")
    global _g_limiter
    _g_limiter = asyncio.Semaphore(max_concurrency)


def get_limiter() -> asyncio.Semaphore:
    global _g_limiter
    if _g_limiter is None:
        _g_limiter = asyncio.Semaphore(DEFAULT_MAX_CONCURRENCY)
    return _g_limiter
    