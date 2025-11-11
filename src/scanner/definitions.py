from __future__  import annotations

import asyncio
import datetime
from typing import Optional
from pathlib import Path
from aiohttp import ClientResponse

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
    

_rate_log_path: Optional[Path] = None
_rate_log_lock: Optional[asyncio.Lock] = None

def init_rate_limiter_logger(output_dir: Optional[Path] = None) -> None:
    global _rate_log_path, _rate_log_lock
    _rate_log_lock = asyncio.Lock()
    if output_dir is None:
        _rate_log_path = None
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    _rate_log_path = output_dir / f"rate_limit_{ts}.log"


async def log_rate_limit(origin: str, response: ClientResponse, module: str) -> None:
    global _rate_log_path, _rate_log_lock

    if response.status not in (429, 403, 503):
        return

    msg = f"[RateLimit] {module} -> {origin} ({response.status})"
    print(msg)

    if not _rate_log_path:
        return  # disabled if not initialized

    if _rate_log_lock is None:
        _rate_log_lock = asyncio.Lock()

    async with _rate_log_lock:
        async with await asyncio.to_thread(open, _rate_log_path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")