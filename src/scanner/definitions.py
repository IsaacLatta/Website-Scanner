from __future__  import annotations

import asyncio
import datetime
import random
from urllib.parse import urlparse
from typing import Optional
from pathlib import Path
from aiohttp import ClientResponse
from contextlib import asynccontextmanager
from collections import defaultdict

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


def always_include_headers() -> dict[str, str]:
    """
    Return a set of default headers that make our HTTP requests
    look more like real browser traffic.
    These are applied on every GET/HEAD request unless overridden.
    """
    return {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/119.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
        "DNT": "1",
        "Referer": "https://www.google.com/",
    }

async def sample_noise(min_delay: float = 0.1, max_delay: float = 0.5) -> None:
    """
    Sleep for a random duration between min_delay and max_delay seconds.
    Used to break deterministic request patterns that may trigger WAFs.
    """
    await asyncio.sleep(random.uniform(min_delay, max_delay))

_per_host_locks: dict[str, asyncio.Semaphore] = {}
_per_host_global_lock = asyncio.Lock()
_HOST_SEM_LIMIT = None
_DEFAULT_HOST_SEM_LIMIT = 5

def init_host_semaphore(limit: int):
    global _HOST_SEM_LIMIT
    _HOST_SEM_LIMIT = limit

async def _get_host_semaphore(host: str) -> asyncio.Semaphore:
    async with _per_host_global_lock:
        sem = _per_host_locks.get(host)
        if sem is None:
            sem = asyncio.Semaphore(_HOST_SEM_LIMIT or _DEFAULT_HOST_SEM_LIMIT)
            _per_host_locks[host] = sem
        return sem

@asynccontextmanager
async def host_semaphore(url: str):
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc or url
    sem = await _get_host_semaphore(host)
    async with sem:
        yield

# @asynccontextmanager
# async def acquire_global_and_host(url: str):
#     global_sem = get_limiter()
#     parsed = urlparse(url)
#     host = parsed.hostname or parsed.netloc or url
#     host_sem = await _get_host_semaphore(host)

#     async with global_sem, host_sem:
#         yield

@asynccontextmanager
async def acquire_global_and_host(url: str):
    global _g_limiter
    if _g_limiter is None:
        _g_limiter = asyncio.Semaphore(DEFAULT_MAX_CONCURRENCY)

    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc or url
    sem = await _get_host_semaphore(host)

    await _g_limiter.acquire()
    await sem.acquire()
    try:
        yield
    finally:
        sem.release()
        _g_limiter.release()
