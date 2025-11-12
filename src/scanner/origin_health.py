from dataclasses import dataclass, asdict
from collections import defaultdict
from urllib.parse import urlparse
from asyncio import TimeoutError
import socket

HTTP_TIMEOUT_THRESHOLD = 3
TLS_TIMEOUT_THRESHOLD  = 2

@dataclass
class OriginHealth:
    http_forbidden: bool = False
    http_statuses: list[int] = None 
    http_timeout_count: int = 0

    tls_timeout_count: int = 0

    def __post_init__(self):
        if self.http_statuses is None:
            self.http_statuses = []

    @property
    def http_dead(self) -> bool:
        return self.http_timeout_count >= HTTP_TIMEOUT_THRESHOLD

    @property
    def tls_dead(self) -> bool:
        return self.tls_timeout_count >= TLS_TIMEOUT_THRESHOLD


_origin_health: dict[str, OriginHealth] = defaultdict(OriginHealth)

def _origin_key(url_or_origin: str) -> str:
    if "://" in url_or_origin:
        parsed = urlparse(url_or_origin)
        host = parsed.hostname or ""
        port = parsed.port or 443
        return f"{host}:{port}"
    return url_or_origin


def record_http_block(origin_or_url: str, status: int) -> None:
    key = _origin_key(origin_or_url)
    h = _origin_health[key]
    h.http_forbidden = True
    if status not in h.http_statuses:
        print(f"origin http block: {origin_or_url} -> ({status})")
        h.http_statuses.append(status)

def record_http_timeout(origin_or_url: str) -> None:
    key = _origin_key(origin_or_url)
    _origin_health[key].http_timeout_count += 1

def is_timeout_exc(e: Exception) -> bool:
    if e is None:
        return False
    msg = str(e).lower()
    return (
        isinstance(e, (TimeoutError, socket.timeout))
        or "timed out" in msg
        or "time-out" in msg
    )

def record_tls_timeout(origin_or_url: str, e: Exception = None) -> None:
    if e is None or not is_timeout_exc(e):
        return
    
    print(f"origin tls timeout: {origin_or_url}")
    key = _origin_key(origin_or_url)
    _origin_health[key].tls_timeout_count += 1

def should_run_http_modules(origin_or_url: str) -> bool:
    h = _origin_health[_origin_key(origin_or_url)]
    return not h.http_dead  

def should_run_tls_modules(origin_or_url: str) -> bool:
    h = _origin_health[_origin_key(origin_or_url)]
    return not h.tls_dead

def snapshot_origin_health() -> dict[str, dict]:
    return {k: asdict(v) for k, v in _origin_health.items()}

