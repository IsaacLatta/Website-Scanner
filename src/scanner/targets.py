from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Set

_DEFAULT_HTTPS_PORT = 443
_DEFAULT_HTTP_PORT = 80

@dataclass
class ScanTargets:
    origins: List[str]
    uris: List[str]


def _normalize_origin(host: str, scheme: str, port: int | None) -> str:
    if port is None:
        return host

    if scheme == "https" and port == _DEFAULT_HTTPS_PORT:
        return host
    if scheme == "http" and port == _DEFAULT_HTTP_PORT:
        return host

    return f"{host}:{port}"


def clean_domains(domains: List[str]) -> list[str]:
    return [
        d.strip().replace(" ", "").replace("\n", "").replace("\r", "")
        for d in domains
    ]


def build_scan_targets(items: List[str]) -> ScanTargets:
    raw_items = clean_domains(items)

    origins: Set[str] = set()
    uris: Set[str] = set()

    for raw in raw_items:
        if not raw:
            continue

        s = raw.strip()
        if not s:
            continue

        if "://" not in s:
            candidate = "https://" + s
        else:
            candidate = s

        parsed = urlparse(candidate)
        if not parsed.hostname:
            continue

        scheme = parsed.scheme or "https"
        host = parsed.hostname.lower()
        port = parsed.port

        origin = _normalize_origin(host, scheme, port)
        origins.add(origin)

        if port is not None:
            netloc = f"{host}:{port}"
        else:
            netloc = host

        normalized_parsed = parsed._replace(netloc=netloc)
        uri = normalized_parsed.geturl()
        uris.add(uri)

    return ScanTargets(
        origins=sorted(origins),
        uris=sorted(uris),
    )
