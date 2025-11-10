from __future__ import annotations
import asyncio
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import ClientTimeout

from scanner.modules.export import ModuleExport
from scanner.definitions import get_limiter

_ONE_YEAR = 31536000

def _parse_hsts(value: str) -> dict:
    out = {"max_age": -1, "include_subdomains": False, "preload": False}
    if not value:
        return out
    parts = [p.strip() for p in value.split(";")]
    for p in parts:
        if not p:
            continue
        low = p.lower()
        if low.startswith("max-age"):
            kv = p.split("=", 1)
            if len(kv) == 2:
                try:
                    out["max_age"] = int(kv[1].strip())
                except ValueError:
                    pass
        elif low == "includesubdomains":
            out["include_subdomains"] = True
        elif low == "preload":
            out["preload"] = True
    return out


@dataclass
class HSTSRow:
    origin: str
    redirected_to_https: bool = False
    redirect_status: int | None = None
    redirect_location: str = ""
    https_ok: bool = False
    has_hsts: bool = False
    max_age_ge_1yr: bool = False
    include_subdomains: bool = False
    preload: bool = False
    error: str = ""


class HSTSModule(ModuleExport):
    def __init__(self, *, session: aiohttp.ClientSession, timeout_s: int = 10, limiter: Optional[asyncio.Semaphore] = None):
        self._session = session
        self._timeout = ClientTimeout(total=timeout_s)
        self._results: Dict[str, HSTSRow] = {}
        self._limiter = limiter or get_limiter()

    def name(self) -> str: return "hsts"
    def scope(self) -> str: return "origin"

    def results(self) -> dict[str, dict]:
        return {k: asdict(v) for k, v in self._results.items()}

    async def run(self, origins: List[str]) -> None:
        await asyncio.gather(*(self._scan_one(o) for o in origins))

    async def _scan_one(self, origin: str) -> None:
        row = HSTSRow(origin=origin)

        http_url = f"http://{origin}/"
        https_target = f"https://{origin}/"

        try:
            async with self._limiter:
                async with self._session.get(http_url, allow_redirects=False, timeout=self._timeout) as r:
                    row.redirect_status = r.status
                    loc = r.headers.get("Location", "")
                    row.redirect_location = loc

                    if 300 <= r.status < 400 and loc:
                        target = loc if urlparse(loc).scheme else urljoin(http_url, loc)
                        if urlparse(target).scheme.lower() == "https":
                            row.redirected_to_https = True
                            https_target = target
        except Exception as e:
            row.error = f"http_probe: {e}"

        try:
            async with self._session.get(https_target, timeout=self._timeout) as r:
                row.https_ok = (200 <= r.status < 600)
                hsts_val = r.headers.get("Strict-Transport-Security", "")
                if hsts_val:
                    parsed = _parse_hsts(hsts_val)
                    row.has_hsts = True
                    row.max_age_ge_1yr = (
                        parsed["max_age"] >= _ONE_YEAR if parsed["max_age"] >= 0 else False
                    )
                    row.include_subdomains = parsed["include_subdomains"]
                    row.preload = parsed["preload"]
        except Exception as e:
            row.error = (row.error + " | " if row.error else "") + f"https_probe: {e}"

        self._results[origin] = row
