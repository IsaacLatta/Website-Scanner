from __future__ import annotations
import asyncio
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
import asyncio
import aiohttp
from aiohttp.client_exceptions import ClientError
from scanner.modules.export import ModuleExport
from scanner.definitions import log_rate_limit, sample_noise, acquire_global_and_host
from scanner.origin_health import *

@dataclass
class HTTPSConnectivityRow:
    origin: str
    success: bool
    status: int | None
    final_scheme: str
    redirects: int
    has_hsts: bool
    error: str

class HTTPSConnectivityExport(ModuleExport):
    def __init__(self, *, session: aiohttp.ClientSession, timeout_s: int):
        self._session = session
        self._timeout = aiohttp.ClientTimeout(total=timeout_s)
        self._results: Dict[str, HTTPSConnectivityRow] = {}

    def name(self) -> str: return "https_connectivity"
    def scope(self) -> str: return "origin"
    def results(self) -> Dict[str, Dict]:
        return {k: asdict(v) for k, v in self._results.items()}

    async def run(self, origins: List[str]) -> None:
        await asyncio.gather(*[self._check(o) for o in origins])

    async def _check(self, origin: str) -> None:
        row = HTTPSConnectivityRow(
            origin=origin, success=False, status=None, final_scheme="",
            redirects=0, has_hsts=False, error=""
        )

        # if not should_run_http_modules(origin):
        #     row.error = "origin offline"
        #     self._results[origin] = row
        #     return

        url = f"https://{origin}"
        try:
            async with acquire_global_and_host(url):
                await sample_noise()
                async with self._session.get(
                    url, timeout=self._timeout, allow_redirects=True
                ) as resp:
                    await log_rate_limit(url, resp, self.name())
                    row.status = resp.status
                    row.redirects = len(resp.history)
                    row.final_scheme = str(resp.real_url.scheme)
                    row.has_hsts = "strict-transport-security" in {
                        k.lower(): v for k, v in resp.headers.items()
                    }
                    row.success = (row.final_scheme == "https")
        except asyncio.TimeoutError:
            row.error = "timeout"
            record_http_timeout(origin)
        except ClientError as e:
            row.error = str(e)
        except Exception as e:
            row.error = str(e)

        self._results[origin] = row
