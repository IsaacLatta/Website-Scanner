# scanner/redirects.py
from __future__ import annotations

import asyncio
from tqdm.asyncio import tqdm_asyncio
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set

from urllib.parse import urlparse, urljoin
from scanner.definitions import log_rate_limit

import aiohttp
from aiohttp.client_exceptions import ClientError

from scanner.targets import ScanTargets, _normalize_origin
from scanner.definitions import sample_noise, acquire_global_and_host

@dataclass
class RedirectHop:
    """One step in a redirect chain."""
    status: int
    url: str


@dataclass
class ResolutionResult:
    """
    Resolution of a single input URL, including:
      - entry origin (derived from input_url)
      - final URL/origin (if reached)
      - full hop chain
      - cached headers on the final response
    """
    input_url: str

    entry_origin: str

    entry_status: Optional[int] = None
    entry_headers: Optional[Dict[str, str]] = None

    final_url: Optional[str] = None
    final_origin: Optional[str] = None

    final_status: Optional[int] = None
    final_headers: Optional[Dict[str, str]] = None

    hops: List[RedirectHop] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class RedirectResolver:
    """
    Resolves a set of URLs by manually following 3xx hops (up to max_hops)
    and caching the final response headers.
    """
    def __init__(
        self,
        session: aiohttp.ClientSession,
        timeout: aiohttp.ClientTimeout,
        max_hops: int = 8,
        concurrency: int = 50,
    ) -> None:
        self._session = session
        self._timeout = timeout
        self._max_hops = max_hops
        self._semaphore = asyncio.Semaphore(concurrency)
        self._results: Dict[str, ResolutionResult] = {}

    # async def resolve_all(self, urls: List[str], show_progress: bool = False) -> Dict[str, ResolutionResult]:
    #     """
    #     Resolve all given URLs concurrently.
    #     Returns a map: input_url -> ResolutionResult
    #     """
    #     await asyncio.gather(*(self._resolve_with_limit(u) for u in urls))
    #     return self._results

    async def resolve_all(self, urls: List[str], show_progress: bool = False) -> Dict[str, ResolutionResult]:
        """
        Resolve all given URLs concurrently.
        Returns a map: input_url -> ResolutionResult
        """
        tasks = [self._resolve_with_limit(u) for u in urls]
        if show_progress:
            print(f"\n[Progress] Resolving {len(urls)} URLs...")
            await tqdm_asyncio.gather(*tasks, total=len(urls))
        else:
            await asyncio.gather(*tasks)
        return self._results

    async def _resolve_with_limit(self, url: str) -> None:
        async with acquire_global_and_host(url):
            self._results[url] = await self._resolve_one(url)

    async def _resolve_one(self, url: str) -> ResolutionResult:
        parsed = urlparse(url)
        if not parsed.hostname:
            return ResolutionResult(
                input_url=url,
                entry_origin="",
                error="no_hostname",
                hops=[],
            )

        entry_host = parsed.hostname.lower()
        entry_scheme = parsed.scheme or "https"
        entry_port = parsed.port
        entry_origin = _normalize_origin(entry_host, entry_scheme, entry_port)

        result = ResolutionResult(
            input_url=url,
            entry_origin=entry_origin,
            hops=[],
        )

        visited: Set[str] = set()
        current = url

        for _ in range(self._max_hops):
            try:
                await sample_noise()
                async with self._session.get(
                    current,
                    allow_redirects=False,
                    timeout=self._timeout,
                ) as resp:
                    await log_rate_limit(current, resp, "redirect resolution")
                    status = resp.status
                    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                    if result.entry_headers is None:
                        result.entry_status = status
                        result.entry_headers = headers_lower

                    # If not a 3xx, this is our final response
                    if not (300 <= status < 400):
                        result.final_url = str(resp.url)
                        result.final_status = status
                        result.final_headers = headers_lower

                        final_parsed = urlparse(result.final_url)
                        if final_parsed.hostname:
                            final_host = final_parsed.hostname.lower()
                            final_scheme = final_parsed.scheme or "https"
                            final_port = final_parsed.port
                            result.final_origin = _normalize_origin(
                                final_host, final_scheme, final_port
                            )
                        return result

                    # 3xx with Location -> follow
                    loc = resp.headers.get("Location")
                    if not loc:
                        result.error = f"redirect_without_location (status={status})"
                        result.final_status = status
                        return result

                    next_url = urljoin(current, loc)
                    result.hops.append(RedirectHop(status=status, url=next_url))

                    if next_url in visited:
                        result.error = "redirect_loop"
                        return result

                    visited.add(next_url)
                    current = next_url

            except asyncio.TimeoutError:
                result.error = "timeout"
                return result
            except ClientError as e:
                result.error = f"client_error: {e}"
                return result
            except Exception as e:
                result.error = f"error: {e}"
                return result

        # Exceeded max_hops
        if not result.error:
            result.error = "max_hops_exceeded"
        return result
