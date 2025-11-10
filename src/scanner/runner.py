# scanner/runner.py
from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Any, Dict, List, Sequence
from concurrent.futures import ThreadPoolExecutor

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
import ssl

from scanner.definitions import init_global_limiter, get_limiter
from scanner.targets import build_scan_targets, ScanTargets
from scanner.redirects import RedirectResolver, ResolutionResult
from scanner.origins import build_origin_targets, OriginTargets
from scanner.modules.export import ModuleExport

from scanner.modules.error.error_leak import ErrorLeakExport
from scanner.modules.tls import TLSModule
from scanner.modules.hsts import HSTSModule
from scanner.modules.securitytxt import SecurityTxtExport
from scanner.modules.connectivity import HTTPSConnectivityExport
from scanner.modules.cipher import CipherSuitesModule 
from scanner.modules.headers import HeaderAnalyzer, default_header_rules


def _final_uris_from_resolutions(resolutions: Dict[str, ResolutionResult]) -> List[str]:
    """
    Collect unique final URLs from the redirect resolution pass.
    Only non-empty final_url values are included.
    """
    uris: set[str] = set()
    for res in resolutions.values():
        if res.final_url:
            uris.add(res.final_url)
    return sorted(uris)

async def run_scan(
    domains: Sequence[str],
    *,
    max_concurrency: int = 20,
    http_timeout_s: int = 10,
    redirect_max_hops: int = 8,
    verify_certificate: bool = True,
) -> Dict[str, Any]:
    """
    1. Build ScanTargets from the input domains/URLs.
    2. Initialize the global concurrency limiter.
    3. Resolve all URIs to final URLs (capturing hops + final headers).
    4. Build origin targets (entry + final origins).
    5. Instantiate and run all modules over the appropriate targets.
    6. Run header analysis on cached final_headers.
    7. Return a dict structure suitable for later JSON export / analysis.
    """
    domains = list(domains)
    if not domains:
        return {
            "scan_targets": {"origins": [], "uris": []},
            "origin_targets": {"entry_origins": [], "final_origins": [], "all_origins": []},
            "resolutions": {},
            "modules": {},
        }

    scan_targets: ScanTargets = build_scan_targets(domains)

    init_global_limiter(max_concurrency)
    limiter = get_limiter()

    if verify_certificate:
        connector = TCPConnector()
    else:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = TCPConnector(ssl=ssl_ctx)


    timeout = ClientTimeout(total=http_timeout_s)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        resolver = RedirectResolver(
            session=session,
            timeout=timeout,
            max_hops=redirect_max_hops,
            concurrency=max_concurrency,
        )
        resolutions: Dict[str, ResolutionResult] = await resolver.resolve_all(
            scan_targets.uris
        )

        origin_targets: OriginTargets = build_origin_targets(scan_targets, resolutions)

        with ThreadPoolExecutor(max_workers=max_concurrency) as executor:
            modules: List[ModuleExport] = [
                TLSModule(executor=executor, timeout_s=http_timeout_s, limiter=limiter),
                HTTPSConnectivityExport(session=session, timeout_s=http_timeout_s, limiter=limiter),
                HSTSModule(session=session, timeout_s=http_timeout_s, limiter=limiter),
                SecurityTxtExport(
                    verify_certificate=True,
                    timeout_s=http_timeout_s,
                    session=session,
                    limiter=limiter,
                ),
                CipherSuitesModule(executor=executor, timeout_s=http_timeout_s, limiter=limiter),
                ErrorLeakExport(session=session),
            ]

            origin_modules: List[ModuleExport] = [m for m in modules if m.scope() == "origin"]
            uri_modules: List[ModuleExport] = [m for m in modules if m.scope() == "uri"]

            tasks: List[asyncio.Future] = []

            if origin_modules:
                origin_list = origin_targets.all_origins
                tasks.extend(m.run(origin_list) for m in origin_modules)

            if uri_modules:
                final_uris = _final_uris_from_resolutions(resolutions)
                tasks.extend(m.run(final_uris) for m in uri_modules)

            if tasks:
                await asyncio.gather(*tasks)

            module_results: Dict[str, Dict] = {
                m.name(): m.results() for m in modules
            }

            analyzer = HeaderAnalyzer(default_header_rules())
            header_analysis: Dict[str, list[dict[str, Any]]] = {}

            for input_url, res in resolutions.items():
                if res.final_headers:
                    header_results = analyzer.run(res.final_headers)
                    header_analysis[input_url] = [asdict(hr) for hr in header_results]
                else:
                    header_analysis[input_url] = []

            module_results["headers"] = header_analysis

    resolutions_dict: Dict[str, Dict[str, Any]] = {
        url: res.to_dict() for url, res in resolutions.items()
    }

    return {
        "scan_targets": {
            "origins": scan_targets.origins,
            "uris": scan_targets.uris,
        },
        "origin_targets": asdict(origin_targets),
        "resolutions": resolutions_dict,
        "modules": module_results,
    }

