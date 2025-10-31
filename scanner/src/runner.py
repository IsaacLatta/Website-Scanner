#!/usr/bin/env python3
import asyncio
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor

from scanner.modules.export import ModuleExport

from tests import (
    connectivity,
    headers,
    tls,
    cipher,
    securitytxt,
    redirection
)

from scanner.config import Config

class SecurityScanner:
    def __init__(self, config: Config, modules: list[ModuleExport], max_workers: int = 10):
        self._config = config
        self._max_workers = max_workers
        self._modules = modules

    def scan_domains(self, domains: List[str]) -> dict:
        self.start_time = time.time()
        results = asyncio.run(self._run_async_scan(domains))
        self.end_time = time.time()
        return results
    
    def duration(self) -> float:
        return self.end_time - self.start_time

    async def _run_async_scan(self, domains: List[str]) -> Dict:
        results = {
            'domains': domains,
            'total': len(domains),
            'per_site': [],
            'aggregated': {}
        }
        
        print("\nTesting HTTPS connectivity...")
        https_results = await connectivity.test_https_batch(domains, self._config.MAX_TIMEOUT)
        
        https_capable = [d for d in domains if https_results.get(d, {}).get('success', False)]
        failed_domains = [d for d in domains if d not in https_capable]
        
        print(f"\t+ {len(https_capable)}/{len(domains)} sites support HTTPS")
        if failed_domains:
            print(f"\t- Failed: {', '.join(failed_domains[:5])}{'...' if len(failed_domains) > 5 else ''}")
        
        results['https_results'] = https_results
        results['https_capable'] = https_capable
        
        if not https_capable:
            print("No HTTPS-capable sites to test further.")
            return results
        
        for domain in https_capable:
            site_result = {
                'host': domain,
                'https_ok': True,
                'response_data': https_results[domain]
            }
            results['per_site'].append(site_result)
        
        print("\nAnalyzing security headers...")
        header_results = headers.analyze_headers_batch(
            {d: https_results[d] for d in https_capable}
        )
        
        for site in results['per_site']:
            site.update(header_results.get(site['host'], {}))
        
        results['aggregated']['headers'] = headers.aggregate_header_stats(header_results)
        
        print("\nTesting TLS version support...")
        tls_results = await self._run_sync_tests_async(https_capable, tls)
        
        for site in results['per_site']:
            site.update(tls_results.get(site['host'], {}))
        
        results['aggregated']['tls'] = tls.aggregate_tls_stats(tls_results)
        
        print("\nTesting cipher suite security...")
        cipher_results = await self._run_sync_tests_async(https_capable, cipher)
        
        for site in results['per_site']:
            site.update(cipher_results.get(site['host'], {}))
        
        results['aggregated']['cipher'] = cipher.aggregate_cipher_stats(cipher_results)
        
        print("\nChecking security.txt implementation...")
        sectxt_results = await securitytxt.test_securitytxt_batch(https_capable, self._config.MAX_TIMEOUT)
        
        for site in results['per_site']:
            site.update(sectxt_results.get(site['host'], {}))
        
        # results['aggregated']['securitytxt'] = securitytxt.aggregate_securitytxt_stats(sectxt_results)
        results["aggregated"][]

        print("\nTesting HTTP to HTTPS redirection...")
        redir_results = await redirection.test_redirection_batch(https_capable, self._config.MAX_TIMEOUT)
        
        for site in results['per_site']:
            site.update(redir_results.get(site['host'], {}))
        
        results['aggregated']['redirection'] = redirection.aggregate_redirection_stats(redir_results)
        
        return results
    
    async def _run_sync_tests_async(self, domains: List[str], module) -> Dict:
        loop = asyncio.get_event_loop()
        results = {}
        
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            test_funcs = []
            for name in dir(module):
                if name.startswith('test_'):
                    func = getattr(module, name)
                    if callable(func) and not asyncio.iscoroutinefunction(func):
                        test_funcs.append((name, func))
            
            futures = []
            for domain in domains:
                for test_name, test_func in test_funcs:
                    future = loop.run_in_executor(executor, test_func, domain)
                    futures.append((domain, test_name, future))
            
            for domain, test_name, future in futures:
                if domain not in results:
                    results[domain] = {}
                try:
                    result = await future
                    key = test_name.replace('test_', '')
                    results[domain][key] = result
                except Exception as e:
                    print(f"  Error testing {domain} with {test_name}: {e}")
                    key = test_name.replace('test_', '')
                    results[domain][key] = None
        
        return results
    
    