#!/usr/bin/env python3
import asyncio
import aiohttp
import requests
import time
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import importlib
import inspect

# Test modules
from tests import (
    connectivity,
    headers,
    tls,
    cipher,
    securitytxt,
    redirection
)

from plotter import PlotGenerator
from config import Config

class SecurityScanner:
    def __init__(self, output_dir=".", csv_filename="results.csv", 
                 max_workers=10, timeout=10, verify_certificates=False,
                 missing_headers_file=None, regex_headers_file=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.csv_filename = csv_filename
        self.max_workers = max_workers
        self.timeout = timeout
        self.verify_certificates = verify_certificates
        
        Config.OUTPUT_DIR = self.output_dir
        Config.MAX_TIMEOUT = timeout
        Config.VERIFY_CERTIFICATE = verify_certificates
        
        self._load_global_data()
        
        if missing_headers_file or regex_headers_file:
            headers.configure_analyzer(missing_headers_file, regex_headers_file)
        
        self.plotter = PlotGenerator(self.output_dir)
        
    def _load_global_data(self):
        try:
            r = requests.get("https://ciphersuite.info/api/cs", timeout=self.timeout).json()
            Config.CIPHERSUITES = r['ciphersuites']
        except Exception as e:
            print(f"WARNING: Could not load cipher suite data: {e}")
            Config.CIPHERSUITES = []
        
        try:
            r = requests.get("https://owasp.org/www-project-secure-headers/ci/headers_remove.json", 
                           timeout=self.timeout).json()
            Config.REVEALING_HEADERS = r['headers']
            Config.REVEALING_HEADERS_LOWER = [h.lower() for h in r['headers']]
        except Exception as e:
            print(f"WARNING: Could not load revealing headers data: {e}")
            Config.REVEALING_HEADERS = []
            Config.REVEALING_HEADERS_LOWER = []
    
    def scan_domains(self, domains: List[str]):
        print(f"Starting scan of {len(domains)} domains...")
        start_time = time.time()
        domains_clean = [d.strip().replace(' ', '').replace('\n', '').replace('\r', '') 
                        for d in domains]
    
        results = asyncio.run(self._run_async_scan(domains_clean))
        self._generate_reports(results, len(domains))
        print(f"Scan completed in {time.time() - start_time:.2f} seconds")
    
    async def _run_async_scan(self, domains: List[str]) -> Dict:
        results = {
            'domains': domains,
            'total': len(domains),
            'per_site': [],
            'aggregated': {}
        }
        
        print("\nTesting HTTPS connectivity...")
        https_results = await connectivity.test_https_batch(domains, self.timeout)
        
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
        sectxt_results = await securitytxt.test_securitytxt_batch(https_capable, self.timeout)
        
        for site in results['per_site']:
            site.update(sectxt_results.get(site['host'], {}))
        
        results['aggregated']['securitytxt'] = securitytxt.aggregate_securitytxt_stats(sectxt_results)
        
        print("\nTesting HTTP to HTTPS redirection...")
        redir_results = await redirection.test_redirection_batch(https_capable, self.timeout)
        
        for site in results['per_site']:
            site.update(redir_results.get(site['host'], {}))
        
        results['aggregated']['redirection'] = redirection.aggregate_redirection_stats(redir_results)
        
        return results
    
    async def _run_sync_tests_async(self, domains: List[str], module) -> Dict:
        loop = asyncio.get_event_loop()
        results = {}
        
        # Discover the test funcs in a given module
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            test_funcs = []
            for name in dir(module):
                if name.startswith('test_'):
                    func = getattr(module, name)
                    if callable(func) and not asyncio.iscoroutinefunction(func):
                        test_funcs.append((name, func))
            
            futures = []
            for domain in domains:
                for test_name, test_func in test_funcs:

                    # The encryption related tests have blocking io, 
                    # so I have enqueued them on the thread pool
                    future = loop.run_in_executor(executor, test_func, domain)
                    futures.append((domain, test_name, future))
            
            for domain, test_name, future in futures: # Should maybe use as_completed here
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
    
    def _generate_reports(self, results: Dict, total_domains: int):
        self._write_csv(results)
        
        print("\nGenerating visualizations...")
        
        if 'https_results' in results:
            https_capable = len(results.get('https_capable', []))
            https_failed = total_domains - https_capable
            self.plotter.plot_https_connectivity(https_capable, https_failed, total_domains)
        
        if 'headers' in results.get('aggregated', {}):
            header_stats = results['aggregated']['headers']
            self.plotter.plot_header_implementation(header_stats)
        
        if 'tls' in results.get('aggregated', {}):
            tls_stats = results['aggregated']['tls']
            self.plotter.plot_tls_support(tls_stats)
        
        if 'cipher' in results.get('aggregated', {}):
            cipher_stats = results['aggregated']['cipher']
            self.plotter.plot_cipher_security(cipher_stats)
        
        if 'securitytxt' in results.get('aggregated', {}):
            sectxt_stats = results['aggregated']['securitytxt']
            self.plotter.plot_securitytxt(sectxt_stats)
        
        if 'redirection' in results.get('aggregated', {}):
            redir_stats = results['aggregated']['redirection']
            self.plotter.plot_redirection(redir_stats)
    
    def _write_csv(self, results: Dict):
        csv_path = self.output_dir / self.csv_filename
        
        if not results.get('per_site'):
            print("No results to write to CSV")
            return
        
        all_keys = set()
        for site in results['per_site']:
            all_keys.update(site.keys())
        
        all_keys.discard('response_data')
        
        fieldnames = ['host', 'https_ok'] + sorted([k for k in all_keys if k not in ['host', 'https_ok']])
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for site in results['per_site']:
                row = {}
                for key in fieldnames:
                    value = site.get(key, '')
                    if isinstance(value, bool):
                        row[key] = str(value)
                    elif value is None:
                        row[key] = ''
                    else:
                        row[key] = value
                writer.writerow(row)
        
        print(f"Results written to {csv_path}")