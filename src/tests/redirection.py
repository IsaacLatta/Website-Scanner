#!/usr/bin/env python3
import aiohttp
import asyncio
from typing import Dict, List
from config import Config

async def test_redirection_batch(domains: List[str], timeout: int = None) -> Dict:
    if timeout is None:
        timeout = Config.MAX_TIMEOUT
    
    results = {}
    connector = aiohttp.TCPConnector(limit=20, limit_per_host=5, ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for domain in domains:
            task = test_redirection_single(session, domain, timeout)
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for domain, response in zip(domains, responses):
            if isinstance(response, Exception):
                results[domain] = {
                    'redirection_http_to_https': False,
                    'redirection_status_code': None,
                    'redirection_error': str(response)
                }
            else:
                results[domain] = response
    
    return results

async def test_redirection_single(session: aiohttp.ClientSession, domain: str, timeout: int) -> Dict:
    try:
        url = f"http://{domain}/"
        async with session.get(url, 
                              timeout=aiohttp.ClientTimeout(total=timeout),
                              allow_redirects=False) as response:
            status = response.status
            
            is_redirect = str(status).startswith('3')
            
            redirects_to_https = False
            if is_redirect:
                location = response.headers.get('Location', '')
                redirects_to_https = location.startswith('https://')
            
            return {
                'redirection_http_to_https': is_redirect and redirects_to_https,
                'redirection_status_code': status,
                'redirection_error': None
            }
    except asyncio.TimeoutError:
        return {
            'redirection_http_to_https': False,
            'redirection_status_code': None,
            'redirection_error': 'Timeout'
        }
    except Exception as e:
        return {
            'redirection_http_to_https': False,
            'redirection_status_code': None,
            'redirection_error': str(e)
        }

def aggregate_redirection_stats(results: Dict) -> Dict:
    stats = {
        'redirects': 0,
        'no_redirect': 0,
        'errors': 0,
        'status_codes': {},
        'total': len(results)
    }
    
    for domain, data in results.items():
        if data.get('redirection_error'):
            stats['errors'] += 1
        elif data.get('redirection_http_to_https'):
            stats['redirects'] += 1
        else:
            stats['no_redirect'] += 1
        
        status = data.get('redirection_status_code')
        if status:
            stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
    
    return stats