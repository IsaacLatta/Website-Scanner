#!/usr/bin/env python3
import aiohttp
import asyncio
from typing import Dict, List, Optional
from config import Config

async def test_https_batch(domains: List[str], timeout: int = None) -> Dict:
    if timeout is None:
        timeout = Config.MAX_TIMEOUT
    
    results = {}
    connector = aiohttp.TCPConnector(limit=20, limit_per_host=5, ssl=not Config.VERIFY_CERTIFICATE)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for domain in domains:
            task = test_https_single(session, domain, timeout)
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for domain, response in zip(domains, responses):
            if isinstance(response, Exception):
                results[domain] = {
                    'success': False,
                    'error': str(response),
                    'status': None,
                    'headers': {},
                    'content': b''
                }
            else:
                results[domain] = response
    
    return results

async def test_https_single(session: aiohttp.ClientSession, domain: str, timeout: int) -> Dict:
    try:
        url = f"https://{domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
            headers = dict(response.headers)
            content = await response.read()
            
            return {
                'success': True,
                'status': response.status,
                'headers': headers,
                'content': content,
                'error': None
            }
    except asyncio.TimeoutError:
        return {
            'success': False,
            'error': 'Timeout',
            'status': None,
            'headers': {},
            'content': b''
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'status': None,
            'headers': {},
            'content': b''
        }
    