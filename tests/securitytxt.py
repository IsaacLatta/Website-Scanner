#!/usr/bin/env python3
import aiohttp
import asyncio
from typing import Dict, List, Optional, Tuple
from config import Config

async def test_securitytxt_batch(domains: List[str], timeout: int = None) -> Dict:
    if timeout is None:
        timeout = Config.MAX_TIMEOUT
    
    results = {}
    connector = aiohttp.TCPConnector(limit=20, limit_per_host=5, ssl=not Config.VERIFY_CERTIFICATE)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for domain in domains:
            task = test_securitytxt_single(session, domain, timeout)
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for domain, response in zip(domains, responses):
            if isinstance(response, Exception):
                results[domain] = {
                    'securitytxt_present': False,
                    'securitytxt_correctness': 'none',
                    'securitytxt_location': None
                }
            else:
                results[domain] = response
    
    return results

async def test_securitytxt_single(session: aiohttp.ClientSession, domain: str, timeout: int) -> Dict:
    result = {
        'securitytxt_present': False,
        'securitytxt_correctness': 'none',
        'securitytxt_location': None
    }
    
    try:
        url = f"https://{domain}/.well-known/security.txt"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
            if response.status == 200:
                content = await response.read()
                result['securitytxt_present'] = True
                result['securitytxt_location'] = '/.well-known/security.txt'
                result['securitytxt_correctness'] = _check_correctness(content)
                return result
    except:
        pass
    
    try:
        url = f"https://{domain}/security.txt"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
            if response.status == 200:
                content = await response.read()
                result['securitytxt_present'] = True
                result['securitytxt_location'] = '/security.txt'
                result['securitytxt_correctness'] = _check_correctness(content)
                return result
    except:
        pass
    
    return result

def _check_correctness(content: bytes) -> str:
    try:
        has_contact = b'Contact' in content or b'contact' in content
        has_expires = b'Expires' in content or b'expires' in content
        
        if has_contact and has_expires:
            return 'both'
        elif has_contact:
            return 'contact'
        elif has_expires:
            return 'expires'
        else:
            return 'none'
    except:
        return 'none'

def aggregate_securitytxt_stats(results: Dict) -> Dict:
    stats = {
        'present': 0,
        'absent': 0,
        'correctness': {
            'both': 0,
            'contact_only': 0,
            'expires_only': 0,
            'none': 0
        },
        'locations': {
            '/.well-known/security.txt': 0,
            '/security.txt': 0
        },
        'total': len(results)
    }
    
    for domain, data in results.items():
        if data.get('securitytxt_present'):
            stats['present'] += 1
            
            correctness = data.get('securitytxt_correctness', 'none')
            if correctness == 'both':
                stats['correctness']['both'] += 1
            elif correctness == 'contact':
                stats['correctness']['contact_only'] += 1
            elif correctness == 'expires':
                stats['correctness']['expires_only'] += 1
            else:
                stats['correctness']['none'] += 1
            
            location = data.get('securitytxt_location')
            if location in stats['locations']:
                stats['locations'][location] += 1
        else:
            stats['absent'] += 1
    
    return stats