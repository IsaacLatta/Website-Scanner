#!/usr/bin/env python3
from typing import Dict, List
from config import Config

def analyze_headers_batch(https_results: Dict) -> Dict:
    results = {}
    
    for domain, data in https_results.items():
        if data.get('success') and data.get('headers'):
            results[domain] = analyze_headers_single(data['headers'])
        else:
            results[domain] = _empty_header_result()
    
    return results

def analyze_headers_single(headers: Dict) -> Dict:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    result = {
        'referrer_policy_present': False,
        'referrer_policy_correct': False,
        
        'x_content_type_options_present': False,
        'x_content_type_options_correct': False,
        
        'x_frame_options_present': False,
        'x_frame_options_correct': False,
        
        'csp_present': False,
        'csp_reasonable': False,
        
        'hsts_present': False,
        'hsts_includeSubDomains': False,
        'hsts_max_age_ge_31536000': False,
        'hsts_preload': False,
        
        'revealing_headers': False,
        'revealing_headers_list': []
    }
    
    if 'referrer-policy' in headers_lower:
        result['referrer_policy_present'] = True
        value = headers_lower['referrer-policy'].lower()
        if any(policy in value for policy in ['same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']):
            result['referrer_policy_correct'] = True
    
    if 'x-content-type-options' in headers_lower:
        result['x_content_type_options_present'] = True
        if 'nosniff' in headers_lower['x-content-type-options'].lower():
            result['x_content_type_options_correct'] = True
    
    if 'x-frame-options' in headers_lower:
        result['x_frame_options_present'] = True
        value = headers_lower['x-frame-options'].lower()
        if 'deny' in value or 'sameorigin' in value:
            result['x_frame_options_correct'] = True
    
    if 'content-security-policy' in headers_lower:
        result['csp_present'] = True
        value = headers_lower['content-security-policy'].lower()
        # Basic CSP validation
        has_default_or_script = 'default-src' in value or ('script-src' in value and 'object-src' in value)
        no_unsafe = 'unsafe-inline' not in value and 'data:' not in value
        if has_default_or_script and no_unsafe:
            result['csp_reasonable'] = True
    
    if 'strict-transport-security' in headers_lower:
        result['hsts_present'] = True
        value = headers_lower['strict-transport-security'].lower()
        
        if 'includesubdomains' in value:
            result['hsts_includeSubDomains'] = True
        
        if 'preload' in value:
            result['hsts_preload'] = True
        
        import re
        max_age_match = re.search(r'max-age=(\d+)', value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age >= 31536000:  # One year
                result['hsts_max_age_ge_31536000'] = True
    
    if Config.REVEALING_HEADERS:
        revealing = []
        for header in headers_lower:
            if header in [h.lower() for h in Config.REVEALING_HEADERS]:
                revealing.append(header)
        
        if revealing:
            result['revealing_headers'] = True
            result['revealing_headers_list'] = revealing
    
    return result

def _empty_header_result() -> Dict:
    return {
        'referrer_policy_present': False,
        'referrer_policy_correct': False,
        'x_content_type_options_present': False,
        'x_content_type_options_correct': False,
        'x_frame_options_present': False,
        'x_frame_options_correct': False,
        'csp_present': False,
        'csp_reasonable': False,
        'hsts_present': False,
        'hsts_includeSubDomains': False,
        'hsts_max_age_ge_31536000': False,
        'hsts_preload': False,
        'revealing_headers': False,
        'revealing_headers_list': []
    }

def aggregate_header_stats(results: Dict) -> Dict:
    stats = {
        'referrer_policy': {'present': 0, 'correct': 0},
        'x_content_type_options': {'present': 0, 'correct': 0},
        'x_frame_options': {'present': 0, 'correct': 0},
        'csp': {'present': 0, 'reasonable': 0},
        'hsts': {
            'present': 0,
            'includeSubDomains': 0,
            'max_age_ok': 0,
            'preload': 0
        },
        'revealing_headers': {'count': 0, 'domains': []},
        'total': len(results)
    }
    
    for domain, data in results.items():
        if data.get('referrer_policy_present'):
            stats['referrer_policy']['present'] += 1
            if data.get('referrer_policy_correct'):
                stats['referrer_policy']['correct'] += 1
        
        if data.get('x_content_type_options_present'):
            stats['x_content_type_options']['present'] += 1
            if data.get('x_content_type_options_correct'):
                stats['x_content_type_options']['correct'] += 1
        
        if data.get('x_frame_options_present'):
            stats['x_frame_options']['present'] += 1
            if data.get('x_frame_options_correct'):
                stats['x_frame_options']['correct'] += 1
        
        if data.get('csp_present'):
            stats['csp']['present'] += 1
            if data.get('csp_reasonable'):
                stats['csp']['reasonable'] += 1
        
        if data.get('hsts_present'):
            stats['hsts']['present'] += 1
            if data.get('hsts_includeSubDomains'):
                stats['hsts']['includeSubDomains'] += 1
            if data.get('hsts_max_age_ge_31536000'):
                stats['hsts']['max_age_ok'] += 1
            if data.get('hsts_preload'):
                stats['hsts']['preload'] += 1
        
        if data.get('revealing_headers'):
            stats['revealing_headers']['count'] += 1
            stats['revealing_headers']['domains'].append(domain)
    
    return stats