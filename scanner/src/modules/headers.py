#!/usr/bin/env python3
import re
from typing import Dict, List, Callable, Optional, Any
from dataclasses import dataclass
from scanner.config import Config

@dataclass
class HeaderRule:
    name: str
    display_name: str  
    validator: Optional[Callable[[str], bool]] = None
    required: bool = False
    description: str = ""

def validate_referrer_policy(value: str) -> bool:
    v = value.lower()
    return any(x in v for x in ["same-origin", "strict-origin", "strict-origin-when-cross-origin", "no-referrer"])

def validate_x_content_type_options(value: str) -> bool:
    return "nosniff" in value.lower()

def validate_x_frame_options(value: str) -> bool:
    v = value.lower()
    return "deny" in v or "sameorigin" in v

def validate_csp(value: str) -> bool:
    v = value.lower()
    has_default_or_script = "default-src" in v or ("script-src" in v and "object-src" in v)
    no_unsafe = "data:" not in v and "unsafe-inline" not in v
    return has_default_or_script and no_unsafe

def validate_hsts(value: str) -> Dict[str, bool]:
    v = value.lower()
    result = {
        'includeSubDomains': 'includesubdomains' in v,
        'preload': 'preload' in v,
        'max_age_ok': False
    }
    
    try:
        max_age = int(re.findall(r'\d+', v)[0])
        result['max_age_ok'] = max_age >= 31536000
    except:
        pass
    
    return result

def validate_permissions_policy(value: str) -> bool:
    return "=*" not in value and len(value.strip()) > 0

def validate_coop(value: str) -> bool:
    return value.strip().lower() == "same-origin"

def validate_coep(value: str) -> bool:
    return "require-corp" in value.lower()

def validate_corp(value: str) -> bool:
    v = value.lower()
    return "same-origin" in v or "same-site" in v

def validate_clear_site_data(value: str) -> bool:
    return any(tok in value for tok in ['"cache"', '"cookies"', '"storage"', "cache", "cookies", "storage"])

def validate_x_permitted_cross_domain(value: str) -> bool:
    return value.strip().lower() == "none"

def validate_cookies(headers: Dict[str, str]) -> Dict[str, bool]:
    if 'set-cookie' not in headers:
        return {'present': False}
    
    cv = headers['set-cookie'].lower()
    return {
        'present': True,
        'missing_secure': 'secure' not in cv,
        'missing_httponly': 'httponly' not in cv,
        'samesite_none_without_secure': ('samesite=none' in cv) and ('secure' not in cv)
    }

DEFAULT_HEADER_RULES = [
    HeaderRule(
        name="referrer-policy",
        display_name="Referrer-Policy",
        validator=validate_referrer_policy,
        description="Should be same-origin, strict-origin, strict-origin-when-cross-origin, or no-referrer"
    ),
    HeaderRule(
        name="x-content-type-options",
        display_name="X-Content-Type-Options",
        validator=validate_x_content_type_options,
        description="Should be 'nosniff'"
    ),
    HeaderRule(
        name="x-frame-options",
        display_name="X-Frame-Options",
        validator=validate_x_frame_options,
        description="Should be 'DENY' or 'SAMEORIGIN'"
    ),
    HeaderRule(
        name="content-security-policy",
        display_name="Content-Security-Policy",
        validator=validate_csp,
        description="Should have default-src or script-src+object-src, without unsafe-inline or data:"
    ),
    HeaderRule(
        name="strict-transport-security",
        display_name="Strict-Transport-Security",
        validator=None, 
        description="Should have max-age >= 31536000, includeSubDomains, and preload"
    ),
    HeaderRule(
        name="permissions-policy",
        display_name="Permissions-Policy",
        validator=validate_permissions_policy,
        description="Should not allow all origins (=*)"
    ),
    HeaderRule(
        name="cross-origin-opener-policy",
        display_name="Cross-Origin-Opener-Policy",
        validator=validate_coop,
        description="Should be 'same-origin'"
    ),
    HeaderRule(
        name="cross-origin-embedder-policy",
        display_name="Cross-Origin-Embedder-Policy",
        validator=validate_coep,
        description="Should contain 'require-corp'"
    ),
    HeaderRule(
        name="cross-origin-resource-policy",
        display_name="Cross-Origin-Resource-Policy",
        validator=validate_corp,
        description="Should be 'same-origin' or 'same-site'"
    ),
    HeaderRule(
        name="clear-site-data",
        display_name="Clear-Site-Data",
        validator=validate_clear_site_data,
        description="Should specify cache, cookies, or storage to clear"
    ),
    HeaderRule(
        name="x-permitted-cross-domain-policies",
        display_name="X-Permitted-Cross-Domain-Policies",
        validator=validate_x_permitted_cross_domain,
        description="Should be 'none'"
    ),
    HeaderRule(
        name="content-security-policy-report-only",
        display_name="Content-Security-Policy-Report-Only",
        validator=None,  # Presence check only
        description="Used for CSP testing/monitoring"
    )
]

class HeaderAnalyzer:
    def __init__(self):
        self.rules = DEFAULT_HEADER_RULES.copy()
        self.custom_missing_headers = []
        self.custom_regex_rules = []
        
    def add_missing_header_check(self, header_name: str):
        rule = HeaderRule(
            name=header_name.lower(),
            display_name=header_name,
            validator=None, 
            required=True,
            description=f"Custom required header: {header_name}"
        )
        self.custom_missing_headers.append(rule)
        
    def add_regex_rule(self, header_name: str, pattern: str):
        compiled_pattern = re.compile(pattern, re.IGNORECASE)
        
        def regex_validator(value: str) -> bool:
            return bool(compiled_pattern.search(value))
        
        rule = HeaderRule(
            name=header_name.lower(),
            display_name=header_name,
            validator=regex_validator,
            description=f"Must match pattern: {pattern}"
        )
        self.custom_regex_rules.append(rule)
    
    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        h = self._lower_headers(headers or {})
        result = {}
        
        for rule in self.rules:
            header_key = rule.name
            present_key = f"{header_key.replace('-', '_')}_present"
            correct_key = f"{header_key.replace('-', '_')}_correct"
            
            is_present = header_key in h
            result[present_key] = is_present
            
            if header_key == "strict-transport-security" and is_present:
                hsts_checks = validate_hsts(h[header_key])
                result['hsts_include_subdomains'] = hsts_checks['includeSubDomains']
                result['hsts_max_age_ok'] = hsts_checks['max_age_ok']
                result['hsts_preload'] = hsts_checks['preload']
                result[correct_key] = all(hsts_checks.values())
            
            elif header_key == "set-cookie":
                cookie_checks = validate_cookies(h)
                result['cookies_present'] = cookie_checks.get('present', False)
                if cookie_checks.get('present'):
                    result['cookies_missing_secure'] = cookie_checks['missing_secure']
                    result['cookies_missing_httponly'] = cookie_checks['missing_httponly']
                    result['cookies_samesite_none_without_secure'] = cookie_checks['samesite_none_without_secure']
            
            elif is_present and rule.validator:
                try:
                    result[correct_key] = rule.validator(h[header_key])
                except Exception as e:
                    result[correct_key] = False
                    result[f"{header_key.replace('-', '_')}_error"] = str(e)
            else:
                result[correct_key] = False
        
        for rule in self.custom_missing_headers:
            header_key = rule.name
            present_key = f"custom_{header_key.replace('-', '_')}_present"
            result[present_key] = header_key in h
        
        for rule in self.custom_regex_rules:
            header_key = rule.name
            present_key = f"custom_{header_key.replace('-', '_')}_present"
            match_key = f"custom_{header_key.replace('-', '_')}_matches"
            
            is_present = header_key in h
            result[present_key] = is_present
            
            if is_present and rule.validator:
                try:
                    result[match_key] = rule.validator(h[header_key])
                except Exception:
                    result[match_key] = False
            else:
                result[match_key] = False
        
        if Config.REVEALING_HEADERS:
            revealing_lower = [h.lower() for h in Config.REVEALING_HEADERS]
            result['revealing_headers'] = any(k in revealing_lower for k in h.keys())
            result['revealing_headers_list'] = [k for k in h.keys() if k in revealing_lower]
        
        return result
    
    def _lower_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        return {k.lower(): v for k, v in headers.items()}
    
    def load_missing_headers_file(self, filepath: str):
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.add_missing_header_check(line)
        except Exception as e:
            print(f"Error loading missing headers file: {e}")
    
    def load_regex_rules_file(self, filepath: str):
        """Load regex rules from file (format: header_name:pattern)"""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and ':' in line:
                        header_name, pattern = line.split(':', 1)
                        self.add_regex_rule(header_name.strip(), pattern.strip())
        except Exception as e:
            print(f"Error loading regex rules file: {e}")

_analyzer = HeaderAnalyzer()

def configure_analyzer(missing_file: Optional[str] = None, regex_file: Optional[str] = None):
    global _analyzer
    if missing_file:
        _analyzer.load_missing_headers_file(missing_file)
    if regex_file:
        _analyzer.load_regex_rules_file(regex_file)

def analyze_headers_single(headers: Dict[str, str]) -> Dict:
    return _analyzer.analyze_headers(headers)

def analyze_headers_batch(https_results: Dict) -> Dict:
    results = {}
    
    for domain, data in https_results.items():
        if data.get('success') and data.get('headers'):
            results[domain] = analyze_headers_single(data['headers'])
        else:
            results[domain] = _empty_header_result()
    
    return results

def _empty_header_result() -> Dict:
    result = {}
    
    for rule in _analyzer.rules:
        header_key = rule.name.replace('-', '_')
        result[f"{header_key}_present"] = False
        result[f"{header_key}_correct"] = False
    
    result['hsts_include_subdomains'] = False
    result['hsts_max_age_ok'] = False
    result['hsts_preload'] = False
    result['cookies_present'] = False
    result['revealing_headers'] = False
    result['revealing_headers_list'] = []
    
    return result

def aggregate_header_stats(results: Dict) -> Dict:
    stats = {
        'headers': {},
        'custom_missing': {},
        'custom_regex': {},
        'revealing_headers': {'count': 0, 'domains': []},
        'total': len(results)
    }
    
    for rule in _analyzer.rules:
        header_key = rule.name.replace('-', '_')
        stats['headers'][header_key] = {
            'present': 0,
            'correct': 0,
            'display_name': rule.display_name
        }
    
    for domain, data in results.items():
        for rule in _analyzer.rules:
            header_key = rule.name.replace('-', '_')
            if data.get(f"{header_key}_present"):
                stats['headers'][header_key]['present'] += 1
                if data.get(f"{header_key}_correct"):
                    stats['headers'][header_key]['correct'] += 1
        
        for key in data:
            if key.startswith('custom_') and key.endswith('_present'):
                header_name = key.replace('custom_', '').replace('_present', '')
                if header_name not in stats['custom_missing']:
                    stats['custom_missing'][header_name] = {'present': 0}
                if data[key]:
                    stats['custom_missing'][header_name]['present'] += 1
            
            elif key.startswith('custom_') and key.endswith('_matches'):
                header_name = key.replace('custom_', '').replace('_matches', '')
                if header_name not in stats['custom_regex']:
                    stats['custom_regex'][header_name] = {'matches': 0}
                if data[key]:
                    stats['custom_regex'][header_name]['matches'] += 1
        
        if data.get('revealing_headers'):
            stats['revealing_headers']['count'] += 1
            stats['revealing_headers']['domains'].append(domain)
    
    return stats