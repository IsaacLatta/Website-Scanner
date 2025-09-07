#!/usr/bin/env python3
import re
from typing import Dict, List, Tuple, Any

from config import Config

def _lower_headers(h: Dict[str, str]) -> Dict[str, str]:
    return {k.lower(): (v.lower() if isinstance(v, str) else v) for k, v in h.items()}


def analyze_headers_single(headers: Dict[str, str]) -> Dict:
    h = _lower_headers(headers or {})

    rp_present = "referrer-policy" in h
    rp_correct = False
    if rp_present:
        v = h.get("referrer-policy", "")
        rp_correct = any(x in v for x in ("same-origin", "strict-origin", "strict-origin-when-cross-origin", "no-referrer"))

    xcto_present = "x-content-type-options" in h
    xcto_correct = False
    if xcto_present:
        xcto_correct = "nosniff" in h.get("x-content-type-options", "")

    xfo_present = "x-frame-options" in h
    xfo_correct = False
    if xfo_present:
        v = h.get("x-frame-options", "")
        xfo_correct = ("deny" in v) or ("sameorigin" in v)

    csp_present = "content-security-policy" in h
    csp_reasonable = False
    if csp_present:
        v = h.get("content-security-policy", "")
        csp_reasonable = (
            (("default-src" in v) or ("script-src" in v and "object-src" in v))
            and ("data:" not in v)
            and ("unsafe-inline" not in v)
        )

    hsts_present = "strict-transport-security" in h
    hsts_incsub = False
    hsts_maxage_ok = False
    hsts_preload = False
    if hsts_present:
        hv = h.get("strict-transport-security", "")
        hsts_incsub = "includesubdomains" in hv
        # first integer occurrence = max-age
        try:
            maxage = int(re.findall(r"\d+", hv)[0])
        except Exception:
            maxage = 0
        hsts_maxage_ok = maxage >= 31536000
        hsts_preload = "preload" in hv

    pp_present = "permissions-policy" in h
    pp_reasonable = False
    if pp_present:
        v = h.get("permissions-policy", "")
        pp_reasonable = ("=*") not in v and len(v.strip()) > 0

    coop_present = "cross-origin-opener-policy" in h
    coop_safe = False
    if coop_present:
        v = h.get("cross-origin-opener-policy", "").strip()
        coop_safe = v == "same-origin"

    coep_present = "cross-origin-embedder-policy" in h
    coep_safe = False
    if coep_present:
        v = h.get("cross-origin-embedder-policy", "")
        coep_safe = "require-corp" in v

    corp_present = "cross-origin-resource-policy" in h
    corp_safe = False
    if corp_present:
        v = h.get("cross-origin-resource-policy", "")
        corp_safe = ("same-origin" in v) or ("same-site" in v)

    csd_present = "clear-site-data" in h
    csd_has_any = False
    if csd_present:
        v = h.get("clear-site-data", "")
        csd_has_any = any(tok in v for tok in ('"cache"', '"cookies"', '"storage"', "cache", "cookies", "storage"))

    xpcdp_present = "x-permitted-cross-domain-policies" in h
    xpcdp_safe = False
    if xpcdp_present:
        v = h.get("x-permitted-cross-domain-policies", "").strip()
        xpcdp_safe = v == "none"

    csp_ro_present = "content-security-policy-report-only" in h

    # 8) Cookie flags (only evaluate if cookies are actually being set)
    cookies_present = "set-cookie" in h
    cookies_missing_secure = False
    cookies_missing_httponly = False
    cookies_samesite_none_without_secure = False
    if cookies_present:
        # NOTE: with some HTTP clients, multiple Set-Cookie lines may be collapsed.
        # We conservatively scan the combined string for flags.
        cv = h.get("set-cookie", "")
        vlow = cv.lower()
        cookies_missing_secure = "secure" not in vlow
        cookies_missing_httponly = "httponly" not in vlow
        # SameSite=None must be paired with Secure
        cookies_samesite_none_without_secure = ("samesite=none" in vlow) and ("secure" not in vlow)

    # Revealing headers (from Config.REVEALING_HEADERS)
    revealing = any(k.lower() in Config.REVEALING_HEADERS_LOWER for k in h.keys())

    return {
        # existing fields
        "referrer_policy_present": rp_present,
        "referrer_policy_correct": rp_correct,
        "x_content_type_options_present": xcto_present,
        "x_content_type_options_correct": xcto_correct,
        "x_frame_options_present": xfo_present,
        "x_frame_options_correct": xfo_correct,
        "csp_present": csp_present,
        "csp_reasonable": csp_reasonable,
        "hsts_present": hsts_present,
        "hsts_include_subdomains": hsts_incsub,
        "hsts_max_age_ok": hsts_maxage_ok,
        "hsts_preload": hsts_preload,
        "revealing_headers": revealing,

        # new fields
        "permissions_policy_present": pp_present,
        "permissions_policy_reasonable": pp_reasonable,

        "coop_present": coop_present,
        "coop_safe": coop_safe,

        "coep_present": coep_present,
        "coep_safe": coep_safe,

        "corp_present": corp_present,
        "corp_safe": corp_safe,

        "clear_site_data_present": csd_present,
        "clear_site_data_has_any": csd_has_any,

        "x_permitted_cross_domain_policies_present": xpcdp_present,
        "x_permitted_cross_domain_policies_safe": xpcdp_safe,

        "csp_report_only_present": csp_ro_present,

        "cookies_present": cookies_present,
        "cookies_missing_secure": cookies_missing_secure,
        "cookies_missing_httponly": cookies_missing_httponly,
        "cookies_samesite_none_without_secure": cookies_samesite_none_without_secure,
    }


def analyze_headers_batch(headers_by_domain: Dict[str, Dict[str, str]]) -> Dict[str, Dict]:
    """
    headers_by_domain: { domain -> {header: value, ...} }
    Returns: { domain -> analysis dict }
    """
    results: Dict[str, Dict] = {}
    for domain, hdrs in headers_by_domain.items():
        try:
            results[domain] = analyze_headers_single(hdrs or {})
        except Exception as e:
            results[domain] = {"error": str(e)}
    return results

from typing import Dict

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
