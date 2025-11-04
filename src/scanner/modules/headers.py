#!/usr/bin/env python3
from __future__ import annotations

from typing import TypeAlias, Callable, Optional, Any, Literal, Mapping, Dict, List
from dataclasses import dataclass

HeaderClass: TypeAlias = Literal["recommended", "sufficient", "insecure", "obsolete", "unknown"]


@dataclass
class HeaderRule:
    name: str
    display_name: str
    classifier: Optional[Callable[[str], HeaderClass]] = None
    on_missing_class: HeaderClass = "insecure"

@dataclass
class HeaderResult:
    name: str
    present: bool
    rating: HeaderClass
    raw: str 


# OWASP only recommends sowco, MDN recommends all of these
REFFERER_POLICY_RECOMMENDED = [
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
]

# MDN says these do not protect the user (OWASP omits them--meaning insecure)
REFFERER_POLICY_INSECURE = [
    "origin",
    "origin-when-cross-origin",
    "no-referrer-when-downgrade",
    "unsafe-url",
]

def classify_referrer_policy(value: str) -> HeaderClass:
    """
    We follow MDN's effective policy semantics:
    - multiple policies -> the last one wins.
    - Recommended: values that do not leak full paths cross-origin.
    - Insecure: MDN's "unsafe" group.
    """
    if not value:
        # syntactically present but empty -> treat as misconfig / insecure
        return "insecure"

    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    if not tokens:
        return "insecure"

    eff = tokens[-1]

    if eff in REFFERER_POLICY_RECOMMENDED:
        return "recommended"
    if eff in REFFERER_POLICY_INSECURE:
        return "insecure"

    return "unknown"

def _extract_frame_ancestors(value: str) -> List[str]:
    """
    Pull out the value of the frame-ancestors directive from a full CSP header.
    "default-src 'self'; frame-ancestors 'none'; object-src 'none'" -> ["'none'"]
    """
    parts = [p.strip() for p in value.split(";") if p.strip()]
    fa_raw = None
    for p in parts:
        lower = p.lower()
        if lower.startswith("frame-ancestors"):
            after = p[len("frame-ancestors"):].strip()
            fa_raw = after
    if fa_raw is None:
        return []

    tokens = [t.strip().lower() for t in fa_raw.split() if t.strip()]
    return tokens


def classify_csp(value: str) -> HeaderClass:
    """
    Classify CSP based solely on the frame-ancestors directive.

    Recommended:
      frame-ancestors 'none';

    Sufficient:
      frame-ancestors 'self';              (current site only)
      frame-ancestors 'self' <other>;      (self plus explicit allowlist, no '*')

    Insecure:
      - Header present but no frame-ancestors at all.
      - frame-ancestors * (any origin may frame)
      - syntactically empty or obviously broken.

    Unknown:
      Something else we don't want to over-interpret.
    """
    if not value:
        return "insecure"

    tokens = _extract_frame_ancestors(value)
    if not tokens:
        return "insecure"

    norm = [t.strip() for t in tokens]

    if "'none'" in norm and len(norm) == 1:
        return "recommended"

    if "*" in norm:
        return "insecure"

    if "'self'" in norm:
        return "sufficient"

    return "unknown"

def classify_x_content_type_options(value: str) -> HeaderClass:
    """
    X-Content-Type-Options:
      - 'nosniff' -> recommended
      - anything else (including empty) -> insecure
    """
    if not value:
        return "insecure"

    v = value.strip().lower()
    if v == "nosniff":
        return "recommended"
    return "insecure"

def classify_x_frame_options(value: str) -> HeaderClass:
    """
    X-Frame-Options is obsolete but still a useful legacy fallback.
    - DENY -> recommended
    - SAMEORIGIN -> sufficient
    - ALLOW-FROM -> obsolete
    Anything else -> unknown.
    """
    if not value:
        return "unknown"

    v = value.strip().upper()
    if v.startswith("DENY"):
        return "recommended"
    if v.startswith("SAMEORIGIN"):
        return "sufficient"
    if v.startswith("ALLOW-FROM"):
        return "obsolete"
    return "unknown"

def default_header_rules() -> List[HeaderRule]:
    return [
        HeaderRule(
            name="referrer-policy",
            display_name="referrer_policy",
            classifier=classify_referrer_policy,
            on_missing_class="recommended" # MDN says the default is sowco--which is recommended by OWASP and MDN
        ),
        HeaderRule(
            name="content-security-policy",
            display_name="csp_frame_ancestors",
            classifier=classify_csp,
            on_missing_class="insecure", # missing leaves frame completely open
        ),
        HeaderRule(
            name="x-frame-options",
            display_name="x_frame_options",
            classifier=classify_x_frame_options,
            on_missing_class="unknown",
        ),
        HeaderRule(
            name="x-content-type-options",
            display_name="x_content_type_options",
            classifier=classify_x_content_type_options,
            on_missing_class="insecure",
        ),
    ]


class HeaderAnalyzer:
    def __init__(self, rules: List[HeaderRule]):
        self._rules = rules

    def run(self, headers: Mapping[str, Any]) -> List[HeaderResult]:
        """
        `headers` can be a plain dict, aiohttp CIMultiDict, etc.
        All normalized to lowercase keys and string values.
        """
        lowered: Dict[str, str] = {}
        for k, v in headers.items():
            lowered[str(k).lower()] = str(v) # Take the last header on duplicates

        results: List[HeaderResult] = []

        for rule in self._rules:
            raw = lowered.get(rule.name)
            present = raw is not None

            rating: HeaderClass = "unknown"
            if present and rule.classifier is not None:
                rating = rule.classifier(raw)
            else:
                rating = rule.on_missing_class
                if raw is None:
                    raw = ""

            results.append(
                HeaderResult(
                    name=rule.display_name,
                    present=present,
                    rating=rating,
                    raw=raw,
                )
            )

        return results
