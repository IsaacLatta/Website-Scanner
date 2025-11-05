#!/usr/bin/env python3
from __future__ import annotations

from typing import TypeAlias, Callable, Optional, Any, Literal, Mapping, Dict, List
from dataclasses import dataclass

from scanner.modules.revealing_headers import REVEALING_HEADERS

HeaderClass: TypeAlias = Literal["recommended", "sufficient", "insecure", "obsolete", "unknown"]

@dataclass
class HeaderRule:
    name: str
    display_name: str
    classifier: Optional[Callable[[str], HeaderClass]] = None
    on_missing_class: HeaderClass = "insecure"
    has_additional_fields: bool = False
    add_fields_parser: Optional[Callable[[str], dict[str, Any]]] = None

@dataclass
class HeaderResult:
    name: str
    present: bool
    rating: HeaderClass
    raw: str
    additional_fields: Optional[dict[str, any]]


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

SENSITIVE_PERMISSIONS = {
    "camera",
    "microphone",
    "geolocation",
    "payment",
    "usb",
    "clipboard-read",
    "clipboard-write",
    "fullscreen",
    "xr-spatial-tracking",
}

def _parse_permissions_policy(value: str) -> Dict[str, List[str]]:
    """
    Maps feature -> list of tokens.
    Examples:
        "camera=()" -> {"camera": []}
        "camera=(self https://a)" -> {"camera": ["self", "https://a"]}
        "geolocation=*" -> {"geolocation": ["*"]}
    """
    directives: Dict[str, List[str]] = {}

    for part in value.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue

        name, rest = part.split("=", 1)
        name = name.strip().lower()
        rest = rest.strip()
        lower_rest = rest.lower()

        if lower_rest in ("none", "()"):
            directives[name] = []
            continue
        if rest.startswith("(") and ")" in rest:
            inner = rest[1 : rest.find(")")]
            tokens = [t.strip(" '\"") for t in inner.split() if t.strip()]
            directives[name] = tokens
            continue
        directives[name] = [rest.strip(" '\"")]
    return directives

# TODO: Should maybe remove the '*' from the insecure. 
# If a permissions policy sets a '*', it may not be a 
# guarantee the site is insecure
def classify_permissions_policy(value: str) -> HeaderClass:
    """
    recommended:
        Header present, we can parse at least one directive, and there is
        no bare '*' origin anywhere. This means the site is explicitly
        controlling which origins can use features (even if it allows some
        cross-origin use).

    insecure:
        Header present but at least one directive uses a bare '*'
        (e.g. geolocation=*), or the value is empty / unparseable
        so the effective behaviour is the default "allow everything".
    """
    if not value or not value.strip():
        return "insecure"

    directives = _parse_permissions_policy(value)
    if not directives:
        return "insecure"

    for tokens in directives.values():
        if any(tok == "*" for tok in tokens):
            return "insecure"

    # Header is set, parsed, and avoids '*', meaning it is explicitly scoping usage.
    return "recommended"

def parse_set_cookie_attributes(value: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "has_secure": False,
        "has_httponly": False,
        "samesite": None,
        "has_max_age": False,
        "has_expires": False,
        "max_age": None,
        "expires": None,
    }

    parts = [p.strip() for p in value.split(";") if p.strip()]
    if not parts:
        return info

    # parts[0] is name=value; attributes start at index 1
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "samesite":
                info["samesite"] = v
            elif k == "max-age":
                info["has_max_age"] = True
                info["max_age"] = v
            elif k == "expires":
                info["has_expires"] = True
                info["expires"] = v
        else:
            token = part.lower()
            if token == "secure":
                info["has_secure"] = True
            elif token == "httponly":
                info["has_httponly"] = True

    return info

def classify_set_cookie(value: str) -> HeaderClass:
    info = parse_set_cookie_attributes(value)

    samesite = (info["samesite"] or "").strip().lower()

    # Recommended: strict + Secure + HttpOnly (CCSA and MDN)
    if info["has_secure"] and info["has_httponly"] and samesite == "strict":
        return "recommended"

    # Sufficient: lax + Secure + HttpOnly + explicit lifetime (MDN)
    if info["has_secure"] and info["has_httponly"] and samesite == "lax":
        return "sufficient"

    return "insecure"

def load_missing_header_rules() -> list[HeaderRule]:
    def missing_header_classifier(value: str) -> HeaderClass:
        return "insecure"

    rules: list[HeaderRule] = []
    for header in REVEALING_HEADERS:
        name = header.lower()
        display = name.replace("-", "_")
        rules.append(
            HeaderRule(
                name=name,
                display_name=display,
                classifier=missing_header_classifier,
                on_missing_class="recommended",
            )
        )
    return rules

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
        HeaderRule(
            name="permissions-policy",
            display_name="permissions_policy",
            classifier=classify_permissions_policy,
            on_missing_class="insecure", # OWASP recommends it should be set
        ),
        HeaderRule(
            name="set-cookie",
            display_name="cookies",
            classifier=classify_set_cookie,
            on_missing_class="unknown",  # site might genuinely be sessionless
            has_additional_fields=True,
            add_fields_parser=parse_set_cookie_attributes
        ),
    ] + load_missing_header_rules()

# TODO: Refactor parsing code to check multiple instances of each header
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

            additional_fields = None
            rating: HeaderClass = "unknown"
            if present:
                if rule.classifier is not None:
                    rating = rule.classifier(raw)
                if rule.has_additional_fields and rule.add_fields_parser is not None:
                    additional_fields = rule.add_fields_parser(raw)
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
                    additional_fields=additional_fields
                )
            )

        return results
