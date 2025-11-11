from __future__ import annotations

import asyncio
import random
import re
import string
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import aiohttp

from scanner.definitions import get_limiter, sample_noise, acquire_global_and_host
from scanner.modules.error.signature import Signature, StackTraceSignature
from scanner.modules.export import ModuleExport
from scanner.modules.error.framework_signatures import FRAMEWORK_SIGNATURES
from scanner.modules.error.database_signatures import DATABASE_SIGNATURES
from scanner.modules.error.cloud_signatures import CLOUD_PLATFORM_SIGNATURES
from scanner.modules.error.stack_trace_signatures import STACKTRACE_SIGNATURES

VERSION_REGEX = re.compile(
    r"""(?ix)
    \b
    v?\s* 
    (\d+\.\d+(?:\.\d+)*)
    \b
    """
)


def default_signatures() -> List[Signature]:
    return [
        *FRAMEWORK_SIGNATURES,
        *DATABASE_SIGNATURES,
        *CLOUD_PLATFORM_SIGNATURES,
    ]

def default_stack_traces() -> List[StackTraceSignature]:
    return list(STACKTRACE_SIGNATURES)

@dataclass
class ErrorLeakRow:
    origin: str    
    signature: Signature
    alias: str
    has_version: bool
    version: Optional[str]
    version_context: str

@dataclass
class StackTraceRow:
    origin: str
    language: str
    display_name: str
    first_line: str
    frame_count: int 

def _compile_alias_pattern(alias: str) -> re.Pattern[str]:
    """
    Build a case-insensitive regex that matches the alias with simple
    word-boundary semantics.
    - Escapes the alias so dots etc. are literal.
    - Spaces are treated inside the alias as \s+ to allow minor formatting changes.
    """
    escaped = re.escape(alias.lower())
    escaped = escaped.replace(r"\ ", r"\s+")
    return re.compile(
        rf"(?<![0-9a-zA-Z_]){escaped}(?![0-9a-zA-Z_])",
        re.IGNORECASE,
    )


def _is_textual_content_type(content_type: str) -> bool:
    ct = content_type.split(";", 1)[0].strip().lower()
    if not ct:
        return False
    return ct.startswith("text/") or ct in (
        "application/json",
        "application/problem+json",
    )


def _random_probe_path() -> str:
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return f"/__scanner_404__{token}/"

def _detect_tech_leaks_for_body(
    origin: str,
    body: str,
    signatures: List[Signature],
    compiled_aliases: Dict[str, re.Pattern[str]],
) -> List[ErrorLeakRow]:
    results: List[ErrorLeakRow] = []

    lower_body = body.lower()

    for sig in signatures:
        # We want at most one row per signature per origin to avoid spam.
        found_for_sig = False

        for alias in sig.aliases:
            pattern = compiled_aliases[alias]
            match = pattern.search(lower_body)
            if not match:
                continue

            start, end = match.span()

            # Look ahead a bit after the alias for a version-like token.
            lookahead_end = min(len(lower_body), end + 80)
            lookahead_slice = lower_body[end:lookahead_end]
            ver_match = VERSION_REGEX.search(lookahead_slice)

            has_version = ver_match is not None
            version: Optional[str] = None
            if has_version:
                version = ver_match.group(1)

            # Capture a small raw snippet around the match for reporting.
            ctx_start = max(0, start - 40)
            ctx_end = min(len(body), end + 80)
            version_context = body[ctx_start:ctx_end]

            results.append(
                ErrorLeakRow(
                    origin=origin,
                    signature=sig,
                    alias=alias,
                    has_version=has_version,
                    version=version,
                    version_context=version_context,
                )
            )
            found_for_sig = True
            break  # stop after first alias hit for this signature

        if found_for_sig:
            continue

    return results

def _detect_stack_traces_for_body(
    origin: str,
    body: str,
    stack_traces: List[StackTraceSignature],
    max_lookahead_lines: int = 30,
) -> List[StackTraceRow]:
    results: List[StackTraceRow] = []
    lines = body.splitlines()

    for sig in stack_traces:
        n = len(lines)
        found_for_sig = False

        for i, line in enumerate(lines):
            if not any(h.search(line) for h in sig.header_patterns):
                continue

            frame_count = 0

            # Some formats put e.g., "Stack trace: #0 ..."
            # on the same line as the header--count those too.
            if any(fp.search(line) for fp in sig.frame_patterns):
                frame_count += 1

            # Look ahead at the next lines for frame patterns.
            upper = min(n, i + 1 + max_lookahead_lines)
            for j in range(i + 1, upper):
                frame_line = lines[j]
                if any(fp.search(frame_line) for fp in sig.frame_patterns):
                    frame_count += 1

            if frame_count > 0:
                first_line = line.strip()
                results.append(
                    StackTraceRow(
                        origin=origin,
                        language=sig.language,
                        display_name=sig.display_name,
                        first_line=first_line,
                        frame_count=frame_count,
                    )
                )
                found_for_sig = True
                break  # one per signature per origin

        if found_for_sig:
            continue

    return results


class ErrorLeakExport(ModuleExport):
    def __init__(
        self,
        session: aiohttp.ClientSession,
        signatures: Optional[List[Signature]] = None,
        stack_traces: Optional[List[StackTraceSignature]] = None,
        max_body_bytes: int = 64_000,
        limiter: Optional[asyncio.Semaphore] = None
    ) -> None:
        self._session = session
        self._signatures = signatures or default_signatures()
        self._stack_traces = stack_traces or default_stack_traces()
        self._max_body_bytes = max_body_bytes
        self._limiter = limiter or get_limiter()

        self._alias_patterns: Dict[str, re.Pattern[str]] = {}
        for sig in self._signatures:
            for alias in sig.aliases:
                alias_l = alias.lower()
                if alias_l not in self._alias_patterns:
                    self._alias_patterns[alias_l] = _compile_alias_pattern(alias_l)

        self._rows: List[ErrorLeakRow] = []
        self._stack_rows: List[StackTraceRow] = []

    def name(self) -> str:
        return "error_leak"

    def scope(self) -> str:
        return "origin"

    def results(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for r in self._rows:
            out.append(
                {
                    "origin": r.origin,
                    "tech_name": r.signature.display_name,
                    "tech_category": r.signature.category,
                    "alias": r.alias,
                    "has_version": r.has_version,
                    "version": r.version,
                    "version_context": r.version_context,
                }
            )
        for r in self._stack_rows:
            out.append(
                {
                    "origin": r.origin,
                    "language": r.language,
                    "display_name": r.display_name,
                    "first_line": r.first_line,
                    "frame_count": r.frame_count,
                }
            )
        return out

    async def run(self, origins: List[str]) -> None:
        tasks = [self._scan_origin(o) for o in origins]
        await asyncio.gather(*tasks)

    async def _scan_origin(self, origin: str) -> None:
        url = f"https://{origin}{_random_probe_path()}"

        try:
            async with acquire_global_and_host(url):
                await sample_noise()
                async with self._session.get(url) as resp:
                    content_type = resp.headers.get("content-type", "")
                    if not _is_textual_content_type(content_type):
                        return

                    # Limit body size to avoid huge responses.
                    raw = await resp.content.read(self._max_body_bytes)
                    try:
                        body = raw.decode("utf-8", errors="replace")
                    except Exception:
                        return
        except Exception:
            return

        stack_hits = _detect_stack_traces_for_body(
            origin=origin,
            body=body,
            stack_traces=self._stack_traces,
        )
        self._stack_rows.extend(stack_hits)

        hits = _detect_tech_leaks_for_body(
            origin=origin,
            body=body,
            signatures=self._signatures,
            compiled_aliases=self._alias_patterns,
        )
        self._rows.extend(hits)
