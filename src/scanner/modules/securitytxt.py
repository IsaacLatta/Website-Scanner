from __future__ import annotations
import asyncio, aiohttp, csv
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from datetime import datetime, timezone
from aiohttp import ClientTimeout, ClientError

from scanner.definitions import get_limiter, log_rate_limit, acquire_global_and_host
from scanner.origin_health import *
from scanner.modules.export import ModuleExport

_MAX_BYTES = 32 * 1024
_MAX_LINES = 1000

def _safe_decode(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")

def _parse_rfc3339(ts: str) -> datetime | None:
    try:
        if ts.endswith("Z") or ts.endswith("z"):
            return datetime.fromisoformat(ts[:-1]).replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def default_locations() -> list[str]:
    return ["/.well-known/security.txt", "/security.txt"]

def _parse_security_txt(lines: List[str]) -> Dict[str, object]:
    """
    Minimal RFC 9116 parser:
    - strip comments (# …)
    - field-name is case-insensitive
    - allow multiple Contact and Canonical
    - Expires must be exactly one occurrence (we keep first valid)
    """
    contacts: List[str] = []
    canon: List[str] = []
    expires_dt: datetime | None = None
    expires_raw = ""

    for raw in lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if ":" not in s:
            continue
        k, v = s.split(":", 1)
        key = k.strip().lower()
        val = v.strip()

        if key == "contact":
            contacts.append(val)
        elif key == "canonical":
            canon.append(val)
        elif key == "expires" and not expires_dt:
            dt = _parse_rfc3339(val)
            if dt is not None:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                expires_dt = dt
                expires_raw = val

    return {
        "contact": contacts,
        "canonical": canon,
        "expires": expires_dt,
        "expires_raw": expires_raw,
    }

@dataclass
class SecurityTxtResult:
    origin: str
    present: bool
    has_contact: bool
    has_expires: bool
    expires_valid: bool
    expires_value: str
    contacts: str
    canonical: str
    location: str
    error: str

class SecurityTxtExport(ModuleExport):
    def __init__(
        self,
        *,
        verify_certificate: bool,
        timeout_s: int,
        session: aiohttp.ClientSession,
        locations: List[str] | None = None,
    ):
        self._timeout = ClientTimeout(total=timeout_s)
        self._session = session
        self._locations = locations or default_locations()
        self._results: Dict[str, SecurityTxtResult] = {}

    def name(self) -> str: return "securitytxt"
    def scope(self) -> str: return "origin"

    def results(self) -> Dict[str, Dict]:
        return {k: asdict(v) for k,v in self._results.items()}

    async def run(self, origins: List[str]) -> None:
        tasks = [self._scan_one(o) for o in origins]
        await asyncio.gather(*tasks)

    async def _scan_one(self, origin: str) -> None:
        row = SecurityTxtResult(
            origin=origin, present=False, has_contact=False, has_expires=False,
            expires_valid=False, expires_value="", contacts="", canonical="",
            location="", error=""
        )

        if not should_run_http_modules(origin):
            row.error = "origin offline"
            self._results[origin] = row
            return

        for loc in self._locations:
            url = f"https://{origin}{loc}"
            async with acquire_global_and_host(url):
                try:
                    async with self._session.get(url, timeout=self._timeout) as resp:
                        await log_rate_limit(url, resp, "securitytxt")
                        
                        if resp.status != 200:
                            continue
                        
                        content = await resp.content.read(_MAX_BYTES + 1)
                        if len(content) > _MAX_BYTES:
                            row.error = "file_too_large"
                            break
                        
                        text = _safe_decode(content)
                        lines = text.splitlines()
                        if len(lines) > _MAX_LINES:
                            row.error = "too_many_lines"
                            break

                        parsed = _parse_security_txt(lines)
                        row.present = True
                        row.has_contact = len(parsed["contact"]) > 0
                        row.has_expires = parsed["expires"] is not None
                        row.expires_value = parsed["expires_raw"]

                        if parsed["expires"] is not None:
                            row.expires_valid = parsed["expires"] > datetime.now(timezone.utc)

                        row.contacts = ",".join(parsed["contact"])
                        row.canonical = ",".join(parsed["canonical"])
                        row.location = loc
                        break
                except (asyncio.TimeoutError, ClientError) as e:
                    record_http_timeout(origin)
                    row.error = f"timeout:{type(e).__name__}"
                    print(f"[{self.name()}] timeout:{type(e).__name__}")
                except Exception as e:
                    row.error = str(e)
                    continue

        self._results[origin] = row


