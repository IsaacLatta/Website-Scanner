import asyncio, aiohttp, ssl
from typing import Dict, List
from scanner.modules.export import ModuleExport, Scope 

def _check_correctness(content: bytes) -> str:
    has_contact = b'contact' in content.lower()
    has_expires = b'expires' in content.lower()
    if has_contact and has_expires: return 'both'
    if has_contact: return 'contact'
    if has_expires: return 'expires'
    return 'none'

def default_locations() -> List[str]:
    return ["/.well-known/security.txt", "/security.txt"]

class SecurityTxtExport(ModuleExport):
    def __init__(
        self,
        *,
        verify_certificate: bool,
        timeout_s: int,
        session: aiohttp.ClientSession,
        locations: List[str] | None = None
    ):
        self._timeout_s = timeout_s
        self._verify_cert = verify_certificate
        self._session = session
        self._locations = locations or default_locations()
        self._results: Dict[str, Dict] = {}

    def name(self) -> str:
        return "security.txt"

    def scope(self) -> str:
        return "origin"

    def csv_columns(self) -> List[str]:
        return [
            "security.txt_present",
            "security.txt_correctness",
            "security.txt_location",
            "security.txt_error"        
            ]

    def results(self) -> dict:
        return self._results

    async def run(self, domains: List[str]) -> None:
        timeout = aiohttp.ClientTimeout(total=self._timeout_s)
        tasks = [self._check_domain(domain, timeout) for domain in domains]
        await asyncio.gather(*tasks)

    async def _check_domain(self, domain: str, timeout: aiohttp.ClientTimeout) -> None:
        result = {
            "security.txt_present": False,
            "security.txt_correctness": "none",
            "security.txt_location": "",
            "security.txt_error": ""
        }
        for location in self._locations:
            url = f"https://{domain}{location}"
            try:
                async with self._session.get(url, timeout=timeout) as resp:
                    if resp.status == 200:
                        content = await resp.read()
                        result["security.txt_present"] = True
                        result["security.txt_location"] = location
                        result["security.txt_correctness"] = _check_correctness(content)
                        self._results[domain] = result
                        return
            except Exception as e:
                result["security.txt_error"] = str(e)
                continue
        self._results[domain] = result
