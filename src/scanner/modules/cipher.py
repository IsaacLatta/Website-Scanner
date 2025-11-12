from __future__ import annotations

import asyncio
import functools
import socket
import ssl
from OpenSSL import SSL 
import requests
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from OpenSSL import SSL  # pyOpenSSL

from scanner.modules.export import ModuleExport
from scanner.definitions import get_limiter, sample_noise, acquire_global_and_host
from scanner.origin_health import *

# From CCSA
TLS13_RECOMMENDED = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_128_CCM_SHA256",
]
TLS13_SUFFICIENT = [
    "TLS_AES_128_CCM_8_SHA256",
]

# From CCSA
TLS12_RECOMMENDED = [
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-CCM",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES128-CCM",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
]
TLS12_SUFFICIENT = [
    "ECDHE-ECDSA-AES256-CCM8",
    "ECDHE-ECDSA-AES128-CCM8",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
]

# NSA "never use" families consolidated as one OpenSSL cipher string for TLS<=1.2
INSECURE_CIPHER_STRING_TLS12 = "eNULL:aNULL:NULL:EXPORT:LOW:RC4:DES:IDEA:MD5:3DES:SHA1"

def _join(names: List[str]) -> str:
    return ":".join(names)

@dataclass
class CipherRow:
    origin: str
    port: int

    negotiated_version: str
    negotiated_cipher: str
    negotiated_security: Optional[str]

    # Category is in ["recommended", "sufficient", "unknown", None]

    tls13_forced_cipher: Optional[str]
    tls13_forced_category: Optional[str]  

    tls12_forced_cipher: Optional[str]
    tls12_forced_category: Optional[str]

    accepts_recommended_tls12: Optional[bool]
    accepts_sufficient_tls12: Optional[bool]
    accepts_insecure_tls12: Optional[bool]

    allows_sha1_tls12: Optional[bool]
    allows_cbc_tls12: Optional[bool]

    error: str = ""

# "catalog" is the ciphersuite.info JSON, injected so tests can mock easily
CipherCatalog = List[Dict[str, Dict[str, object]]]

def _split_host_port(origin: str, default_port: int = 443) -> Tuple[str, int]:
    if ":" in origin and not origin.endswith("]"):
        host, maybe = origin.rsplit(":", 1)
        try:
            return host, int(maybe)
        except ValueError:
            return origin, default_port
    return origin, default_port

def build_catalog_from_api(timeout_s: float = 6.0) -> CipherCatalog:
    url = "https://ciphersuite.info/api/cs/"
    try:
        resp = requests.get(url, timeout=timeout_s)
        resp.raise_for_status()
        data = resp.json()
        ciphersuites = data.get("ciphersuites")
        if isinstance(ciphersuites, list):
            return ciphersuites
    except Exception as e: 
        print(f"WARNING: Could not load cipher suite data from {url}: {e}")
    return []

def _pyopenssl_handshake(
    host: str,
    port: int,
    *,
    min_ver: Optional[int] = None,
    max_ver: Optional[int] = None,
    tls13_ciphers: Optional[str] = None,
    tls12_ciphers: Optional[str] = None,
    timeout: float = 5.0,
) -> Tuple[bool, str, str]:
    sock = None
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)
        if min_ver is not None:
            ctx.set_min_proto_version(min_ver)
        if max_ver is not None:
            ctx.set_max_proto_version(max_ver)

        if tls12_ciphers:
            ctx.set_cipher_list(tls12_ciphers.encode("ascii"))

        # Some machine's have older ssl builds installed, even if a 
        # a modern PyOpenSSL (>= 3.1.1) package is present, seems 
        # like the system install can override. Thus, preventing
        # this scanner from forcing certain cipher suites at tls 1.3.
        if tls13_ciphers and hasattr(ctx, "set_ciphersuites"):
            try:
                ctx.set_ciphersuites(tls13_ciphers.encode("ascii"))
            except Exception:
                pass

        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        conn = SSL.Connection(ctx, sock)
        conn.set_connect_state()
        try:
            conn.set_tlsext_host_name(host.encode("utf-8"))
        except Exception:
            pass

        conn.setblocking(True)
        conn.do_handshake()

        cipher = conn.get_cipher_name() or ""
        try:
            proto = conn.get_protocol_version_name() or ""
        except Exception:
            proto = ""

        try:
            conn.shutdown()
        except Exception:
            pass
        return True, cipher, proto
    except Exception as e:
        if is_timeout_exc(e):
            raise
        return False, "", ""
    finally:
        try:
            sock.close()
        except Exception:
            pass

def _make_catalog_lookup(catalog: Optional[CipherCatalog]) -> Dict[str, str]:
    if not catalog:
        return {}
    out: Dict[str, str] = {}
    for entry in catalog:
        for iana, meta in entry.items():
            sec = str(meta.get("security", "") or "")
            ossl = str(meta.get("openssl_name", "") or "")
            if iana:
                out[iana] = sec
            if ossl:
                out[ossl] = sec
    return out

def _classify_tls13(cipher: str) -> str:
    if cipher in TLS13_RECOMMENDED:
        return "recommended"
    if cipher in TLS13_SUFFICIENT:
        return "sufficient"
    return "unknown"

def _classify_tls12(cipher: str) -> str:
    if cipher in TLS12_RECOMMENDED:
        return "recommended"
    if cipher in TLS12_SUFFICIENT:
        return "sufficient"
    lower = cipher.lower()
    if any(tok in lower for tok in ("rc4", "3des", "des", "md5")):
        return "insecure"
    if "sha1" in lower:
        return "insecure"
    if lower.endswith("-sha") or lower.endswith("_sha"):
        return "insecure"
    return "unknown"

class CipherSuitesModule(ModuleExport):
    def __init__(
        self,
        *,
        executor: ThreadPoolExecutor,
        timeout_s: float = 6.0,
        catalog: Optional[CipherCatalog] = None
    ):
        self._exec = executor
        self._timeout = float(timeout_s)
        self._rows: Dict[str, CipherRow] = {}

        if catalog is None:
            catalog = build_catalog_from_api(timeout_s=self._timeout)
        self._catalog_lookup = _make_catalog_lookup(catalog or [])

        self._can_tls13 = hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_3")
        if not self._can_tls13:
            print("ssl missing TLSv1_3, omitting TLSv1_3 scans!")

        self._can_tls12 = True

    def name(self) -> str: return "ciphers"
    def scope(self) -> str: return "origin"
    def results(self) -> Dict[str, Dict]: return {k: asdict(v) for k, v in self._rows.items()}

    async def run(self, origins: List[str]) -> None:
        await asyncio.gather(*(self._scan_one(o) for o in origins))

    async def _in_executor(self, func, *args, **kwargs):
        loop = asyncio.get_running_loop()
        bound = functools.partial(func, *args, **kwargs)
        host = args[0]
        port = args[1]
        url_like = f"https://{host}:{port}"

        async with acquire_global_and_host(url_like):
            return await loop.run_in_executor(self._exec, bound)

    async def _natural(self, host: str, port: int) -> Tuple[bool, str, str]:
        return await self._in_executor(
            _pyopenssl_handshake, host, port,
            min_ver=None, max_ver=None, tls13_ciphers=None, tls12_ciphers=None,
            timeout=self._timeout,
        )

    async def _force_tls13_observe(self, host: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        if not self._can_tls13:
            return None, None
        ok, cipher, proto = await self._in_executor(
            _pyopenssl_handshake, host, port,
            min_ver=SSL.TLS1_3_VERSION, max_ver=SSL.TLS1_3_VERSION,
            tls13_ciphers=None, tls12_ciphers=None,
            timeout=self._timeout,
        )
        if not ok or not proto.startswith("TLSv1.3"):
            return None, None
        return cipher, _classify_tls13(cipher)

    async def _force_tls12_observe(self, host: str, port: int) -> Tuple[Optional[str], Optional[str]]:
        if not self._can_tls12:
            return None, None
        ok, cipher, proto = await self._in_executor(
            _pyopenssl_handshake, host, port,
            min_ver=SSL.TLS1_2_VERSION, max_ver=SSL.TLS1_2_VERSION,
            tls13_ciphers=None, tls12_ciphers=None,
            timeout=self._timeout,
        )
        if not ok or not proto.startswith("TLSv1.2"):
            return None, None
        return cipher, _classify_tls12(cipher)

    async def _try_bucket_tls12(self, host: str, port: int, names12: List[str]) -> Optional[bool]:
        if not self._can_tls12 or not names12:
            return None
        ok, cipher, proto = await self._in_executor(
            _pyopenssl_handshake, host, port,
            min_ver=SSL.TLS1_2_VERSION, max_ver=SSL.TLS1_2_VERSION,
            tls13_ciphers=None, tls12_ciphers=_join(names12),
            timeout=self._timeout,
        )
        return bool(ok and proto.startswith("TLSv1.2") and cipher in names12)

    async def _try_insecure_tls12(self, host: str, port: int) -> Optional[bool]:
        if not self._can_tls12:
            return None
        ok, _, proto = await self._in_executor(
            _pyopenssl_handshake, host, port,
            min_ver=SSL.TLS1_2_VERSION, max_ver=SSL.TLS1_2_VERSION,
            tls13_ciphers=None, tls12_ciphers=INSECURE_CIPHER_STRING_TLS12,
            timeout=self._timeout,
        )
        return bool(ok and proto.startswith("TLSv1.2"))

    async def _probe_sha1_tls12(self, host: str, port: int) -> Optional[bool]:
        if not self._can_tls12:
            return None
        ok, _, proto = await self._in_executor(
            _pyopenssl_handshake, host, port,
            min_ver=SSL.TLS1_2_VERSION, max_ver=SSL.TLS1_2_VERSION,
            tls13_ciphers=None, tls12_ciphers="SHA1",
            timeout=self._timeout,
        )
        return bool(ok and proto.startswith("TLSv1.2"))

    async def _probe_cbc_tls12(self, host: str, port: int) -> Optional[bool]:
        if not self._can_tls12:
            return None
        ok, _, proto = await self._in_executor(
            _pyopenssl_handshake, host, port,
            min_ver=SSL.TLS1_2_VERSION, max_ver=SSL.TLS1_2_VERSION,
            tls13_ciphers=None, tls12_ciphers="CBC",
            timeout=self._timeout,
        )
        return bool(ok and proto.startswith("TLSv1.2"))

    async def _scan_one(self, origin: str) -> None:
        host, port = _split_host_port(origin, 443)
        row = CipherRow(
            origin=origin, port=port,
            negotiated_version="", negotiated_cipher="", negotiated_security=None,
            tls13_forced_cipher=None, tls13_forced_category=None,
            tls12_forced_cipher=None, tls12_forced_category=None,
            accepts_recommended_tls12=None, accepts_sufficient_tls12=None, accepts_insecure_tls12=None,
            allows_sha1_tls12=None, allows_cbc_tls12=None, error="",
        )

        if not should_run_tls_modules(origin):
            row.error = "origin offline"
            self._rows[origin] = row
            return

        async def _guard_tls(label: str, coro):
            if not should_run_tls_modules(origin):
                return None

            try:
                return await coro
            except Exception as e:
                record_tls_timeout(origin, e)
                row.error += ("" if not row.error else " | ") + f"{label}_timeout:{type(e).__name__}"
                raise

        try:
            # 1) Natural handshake
            res = await _guard_tls("natural", self._natural(host, port))
            if res is not None:
                ok, cipher, proto = res
                row.negotiated_cipher = cipher
                row.negotiated_version = proto

                if cipher and self._catalog_lookup:
                    row.negotiated_security = (
                        self._catalog_lookup.get(cipher)
                        or self._catalog_lookup.get(cipher.replace("_", "-"))
                    )

                if not ok and not cipher:
                    row.error += ("" if not row.error else " | ") + "natural_handshake_failed"

            # 2) TLS 1.3 forced observe
            await sample_noise()
            res13 = await _guard_tls("tls13_obs", self._force_tls13_observe(host, port))
            if res13 is not None:
                c13, cat13 = res13
                row.tls13_forced_cipher = c13
                row.tls13_forced_category = cat13

            # 3) TLS 1.2 forced + buckets
            await sample_noise()
            res12 = await _guard_tls("tls12_obs", self._force_tls12_observe(host, port))
            if res12 is not None:
                c12, cat12 = res12
                row.tls12_forced_cipher = c12
                row.tls12_forced_category = cat12

                await sample_noise()
                row.accepts_recommended_tls12 = await _guard_tls(
                    "tls12_recommended",
                    self._try_bucket_tls12(host, port, TLS12_RECOMMENDED),
                )

                await sample_noise()
                row.accepts_sufficient_tls12 = await _guard_tls(
                    "tls12_sufficient",
                    self._try_bucket_tls12(host, port, TLS12_SUFFICIENT),
                )

                await sample_noise()
                row.accepts_insecure_tls12 = await _guard_tls(
                    "tls12_insecure",
                    self._try_insecure_tls12(host, port),
                )

                await sample_noise()
                row.allows_sha1_tls12 = await _guard_tls(
                    "tls12_sha1",
                    self._probe_sha1_tls12(host, port),
                )

                await sample_noise()
                row.allows_cbc_tls12 = await _guard_tls(
                    "tls12_cbc",
                    self._probe_cbc_tls12(host, port),
                )

        except Exception:
            # Any timeout will land here after record_tls_timeout + row.error update.
            # We don't need to re-raise; we just stop further probes for this origin.
            pass

        self._rows[origin] = row

        # ok, cipher, proto = await self._natural(host, port)
        # row.negotiated_cipher = cipher
        # row.negotiated_version = proto
        # if cipher and self._catalog_lookup:
        #     row.negotiated_security = self._catalog_lookup.get(cipher) or \
        #                               self._catalog_lookup.get(cipher.replace("_", "-"))
        # if not ok and not cipher:
        #     row.error = "natural_handshake_failed"

        # try:
        #     await sample_noise()
        #     c13, cat13 = await self._force_tls13_observe(host, port)
        #     row.tls13_forced_cipher = c13
        #     row.tls13_forced_category = cat13
        # except Exception as e:
        #     row.error += f" | tls13_obs:{e}"

        # try:
        #     await sample_noise()
        #     c12, cat12 = await self._force_tls12_observe(host, port)
        #     row.tls12_forced_cipher = c12
        #     row.tls12_forced_category = cat12
        #     await sample_noise()
        #     row.accepts_recommended_tls12 = await self._try_bucket_tls12(host, port, TLS12_RECOMMENDED)
        #     await sample_noise()
        #     row.accepts_sufficient_tls12 = await self._try_bucket_tls12(host, port, TLS12_SUFFICIENT)
        #     await sample_noise()
        #     row.accepts_insecure_tls12 = await self._try_insecure_tls12(host, port)
        #     await sample_noise()
        #     row.allows_sha1_tls12 = await self._probe_sha1_tls12(host, port)
        #     await sample_noise()
        #     row.allows_cbc_tls12 = await self._probe_cbc_tls12(host, port)
        # except Exception as e:
        #     row.error += f" | tls12:{e}"

        # self._rows[origin] = row
