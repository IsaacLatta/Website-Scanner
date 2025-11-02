from __future__ import annotations
import asyncio
import socket
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import ssl
from OpenSSL import SSL

from scanner.modules.export import ModuleExport

def _split_host_port(origin: str, default_port: int = 443) -> Tuple[str, int]:
    """Parse 'host[:port]' -> (host, port)."""
    if ":" in origin and not origin.endswith("]"):
        host, maybe = origin.rsplit(":", 1)
        try:
            return host, int(maybe)
        except ValueError:
            return origin, default_port
    return origin, default_port


def _pyopenssl_handshake_exact(host: str, port: int, minmax_ver: int, timeout: float = 5.0) -> bool:
    sock = None
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(minmax_ver)
        ctx.set_max_proto_version(minmax_ver)

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
        try:
            conn.shutdown()
        except Exception:
            pass
        return True
    except Exception as e:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass

@dataclass
class TLSRow:
    origin: str
    port: int
    tls13: Optional[bool]
    tls12: Optional[bool]
    tls11: Optional[bool]
    tls10: Optional[bool]
    ssl_legacy: Optional[bool]
    error: str = ""


@dataclass
class TLSProbeCaps:
    can_tls13: bool
    can_tls12: bool
    can_tls11: bool
    can_tls10: bool
    can_ssl_legacy: bool


def _detect_caps() -> TLSProbeCaps:
    """
    Detect which protocol versions this *client* can actually probe, based on
    the linked OpenSSL/Python build. This prevents false negatives.
    """
    can13 = hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_3")
    can12 = hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_2")

    can11 = hasattr(SSL, "TLS1_1_VERSION")
    can10 = hasattr(SSL, "TLS1_VERSION")
    canssl = hasattr(SSL, "SSL3_VERSION")

    caps = TLSProbeCaps(
        can_tls13=can13,
        can_tls12=can12,
        can_tls11=can11,
        can_tls10=can10,
        can_ssl_legacy=canssl,
    )

    print(
        "[TLS probe caps] "
        f"tls1.3={caps.can_tls13} tls1.2={caps.can_tls12} "
        f"tls1.1={caps.can_tls11} tls1.0={caps.can_tls10} sslv3={caps.can_ssl_legacy}"
    )

    return caps

class TLSModule(ModuleExport):
    def __init__(
        self,
        *,
        executor: ThreadPoolExecutor,
        timeout_s: float,
        concurrency: int = 200,
    ):
        self._executor = executor
        self._timeout = float(timeout_s)
        self._sem = asyncio.Semaphore(concurrency)
        self._caps = _detect_caps()
        self._rows: Dict[str, TLSRow] = {}

    def name(self) -> str:
        return "tls"

    def scope(self) -> str:
        return "origin"

    def results(self) -> Dict[str, Dict]:
        return {k: asdict(v) for k, v in self._rows.items()}

    def probe_caps(self) -> Dict[str, bool]:
        return asdict(self._caps)

    async def run(self, origins: List[str]) -> None:
        await asyncio.gather(*(self._scan_one(o) for o in origins))

    async def _scan_one(self, origin: str) -> None:
        host, port = _split_host_port(origin, 443)
        row = TLSRow(
            origin=origin,
            port=port,
            tls13=None,
            tls12=None,
            tls11=None,
            tls10=None,
            ssl_legacy=None,
            error="",
        )

        loop = asyncio.get_running_loop()

        async def _guarded(func, *args):
            async with self._sem:
                return await loop.run_in_executor(self._executor, func, *args)

        if self._caps.can_tls13:
            try:
                row.tls13 = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.TLS1_3_VERSION, self._timeout)
            except Exception as e:
                row.tls13, row.error = False, f"{row.error} tls13:{e}"
        if self._caps.can_tls12:
            try:
                row.tls12 = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.TLS1_2_VERSION, self._timeout)
            except Exception as e:
                row.tls12, row.error = False, f"{row.error} tls12:{e}"

        if self._caps.can_tls11:
            try:
                row.tls11 = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.TLS1_1_VERSION, self._timeout)
            except Exception as e:
                row.tls11, row.error = False, f"{row.error} tls11:{e}"
        if self._caps.can_tls10:
            try:
                row.tls10 = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.TLS1_VERSION, self._timeout)
            except Exception as e:
                row.tls10, row.error = False, f"{row.error} tls10:{e}"
        if self._caps.can_ssl_legacy:
            try:
                row.ssl_legacy = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.SSL3_VERSION, self._timeout)
            except Exception as e:
                row.ssl_legacy, row.error = False, f"{row.error} sslv3:{e}"

        self._rows[origin] = row
