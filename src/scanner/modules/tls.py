from __future__ import annotations
import asyncio
import socket
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import ssl
import warnings
from OpenSSL import SSL

from scanner.modules.export import ModuleExport
from scanner.origin_health import *
from scanner.definitions import get_limiter, sample_noise, acquire_global_and_host

def _split_host_port(origin: str, default_port: int = 443) -> Tuple[str, int]:
    """Parse 'host[:port]' -> (host, port)."""
    if ":" in origin and not origin.endswith("]"):
        host, maybe = origin.rsplit(":", 1)
        try:
            return host, int(maybe)
        except ValueError:
            return origin, default_port
    return origin, default_port

def _set_exact_proto_version(ctx: SSL.Context, ver: int) -> None:
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            category=DeprecationWarning,
            message="Attempting to mutate a Context after a Connection was created.*",
        )
        ctx.set_min_proto_version(ver)
        ctx.set_max_proto_version(ver)

LEGACY_MAX = getattr(SSL, "TLS1_1_VERSION", None)
def _pyopenssl_handshake_exact(host: str, port: int, minmax_ver: int, timeout: float = 5.0) -> bool:
    """
    Perform a blocking TLS handshake where:
        min_proto_version == max_proto_version == minmax_ver

    Returns:
        True  if the handshake succeeds
        False if it fails (except for timeouts, which are re-raised so the
              caller can record them separately).
    """
    sock = None
    conn = None
    try:
        ctx = SSL.Context(SSL.TLS_METHOD)

        # For legacy versions (<= TLS 1.1), drop to SECLEVEL=0 so TLS 1.0/1.1
        # can actually negotiate on OpenSSL 3.x.
        if LEGACY_MAX is not None and minmax_ver <= LEGACY_MAX:
            try:
                ctx.set_cipher_list(b"DEFAULT:@SECLEVEL=0")
            except Exception as e:
                # Non-fatal; worst case we just get more handshake failures.
                print(f"[tls] failed to set SECLEVEL=0 for legacy probe: {e!r}")

        _set_exact_proto_version(ctx, minmax_ver)
        # ctx.set_min_proto_version(minmax_ver)
        # ctx.set_max_proto_version(minmax_ver)

        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        conn = SSL.Connection(ctx, sock)
        conn.set_connect_state()

        # SNI
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
        # Preserve timeout classification for the caller.
        if is_timeout_exc(e):
            raise
        return False

    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        if sock is not None:
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
    ):
        self._executor = executor
        self._timeout = float(timeout_s)
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
        print(f"[{self.name()}] Done.")

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

        if not should_run_tls_modules(origin):
            row.error = "origin offline"
            self._rows[origin] = row
            return

        loop = asyncio.get_running_loop()

        async def _guarded(func, *args):
            host = args[0]
            port = args[1]
            url_like = f"https://{host}:{port}"
            async with acquire_global_and_host(url_like):
                await sample_noise()
                return await loop.run_in_executor(self._executor, func, *args)


        if self._caps.can_tls13 and should_run_tls_modules(origin):
            try:
                row.tls13 = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.TLS1_3_VERSION, self._timeout)
            except Exception as e:
                record_tls_timeout(origin, e)
                row.tls13, row.error = False, f"{row.error} tls13:{e}"

        if self._caps.can_tls12 and should_run_tls_modules(origin):
            try:
                row.tls12 = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.TLS1_2_VERSION, self._timeout)
            except Exception as e:
                record_tls_timeout(origin, e)
                row.tls12, row.error = False, f"{row.error} tls12:{e}"

        if self._caps.can_tls11 and should_run_tls_modules(origin):
            try:
                row.tls11 = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.TLS1_1_VERSION, self._timeout)
            except Exception as e:
                record_tls_timeout(origin, e)
                row.tls11, row.error = False, f"{row.error} tls11:{e}"
        
        if self._caps.can_tls10 and should_run_tls_modules(origin):
            try:
                row.tls10 = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.TLS1_VERSION, self._timeout)
            except Exception as e:
                record_tls_timeout(origin, e)
                row.tls10, row.error = False, f"{row.error} tls10:{e}"
        
        # Nearly all clients dont support it.
        if self._caps.can_ssl_legacy and should_run_tls_modules(origin):
            try:
                row.ssl_legacy = await _guarded(_pyopenssl_handshake_exact, host, port, SSL.SSL3_VERSION, self._timeout)
            except Exception as e:
                record_tls_timeout(origin, e)
                row.ssl_legacy, row.error = False, f"{row.error} sslv3:{e}"

        self._rows[origin] = row
