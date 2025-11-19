import ssl
import asyncio
from aiohttp import web
import pytest
from concurrent.futures import ThreadPoolExecutor

from OpenSSL import SSL
from scanner.modules.tls import TLSModule, _pyopenssl_handshake_exact
from scanner.definitions import PROJECT_ROOT

@pytest.fixture(scope="module")
def tiny_pool():
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="tls-test")
    yield pool
    pool.shutdown(wait=True, cancel_futures=True)

async def _https_app_ok():
    app = web.Application()
    async def root(_req):
        return web.Response(text="ok")
    app.router.add_get("/", root)
    return app

async def _start_https_app(port: int, min_ver: ssl.TLSVersion, max_ver: ssl.TLSVersion):
    app = await _https_app_ok()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    RES = PROJECT_ROOT / "tests" / "res"
    ctx.load_cert_chain(certfile=str(RES / "dev-cert.pem"), keyfile=str(RES / "dev-key.pem"))

    ctx.minimum_version = min_ver
    ctx.maximum_version = max_ver

    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port, ssl_context=ctx)
    await site.start()
    return runner

def _has(ver_name: str) -> bool:
    return hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, ver_name)

pytestmark = pytest.mark.asyncio

async def test_tls_13_only_reports_correctly(tiny_pool):
    if not (_has("TLSv1_3") and _has("TLSv1_2")):
        pytest.skip("Runner lacks TLSv1_2 or TLSv1_3 support in stdlib")

    port = 9643
    runner = await _start_https_app(port, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    try:
        mod = TLSModule(executor=tiny_pool, timeout_s=5.0)
        caps = mod.probe_caps()

        await mod.run([f"127.0.0.1:{port}"])
        row = list(mod.results().values())[0]

        assert row["tls13"] is True

        if caps["can_tls12"]:
            assert row["tls12"] is False
        else:
            assert row["tls12"] is None

        for key, cap in (("tls11", "can_tls11"), ("tls10", "can_tls10"), ("ssl_legacy", "can_ssl_legacy")):
            if caps[cap]:
                assert row[key] is False
            else:
                assert row[key] is None
    finally:
        await runner.cleanup()


async def test_tls_12_only_reports_correctly(tiny_pool):
    if not _has("TLSv1_2"):
        pytest.skip("Runner lacks TLSv1_2 support")

    port = 9644
    runner = await _start_https_app(port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
    try:
        mod = TLSModule(executor=tiny_pool, timeout_s=5.0)
        caps = mod.probe_caps()

        await mod.run([f"127.0.0.1:{port}"])
        row = list(mod.results().values())[0]

        if caps["can_tls12"]:
            assert row["tls12"] is True
        else:
            assert row["tls12"] is None

        if caps["can_tls13"]:
            assert row["tls13"] is False
        else:
            assert row["tls13"] is None

        for key, cap in (("tls11", "can_tls11"), ("tls10", "can_tls10"), ("ssl_legacy", "can_ssl_legacy")):
            if caps[cap]:
                assert row[key] is False
            else:
                assert row[key] is None
    finally:
        await runner.cleanup()



async def test_tls_12_and_13_reports_correctly(tiny_pool):
    if not (_has("TLSv1_2") and _has("TLSv1_3")):
        pytest.skip("Runner lacks TLSv1_2 or TLSv1_3 support")

    port = 9645
    runner = await _start_https_app(port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)
    try:
        mod = TLSModule(executor=tiny_pool, timeout_s=5.0)
        caps = mod.probe_caps()

        await mod.run([f"127.0.0.1:{port}"])
        row = list(mod.results().values())[0]

        if caps["can_tls13"]:
            assert row["tls13"] is True
        else:
            assert row["tls13"] is None

        if caps["can_tls12"]:
            assert row["tls12"] is True
        else:
            assert row["tls12"] is None

        for key, cap in (("tls11", "can_tls11"), ("tls10", "can_tls10"), ("ssl_legacy", "can_ssl_legacy")):
            if caps[cap]:
                assert row[key] is False
            else:
                assert row[key] is None
    finally:
        await runner.cleanup()

async def test_badssl_tls10_only_reports_correctly(tiny_pool):
    """
    Integration-ish test using tls-v1-0.badssl.com:1010.

    That endpoint is TLS 1.0 only, so we expect:
      - tls10 == True
      - tls11/tls12/tls13 == False
    """
    host = "tls-v1-0.badssl.com"
    port = 1010

    try:
        ok = _pyopenssl_handshake_exact(host, port, SSL.TLS1_VERSION, timeout=5.0)
    except Exception:
        ok = False

    if not ok:
        pytest.skip("Environment cannot complete TLS 1.0 handshake to tls-v1-0.badssl.com")

    mod = TLSModule(executor=tiny_pool, timeout_s=5.0)
    caps = mod.probe_caps()

    await mod.run([f"{host}:{port}"])
    row = list(mod.results().values())[0]

    if caps["can_tls10"]:
        assert row["tls10"] is True
    else:
        assert row["tls10"] is None

    for key, cap in (
        ("tls11", "can_tls11"),
        ("tls12", "can_tls12"),
        ("tls13", "can_tls13"),
    ):
        if caps[cap]:
            assert row[key] is False
        else:
            assert row[key] is None

    if caps["can_ssl_legacy"]:
        assert row["ssl_legacy"] is False
    else:
        assert row["ssl_legacy"] is None


async def test_badssl_tls11_only_reports_correctly(tiny_pool):
    """
    Integration-ish test using tls-v1-1.badssl.com:1011.

    That endpoint is TLS 1.1 only, so we expect:
      - tls11 == True        (if we can probe TLS 1.1)
      - tls10/tls12/tls13 == False (if we can probe them)
    """
    host = "tls-v1-1.badssl.com"
    port = 1011

    # Sanity-check TLS 1.1 handshake to this host; skip if env/network breaks it.
    try:
        ok = _pyopenssl_handshake_exact(host, port, SSL.TLS1_1_VERSION, timeout=5.0)
    except Exception:
        ok = False

    if not ok:
        pytest.skip("Environment cannot complete TLS 1.1 handshake to tls-v1-1.badssl.com")

    mod = TLSModule(executor=tiny_pool, timeout_s=5.0)
    caps = mod.probe_caps()

    await mod.run([f"{host}:{port}"])
    row = list(mod.results().values())[0]

    # TLS 1.1 should be True if we can probe it, else None
    if caps["can_tls11"]:
        assert row["tls11"] is True
    else:
        assert row["tls11"] is None

    # TLS 1.0 / 1.2 / 1.3 should be rejected by this host
    for key, cap in (
        ("tls10", "can_tls10"),
        ("tls12", "can_tls12"),
        ("tls13", "can_tls13"),
    ):
        if caps[cap]:
            assert row[key] is False
        else:
            assert row[key] is None

    # SSLv3: same story as above
    if caps["can_ssl_legacy"]:
        assert row["ssl_legacy"] is False
    else:
        assert row["ssl_legacy"] is None
