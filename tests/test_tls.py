# tests/conftest_tls.py  (or paste at the top of tests/test_tls.py)
import ssl
import asyncio
from aiohttp import web
import pytest
from concurrent.futures import ThreadPoolExecutor

from scanner.modules.tls import TLSModule
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
        mod = TLSModule(executor=tiny_pool, timeout_s=5.0, concurrency=32)
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
        mod = TLSModule(executor=tiny_pool, timeout_s=5.0, concurrency=32)
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
        mod = TLSModule(executor=tiny_pool, timeout_s=5.0, concurrency=32)
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

# async def test_tls_legacy_acceptance_if_possible(tiny_pool):
#     if not _has("TLSv1"):
#         pytest.skip("Runner cannot expose TLSv1 server")

#     port = 9646
#     runner = await _start_https_app(port, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2)
#     try:
#         mod = TLSModule(executor=tiny_pool, timeout_s=5.0, concurrency=32)
#         caps = mod.probe_caps()

#         await mod.run([f"127.0.0.1:{port}"])
#         row = list(mod.results().values())[0]

#         if caps["can_tls12"]:
#             assert row["tls12"] is True
#         if caps["can_tls11"]:
#             assert row["tls11"] is True
#         if caps["can_tls10"]:
#             assert row["tls10"] is True
#     finally:
#         await runner.cleanup()