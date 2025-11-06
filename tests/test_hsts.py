import ssl, aiohttp
import pytest_asyncio
from aiohttp import web
from pathlib import Path
from scanner.modules.hsts import HSTSModule
from scanner.definitions import PROJECT_ROOT

RES = PROJECT_ROOT / "tests" / "res"
CERT = RES / "dev-cert.pem"
KEY  = RES / "dev-key.pem"

@pytest_asyncio.fixture
async def session():
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as s:
        yield s

@pytest_asyncio.fixture
async def http_https_sites():
    async def _http_app_redirect_to_https(port_https: int):
        app = web.Application()
        async def root(_req):
            raise web.HTTPMovedPermanently(
                location=f"https://127.0.0.1:{port_https}/"
            )
        app.router.add_get("/", root)
        return app

    async def _https_app_with_hsts(hsts_value: str):
        app = web.Application()
        async def root(_req):
            return web.Response(text="ok",
                                headers={"Strict-Transport-Security": hsts_value})
        app.router.add_get("/", root)
        return app

    async def _start_http(app, port: int):
        r = web.AppRunner(app); await r.setup()
        s = web.TCPSite(r, "127.0.0.1", port); await s.start()
        return r

    async def _start_https(app, port: int):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(CERT), keyfile=str(KEY))
        r = web.AppRunner(app); await r.setup()
        s = web.TCPSite(r, "127.0.0.1", port, ssl_context=ctx); await s.start()
        return r

    return _http_app_redirect_to_https, _https_app_with_hsts, _start_http, _start_https

@pytest_asyncio.fixture
async def starters():
    async def _start_http(app, port: int):
        r = web.AppRunner(app); await r.setup()
        site = web.TCPSite(r, "127.0.0.1", port); await site.start()
        return r

    async def _start_https(app, port: int):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(CERT), keyfile=str(KEY))
        r = web.AppRunner(app); await r.setup()
        site = web.TCPSite(r, "127.0.0.1", port, ssl_context=ctx); await site.start()
        return r

    return _start_http, _start_https

async def test_hsts_redirect_and_header(session, http_https_sites):
    _http_app_redirect_to_https, _https_app_with_hsts, _start_http, _start_https = http_https_sites

    http_port, https_port = 9800, 9443
    http_app  = await _http_app_redirect_to_https(https_port)
    https_app = await _https_app_with_hsts("max-age=31536000; includeSubDomains; preload")

    r1 = await _start_http(http_app,  http_port)
    r2 = await _start_https(https_app, https_port)

    try:
        mod = HSTSModule(session=session, timeout_s=5)
        await mod.run([f"127.0.0.1:{http_port}"])

        res = list(mod.results().values())[0]
        assert res["redirected_to_https"] is True
        assert res["redirect_status"] in (301, 308)
        assert res["https_ok"] is True
        assert res["has_hsts"] is True
        assert res["max_age_ge_1yr"] is True
        assert res["include_subdomains"] is True
        assert res["preload"] is True
    finally:
        await r1.cleanup()
        await r2.cleanup()

async def test_hsts_no_redirect(session, starters):
    _start_http, _ = starters
    http_port = 9810

    http_app = web.Application()
    async def http_root(_req):
        return web.Response(text="plain http ok")
    http_app.router.add_get("/", http_root)

    r1 = await _start_http(http_app, http_port)

    try:
        mod = HSTSModule(session=session, timeout_s=5)
        await mod.run([f"127.0.0.1:{http_port}"])
        res = list(mod.results().values())[0]

        assert res["redirected_to_https"] is False
        assert res["redirect_status"] == 200
        assert res["redirect_location"] == ""
        assert res["https_ok"] is False
        assert res["has_hsts"] is False
    finally:
        await r1.cleanup()


async def test_hsts_redirect_to_non_existent_location(session, starters):
    _start_http, _start_https = starters
    http_port = 9811

    http_app = web.Application()
    async def http_root(_req):
        raise web.HTTPFound(location="/dne")
    http_app.router.add_get("/", http_root)

    r1 = await _start_http(http_app, http_port)
    try:
        mod = HSTSModule(session=session, timeout_s=5)
        await mod.run([f"127.0.0.1:{http_port}"])
        res = list(mod.results().values())[0]

        assert res["redirected_to_https"] is False
        assert res["redirect_status"] == 302
        assert res["https_ok"] is False
    finally:
        await r1.cleanup()


async def test_hsts_header_weak(session, starters):
    _start_http, _start_https = starters
    http_port, https_port = 9812, 9446

    http_app = web.Application()
    async def http_root(_req):
        raise web.HTTPMovedPermanently(location=f"https://127.0.0.1:{https_port}/")
    http_app.router.add_get("/", http_root)

    https_app = web.Application()
    async def https_root(_req):
        # short max-age, no includeSubDomains, no preload
        return web.Response(text="ok", headers={"Strict-Transport-Security": "max-age=1000"})
    https_app.router.add_get("/", https_root)

    r1 = await _start_http(http_app, http_port)
    r2 = await _start_https(https_app, https_port)
    try:
        mod = HSTSModule(session=session, timeout_s=5)
        await mod.run([f"127.0.0.1:{http_port}"])
        res = list(mod.results().values())[0]

        assert res["redirected_to_https"] is True
        assert res["redirect_status"] in (301, 308)
        assert res["https_ok"] is True

        assert res["has_hsts"] is True
        assert res["max_age_ge_1yr"] is False
        assert res["include_subdomains"] is False
        assert res["preload"] is False
    finally:
        await r1.cleanup(); await r2.cleanup()


