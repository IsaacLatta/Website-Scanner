import ssl, aiohttp, pytest, pytest_asyncio
from aiohttp import web
from scanner.modules.connectivity import HTTPSConnectivityExport

pytestmark = pytest.mark.asyncio

async def server_with(headers=None, body=b"ok"):
    headers = headers or {}
    app = web.Application()
    async def root(_req):
        return web.Response(body=body, headers=headers)
    app.router.add_get("/", root)
    return app

async def start_site(app, port, ssl_ctx):
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port, ssl_context=ssl_ctx); await site.start()
    return runner

@pytest_asyncio.fixture
async def ssl_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile="tests/res/dev-cert.pem", keyfile="tests/res/dev-key.pem")
    return ctx

@pytest_asyncio.fixture
async def session():
    client_ctx = ssl.create_default_context()
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(limit=20, limit_per_host=5, ssl=client_ctx)
    s = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=5))
    yield s
    await s.close()

async def test_https_success_and_hsts_present(ssl_ctx, session):
    app = await server_with(headers={"Strict-Transport-Security": "max-age=31536000"})
    r = await start_site(app, 9043, ssl_ctx)
    try:
        mod = HTTPSConnectivityExport(session=session, timeout_s=5)
        await mod.run(["127.0.0.1:9043"])
        row = mod.results()["127.0.0.1:9043"]
        assert row["success"] is True
        assert row["final_scheme"] == "https"
        assert isinstance(row["status"], int) and 200 <= row["status"] < 600
        assert row["has_hsts"] is True
        assert row["redirects"] == 0
        assert row["error"] == ""
    finally:
        await r.cleanup()

async def test_https_success_no_hsts(ssl_ctx, session):
    app = await server_with(headers={})
    r = await start_site(app, 9143, ssl_ctx)
    try:
        mod = HTTPSConnectivityExport(session=session, timeout_s=5)
        await mod.run(["127.0.0.1:9143"])
        row = mod.results()["127.0.0.1:9143"]
        assert row["success"] is True
        assert row["has_hsts"] is False
    finally:
        await r.cleanup()

async def test_https_unreachable_is_failure(session):
    mod = HTTPSConnectivityExport(session=session, timeout_s=2)
    await mod.run(["127.0.0.1:9243"])
    row = mod.results()["127.0.0.1:9243"]
    assert row["success"] is False
    assert row["status"] is None
    assert row["final_scheme"] in ("", "https")
    assert row["error"] 
