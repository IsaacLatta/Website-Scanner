# tests/test_securitytxt.py
import ssl, asyncio, aiohttp, pytest, pytest_asyncio
from aiohttp import web
from scanner.modules.securitytxt import SecurityTxtExport

pytestmark = pytest.mark.asyncio

SEC_TXT_WK = b"Contact: mailto:sec@example.test\nExpires: 2099-12-31T23:59:59Z\n"
SEC_TXT_CONTACT_ONLY = b"Contact: mailto:soc@example.test\n"

async def server_with(path_content_map):
    app = web.Application()
    for path, content in path_content_map.items():
        async def handler(_req, c=content):
            return web.Response(body=c, content_type="text/plain")
        app.router.add_get(path, handler)
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

async def test_securitytxt_variants(ssl_ctx, session):
    a = await server_with({"/.well-known/security.txt": SEC_TXT_WK})
    b = await server_with({"/security.txt": SEC_TXT_CONTACT_ONLY})
    ra = await start_site(a, 8443, ssl_ctx)
    rb = await start_site(b, 9443, ssl_ctx)

    try:
        mod = SecurityTxtExport(verify_certificate=False, timeout_s=5, session=session)
        domains = ["127.0.0.1:8443", "127.0.0.1:9443", "127.0.0.1:10443"]
        await mod.run(domains)
        res = mod.results()

        assert res["127.0.0.1:8443"]["security.txt_present"] is True
        assert res["127.0.0.1:8443"]["security.txt_correctness"] == "both"
        assert res["127.0.0.1:8443"]["security.txt_location"] == "/.well-known/security.txt"

        assert res["127.0.0.1:9443"]["security.txt_present"] is True
        assert res["127.0.0.1:9443"]["security.txt_correctness"] == "contact"
        assert res["127.0.0.1:9443"]["security.txt_location"] == "/security.txt"

        assert res["127.0.0.1:10443"]["security.txt_present"] is False
    finally:
        await ra.cleanup()
        await rb.cleanup()
