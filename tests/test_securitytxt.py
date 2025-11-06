import ssl, aiohttp, pytest, pytest_asyncio
from aiohttp import web
from datetime import datetime, timedelta, timezone
from scanner.modules.securitytxt import SecurityTxtExport

pytestmark = pytest.mark.asyncio

SEC_TXT_WK = b"Contact: mailto:sec@example.test\nExpires: 2099-12-31T23:59:59Z\n"
SEC_TXT_CONTACT_ONLY = b"Contact: mailto:soc@example.test\n" 

def _future_iso(days=365):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat().replace("+00:00", "Z")

def _past_iso(days=365):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")

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

async def test_securitytxt_presence_and_location(ssl_ctx, session):
    # preferred location present at /.well-known/security.txt
    a = await server_with({"/.well-known/security.txt": SEC_TXT_WK})
    # fallback location present at /security.txt
    b = await server_with({"/security.txt": SEC_TXT_CONTACT_ONLY})

    ra = await start_site(a, 8443, ssl_ctx)
    rb = await start_site(b, 9443, ssl_ctx)

    try:
        mod = SecurityTxtExport(verify_certificate=False, timeout_s=5, session=session)
        origins = ["127.0.0.1:8443", "127.0.0.1:9443", "127.0.0.1:10443"]  # last one: no server
        await mod.run(origins)
        res = mod.results()

        # Preferred path found (in wellknown)
        assert res["127.0.0.1:8443"]["present"] is True
        assert res["127.0.0.1:8443"]["location"] == "/.well-known/security.txt"

        # Fallback path found (at root)
        assert res["127.0.0.1:9443"]["present"] is True
        assert res["127.0.0.1:9443"]["location"] == "/security.txt"

        # No file / server -> not present
        assert res["127.0.0.1:10443"]["present"] is False

    finally:
        await ra.cleanup()
        await rb.cleanup()

async def test_securitytxt_valid_both_fields(ssl_ctx, session):
    content = f"Contact: mailto:sec@example.test\nExpires: {_future_iso(400)}\n".encode()
    app = await server_with({"/.well-known/security.txt": content})
    r = await start_site(app, 8543, ssl_ctx)
    try:
        mod = SecurityTxtExport(verify_certificate=False, timeout_s=5, session=session)
        await mod.run(["127.0.0.1:8543"])
        row = mod.results()["127.0.0.1:8543"]
        assert row["present"] is True
        assert row["has_contact"] is True
        assert row["has_expires"] is True
        assert row["expires_valid"] is True
        assert row["location"] == "/.well-known/security.txt"
        assert "mailto:sec@example.test" in row["contacts"]
    finally:
        await r.cleanup()

async def test_securitytxt_past_expires(ssl_ctx, session):
    content = f"Contact: mailto:sec@example.test\nExpires: {_past_iso(30)}\n".encode()
    app = await server_with({"/.well-known/security.txt": content})
    r = await start_site(app, 8843, ssl_ctx)
    try:
        mod = SecurityTxtExport(verify_certificate=False, timeout_s=5, session=session)
        await mod.run(["127.0.0.1:8843"])
        row = mod.results()["127.0.0.1:8843"]
        assert row["present"] is True
        assert row["has_contact"] is True
        assert row["has_expires"] is True
        assert row["expires_valid"] is False
    finally:
        await r.cleanup()

async def test_securitytxt_multiple_contacts_and_canonical(ssl_ctx, session):
    content = (
        b"# This is a comment!\n"
        b"Contact: mailto:sec@example.test\n"
        b"Contact: https://example.test/security\n"
        b"Canonical: https://example.test/.well-known/security.txt\n"
        b"Expires: " + _future_iso(100).encode() + b"\n"
    )
    app = await server_with({"/.well-known/security.txt": content})
    r = await start_site(app, 8943, ssl_ctx)
    try:
        mod = SecurityTxtExport(verify_certificate=False, timeout_s=5, session=session)
        await mod.run(["127.0.0.1:8943"])
        row = mod.results()["127.0.0.1:8943"]
        assert row["present"] is True
        assert row["has_contact"] is True
        assert "mailto:sec@example.test" in row["contacts"]
        assert "https://example.test/security" in row["contacts"]
        assert "https://example.test/.well-known/security.txt" in row["canonical"]
        assert row["has_expires"] is True and row["expires_valid"] is True
    finally:
        await r.cleanup()