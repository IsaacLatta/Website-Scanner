import ssl
import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from pathlib import Path
import pytest
from urllib.parse import urlparse

from scanner.redirects import RedirectResolver, ResolutionResult
from scanner.targets import _normalize_origin

import asyncio
from scanner.redirects import RedirectResolver

HTTP_PORT_BASE = 9900
HTTPS_PORT_BASE = 9440
CERT_PATH = Path("tests/res/dev-cert.pem")
KEY_PATH = Path("tests/res/dev-key.pem")

pytestmark = pytest.mark.asyncio

@pytest_asyncio.fixture
async def session():
    """
    Reusable aiohttp session that disables certificate verification so
    we can hit our self-signed localhost HTTPS servers.
    """
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=connector) as s:
        yield s


@pytest_asyncio.fixture
def ssl_ctx():
    """
    SSL context for HTTPS test servers using dev cert/key under tests/res.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(KEY_PATH))
    return ctx


async def start_http_site(app: web.Application, port: int):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return runner


async def start_https_site(app: web.Application, port: int, ssl_ctx):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port, ssl_context=ssl_ctx)
    await site.start()
    return runner

def find_free_port(base: int, offset: int = 0) -> int:
    # Avoid clashes when running tests concurrently.
    return base + offset


def make_url(scheme: str, port: int, path: str = "/") -> str:
    return f"{scheme}://127.0.0.1:{port}{path}"


async def test_single_redirect_http_to_https(session, ssl_ctx):
    """
    Basic case: HTTP -> 301 -> HTTPS. We should capture one hop and end on https://127.0.0.1:PORT/.
    """
    http_port = 9900
    https_port = 9440

    https_app = web.Application()
    async def https_root(_req):
        return web.Response(text="secure ok")
    https_app.router.add_get("/", https_root)
    https_runner = await start_https_site(https_app, https_port, ssl_ctx)

    http_app = web.Application()
    async def http_root(_req):
        raise web.HTTPMovedPermanently(location=f"https://127.0.0.1:{https_port}/")
    http_app.router.add_get("/", http_root)
    http_runner = await start_http_site(http_app, http_port)

    try:
        resolver = RedirectResolver(session, aiohttp.ClientTimeout(total=5))
        results = await resolver.resolve_all([f"http://127.0.0.1:{http_port}/"])
        res = results[f"http://127.0.0.1:{http_port}/"]

        assert res.error is None
        assert res.final_url == f"https://127.0.0.1:{https_port}/"
        assert res.final_origin == f"127.0.0.1:{https_port}"
        assert res.final_status == 200
        assert isinstance(res.final_headers, dict)
        assert len(res.hops) == 1
        assert res.hops[0].status in (301, 308)
        assert res.hops[0].url == f"https://127.0.0.1:{https_port}/"
    finally:
        await http_runner.cleanup()
        await https_runner.cleanup()



async def test_multiple_hops_http_to_http_to_https(session, ssl_ctx):
    """
    More complex case: HTTP -> 302 -> HTTP -> 301 -> HTTPS.
    Starts on http://127.0.0.1:port1/, gets redirected to another HTTP
    endpoint, which then redirects to HTTPS. We should record both hops
    and end on the HTTPS final URL.
    """
    http_port_1 = find_free_port(HTTP_PORT_BASE, 1)
    http_port_2 = find_free_port(HTTP_PORT_BASE, 2)
    https_port  = find_free_port(HTTPS_PORT_BASE, 1)

    https_app = web.Application()
    async def https_final(_req):
        return web.Response(text="final secure ok")
    https_app.router.add_get("/final", https_final)
    https_runner = await start_https_site(https_app, https_port, ssl_ctx)

    http2_app = web.Application()
    async def http2_step(_req):
        raise web.HTTPMovedPermanently(location=f"https://127.0.0.1:{https_port}/final")
    http2_app.router.add_get("/step", http2_step)
    http2_runner = await start_http_site(http2_app, http_port_2)

    http1_app = web.Application()
    async def http1_root(_req):
        raise web.HTTPFound(location=f"http://127.0.0.1:{http_port_2}/step")
    http1_app.router.add_get("/", http1_root)
    http1_runner = await start_http_site(http1_app, http_port_1)

    start_url = f"http://127.0.0.1:{http_port_1}/"

    try:
        resolver = RedirectResolver(session, aiohttp.ClientTimeout(total=5), max_hops=8)
        results = await resolver.resolve_all([start_url])
        res = results[start_url]

        assert res.error is None
        assert res.final_url == f"https://127.0.0.1:{https_port}/final"
        assert res.final_origin == f"127.0.0.1:{https_port}"
        assert res.final_status == 200
        assert isinstance(res.final_headers, dict)

        assert len(res.hops) == 2

        first_hop = res.hops[0]
        second_hop = res.hops[1]

        assert first_hop.status in (301, 302, 307, 308)
        assert first_hop.url == f"http://127.0.0.1:{http_port_2}/step"

        assert second_hop.status in (301, 302, 307, 308)
        assert second_hop.url == f"https://127.0.0.1:{https_port}/final"
    finally:
        await http1_runner.cleanup()
        await http2_runner.cleanup()
        await https_runner.cleanup()




async def test_multiple_hops_headers_from_final_response(session, ssl_ctx):
    """
    Multi-hop chain where each hop sets different header values.
    We should cache headers only from the FINAL 200 response.
    """
    http_port_1 = find_free_port(HTTP_PORT_BASE, 3)
    http_port_2 = find_free_port(HTTP_PORT_BASE, 4)
    https_port  = find_free_port(HTTPS_PORT_BASE, 3)

    https_app = web.Application()
    async def https_final(_req):
        return web.Response(
            text="final secure ok",
            headers={
                "X-Hop": "final",
                "X-Shared": "final",
                "X-Only-Final": "yes",
            },
        )
    https_app.router.add_get("/final", https_final)
    https_runner = await start_https_site(https_app, https_port, ssl_ctx)

    http2_app = web.Application()
    async def http2_step(_req):
        raise web.HTTPFound(
            location=f"https://127.0.0.1:{https_port}/final",
            headers={
                "X-Hop": "second",
                "X-Shared": "second",
            },
        )
    http2_app.router.add_get("/step", http2_step)
    http2_runner = await start_http_site(http2_app, http_port_2)

    http1_app = web.Application()
    async def http1_root(_req):
        raise web.HTTPFound(
            location=f"http://127.0.0.1:{http_port_2}/step",
            headers={
                "X-Hop": "first",
                "X-Shared": "first",
            },
        )
    http1_app.router.add_get("/", http1_root)
    http1_runner = await start_http_site(http1_app, http_port_1)

    start_url = f"http://127.0.0.1:{http_port_1}/"

    try:
        resolver = RedirectResolver(session, aiohttp.ClientTimeout(total=5), max_hops=8)
        results = await resolver.resolve_all([start_url])
        res = results[start_url]

        assert res.error is None
        assert res.final_url == f"https://127.0.0.1:{https_port}/final"
        assert res.final_origin == f"127.0.0.1:{https_port}"
        assert res.final_status == 200
        assert isinstance(res.final_headers, dict)

        fh = res.final_headers
        assert fh["x-hop"] == "final"
        assert fh["x-shared"] == "final"
        assert fh["x-only-final"] == "yes"

        assert fh["x-hop"] != "first"
        assert fh["x-hop"] != "second"
    finally:
        await http1_runner.cleanup()
        await http2_runner.cleanup()
        await https_runner.cleanup()

async def test_final_response_with_http_500_error_status(session):
    """
    If the server responds with a non-3xx HTTP error (e.g. 500),
    the resolver should treat it as a *final* response:

      - no hops recorded
      - error remains None
      - final_status == 500
      - final_headers come from that 500 response
    """
    http_port = find_free_port(HTTP_PORT_BASE, 5)

    app = web.Application()

    async def error_root(_req):
        return web.Response(
            status=500,
            text="internal error",
            headers={
                "X-Error-Marker": "yes",
                "X-Hop": "error-final",
            },
        )

    app.router.add_get("/", error_root)
    runner = await start_http_site(app, http_port)

    start_url = f"http://127.0.0.1:{http_port}/"

    try:
        resolver = RedirectResolver(session, aiohttp.ClientTimeout(total=5), max_hops=4)
        results = await resolver.resolve_all([start_url])
        res = results[start_url]

        assert len(res.hops) == 0

        assert res.error is None

        assert res.final_url == start_url
        assert res.final_origin == f"127.0.0.1:{http_port}"
        assert res.final_status == 500

        assert isinstance(res.final_headers, dict)
        fh = res.final_headers
        assert fh.get("x-error-marker") == "yes"
        assert fh.get("x-hop") == "error-final"
    finally:
        await runner.cleanup()



async def test_redirect_real_domain_example_com(session):
    """
    Integration-ish test against a real domain. We start from http://example.com/
    and expect to end on an HTTPS URL under example.com, with a valid status and headers.

    This is marked as 'network' so it can be selectively run, and will skip
    if the environment cannot reach example.com.
    """
    start_url = "http://example.com/"

    resolver = RedirectResolver(session, aiohttp.ClientTimeout(total=10), max_hops=8)
    results = await resolver.resolve_all([start_url])
    res = results[start_url]

    if res.error is not None:
        pytest.skip(f"Network/environment cannot resolve example.com: {res.error}")

    assert res.error is None
    assert res.final_url is not None

    parsed = urlparse(res.final_url)
    assert parsed.scheme in ("https", "http")
    assert parsed.hostname is not None
    assert parsed.hostname.endswith("example.com")

    assert res.final_status is not None
    assert 200 <= res.final_status < 600

    assert isinstance(res.final_headers, dict)
    assert "content-type" in res.final_headers


async def test_redirect_without_location_sets_error(session):
    """
    If the server returns a 3xx status but omits the Location header,
    we should not crash or loop. The resolver should:

      - set an error string mentioning redirect_without_location
      - leave final_url/final_status/final_headers as None
      - record zero hops (nothing followed)
    """
    http_port = find_free_port(HTTP_PORT_BASE, 6)

    app = web.Application()

    async def broken_redirect(_req):
        return web.Response(status=302, text="broken redirect")

    app.router.add_get("/", broken_redirect)
    runner = await start_http_site(app, http_port)

    start_url = f"http://127.0.0.1:{http_port}/"

    try:
        resolver = RedirectResolver(session, aiohttp.ClientTimeout(total=5), max_hops=4)
        results = await resolver.resolve_all([start_url])
        res = results[start_url]

        assert res.error is not None
        assert "redirect_without_location" in res.error

        assert res.final_url is None
        assert res.final_status in (301, 302, 307, 308)
        assert res.final_headers is None

        assert len(res.hops) == 0
    finally:
        await runner.cleanup()


async def test_concurrent_resolution_two_independent_chains(session, ssl_ctx):
    """
    Sanity-check concurrency: resolve two different redirect chains in parallel
    and ensure each result is independent and correct.

      Chain A: HTTP -> 301 -> HTTPS (/one)
      Chain B: HTTP -> 302 -> HTTP (/step) -> 301 -> HTTPS (/two)
    """
    http_a_port  = find_free_port(HTTP_PORT_BASE, 10)
    https_a_port = find_free_port(HTTPS_PORT_BASE, 10)

    http_b1_port = find_free_port(HTTP_PORT_BASE, 11)
    http_b2_port = find_free_port(HTTP_PORT_BASE, 12)
    https_b_port = find_free_port(HTTPS_PORT_BASE, 11)

    https_a_app = web.Application()
    async def https_a_root(_req):
        return web.Response(
            text="chain-a final",
            headers={"X-Chain": "A", "X-Path": "/one"},
        )
    https_a_app.router.add_get("/one", https_a_root)
    https_a_runner = await start_https_site(https_a_app, https_a_port, ssl_ctx)

    http_a_app = web.Application()
    async def http_a_root(_req):
        raise web.HTTPMovedPermanently(
            location=f"https://127.0.0.1:{https_a_port}/one"
        )
    http_a_app.router.add_get("/", http_a_root)
    http_a_runner = await start_http_site(http_a_app, http_a_port)

    start_a = f"http://127.0.0.1:{http_a_port}/"

    https_b_app = web.Application()
    async def https_b_final(_req):
        return web.Response(
            text="chain-b final",
            headers={"X-Chain": "B", "X-Path": "/two"},
        )
    https_b_app.router.add_get("/two", https_b_final)
    https_b_runner = await start_https_site(https_b_app, https_b_port, ssl_ctx)

    http_b2_app = web.Application()
    async def http_b2_step(_req):
        raise web.HTTPMovedPermanently(
            location=f"https://127.0.0.1:{https_b_port}/two"
        )
    http_b2_app.router.add_get("/step", http_b2_step)
    http_b2_runner = await start_http_site(http_b2_app, http_b2_port)

    http_b1_app = web.Application()
    async def http_b1_root(_req):
        raise web.HTTPFound(
            location=f"http://127.0.0.1:{http_b2_port}/step"
        )
    http_b1_app.router.add_get("/", http_b1_root)
    http_b1_runner = await start_http_site(http_b1_app, http_b1_port)

    start_b = f"http://127.0.0.1:{http_b1_port}/"

    try:
        resolver = RedirectResolver(
            session,
            aiohttp.ClientTimeout(total=5),
            max_hops=8,
            concurrency=2,
        )

        results = await resolver.resolve_all([start_a, start_b])
        res_a = results[start_a]
        res_b = results[start_b]

        assert res_a.error is None
        assert res_a.final_url == f"https://127.0.0.1:{https_a_port}/one"
        assert res_a.final_origin == f"127.0.0.1:{https_a_port}"
        assert res_a.final_status == 200
        assert len(res_a.hops) == 1
        assert res_a.hops[0].url == f"https://127.0.0.1:{https_a_port}/one"

        fh_a = res_a.final_headers
        assert isinstance(fh_a, dict)
        assert fh_a.get("x-chain") == "A"
        assert fh_a.get("x-path") == "/one"

        assert res_b.error is None
        assert res_b.final_url == f"https://127.0.0.1:{https_b_port}/two"
        assert res_b.final_origin == f"127.0.0.1:{https_b_port}"
        assert res_b.final_status == 200
        assert len(res_b.hops) == 2
        assert res_b.hops[0].url == f"http://127.0.0.1:{http_b2_port}/step"
        assert res_b.hops[1].url == f"https://127.0.0.1:{https_b_port}/two"

        fh_b = res_b.final_headers
        assert isinstance(fh_b, dict)
        assert fh_b.get("x-chain") == "B"
        assert fh_b.get("x-path") == "/two"

        assert fh_a.get("x-chain") != fh_b.get("x-chain")
    finally:
        await http_a_runner.cleanup()
        await https_a_runner.cleanup()
        await http_b1_runner.cleanup()
        await http_b2_runner.cleanup()
        await https_b_runner.cleanup()

async def test_concurrent_resolution_multiple_mixed_success_and_error(session, ssl_ctx):
    """
    Concurrency stress: resolve four different URLs in parallel:

      A: HTTP 200, no redirects.
      B: HTTP -> 301 -> HTTPS (one hop).
      C: HTTP -> 302 -> HTTP (/step) -> 301 -> HTTPS (two hops).
      D: Unreachable port (network error).

    We assert that:
      - each result is independent and correct,
      - success and error cases coexist without interference.
    """
    http_a_port = find_free_port(HTTP_PORT_BASE, 20)
    app_a = web.Application()

    async def a_root(_req):
        return web.Response(
            text="A ok",
            headers={"X-Chain": "a", "X-Stage": "final"},
        )

    app_a.router.add_get("/", a_root)
    runner_a = await start_http_site(app_a, http_a_port)
    start_a = f"http://127.0.0.1:{http_a_port}/"

    http_b_port = find_free_port(HTTP_PORT_BASE, 21)
    https_b_port = find_free_port(HTTPS_PORT_BASE, 20)

    https_b_app = web.Application()

    async def https_b_root(_req):
        return web.Response(
            text="B final",
            headers={"X-Chain": "b", "X-Stage": "final"},
        )

    https_b_app.router.add_get("/", https_b_root)
    runner_b_https = await start_https_site(https_b_app, https_b_port, ssl_ctx)

    http_b_app = web.Application()

    async def http_b_root(_req):
        raise web.HTTPMovedPermanently(
            location=f"https://127.0.0.1:{https_b_port}/"
        )

    http_b_app.router.add_get("/", http_b_root)
    runner_b_http = await start_http_site(http_b_app, http_b_port)
    start_b = f"http://127.0.0.1:{http_b_port}/"

    http_c1_port = find_free_port(HTTP_PORT_BASE, 22)
    http_c2_port = find_free_port(HTTP_PORT_BASE, 23)
    https_c_port = find_free_port(HTTPS_PORT_BASE, 21)

    https_c_app = web.Application()

    async def https_c_final(_req):
        return web.Response(
            text="C final",
            headers={"X-Chain": "c", "X-Stage": "final"},
        )

    https_c_app.router.add_get("/final", https_c_final)
    runner_c_https = await start_https_site(https_c_app, https_c_port, ssl_ctx)

    http_c2_app = web.Application()

    async def http_c2_step(_req):
        raise web.HTTPMovedPermanently(
            location=f"https://127.0.0.1:{https_c_port}/final"
        )

    http_c2_app.router.add_get("/step", http_c2_step)
    runner_c_http2 = await start_http_site(http_c2_app, http_c2_port)

    http_c1_app = web.Application()

    async def http_c1_root(_req):
        raise web.HTTPFound(
            location=f"http://127.0.0.1:{http_c2_port}/step"
        )

    http_c1_app.router.add_get("/", http_c1_root)
    runner_c_http1 = await start_http_site(http_c1_app, http_c1_port)
    start_c = f"http://127.0.0.1:{http_c1_port}/"

    unreachable_port = find_free_port(HTTP_PORT_BASE, 99)
    start_d = f"http://127.0.0.1:{unreachable_port}/"

    try:
        resolver = RedirectResolver(
            session,
            aiohttp.ClientTimeout(total=2),
            max_hops=8,
            concurrency=4,
        )

        starts = [start_a, start_b, start_c, start_d]
        results = await resolver.resolve_all(starts)

        res_a = results[start_a]
        res_b = results[start_b]
        res_c = results[start_c]
        res_d = results[start_d]

        # A
        assert res_a.error is None
        assert res_a.final_url == start_a
        assert res_a.final_origin == f"127.0.0.1:{http_a_port}"
        assert res_a.final_status == 200
        assert len(res_a.hops) == 0
        fh_a = res_a.final_headers
        assert fh_a.get("x-chain") == "a"
        assert fh_a.get("x-stage") == "final"

        # B
        assert res_b.error is None
        assert res_b.final_url == f"https://127.0.0.1:{https_b_port}/"
        assert res_b.final_origin == f"127.0.0.1:{https_b_port}"
        assert res_b.final_status == 200
        assert len(res_b.hops) == 1
        assert res_b.hops[0].url == f"https://127.0.0.1:{https_b_port}/"
        fh_b = res_b.final_headers
        assert fh_b.get("x-chain") == "b"
        assert fh_b.get("x-stage") == "final"

        # C
        assert res_c.error is None
        assert res_c.final_url == f"https://127.0.0.1:{https_c_port}/final"
        assert res_c.final_origin == f"127.0.0.1:{https_c_port}"
        assert res_c.final_status == 200
        assert len(res_c.hops) == 2
        assert res_c.hops[0].url == f"http://127.0.0.1:{http_c2_port}/step"
        assert res_c.hops[1].url == f"https://127.0.0.1:{https_c_port}/final"
        fh_c = res_c.final_headers
        assert fh_c.get("x-chain") == "c"
        assert fh_c.get("x-stage") == "final"

        assert res_d.error is not None
        assert res_d.final_url is None or res_d.final_status is None

        assert fh_a.get("x-chain") != fh_b.get("x-chain") != fh_c.get("x-chain")
    finally:
        await runner_a.cleanup()
        await runner_b_http.cleanup()
        await runner_b_https.cleanup()
        await runner_c_http1.cleanup()
        await runner_c_http2.cleanup()
        await runner_c_https.cleanup()




