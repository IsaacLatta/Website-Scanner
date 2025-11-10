import ssl
from pathlib import Path

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web

from scanner.runner import run_scan
from scanner.modules.headers import HeaderAnalyzer, default_header_rules
from scanner.definitions import PROJECT_ROOT

pytestmark = pytest.mark.asyncio

HTTP_PORT_BASE = 9850
HTTPS_PORT_BASE = 9450

CERT_PATH = PROJECT_ROOT / "tests/res/dev-cert.pem"
KEY_PATH = PROJECT_ROOT / "tests/res/dev-key.pem"


@pytest_asyncio.fixture
def ssl_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT_PATH), str(KEY_PATH))
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
    return base + offset

async def test_run_scan_basic_http_chain_and_headers(ssl_ctx):
    """
    End-to-end sanity check for run_scan:

    - HTTP server A: "/" -> 302 to HTTP server B "/final"
    - HTTP server B: "/final" -> 200 + a set of security headers
    - HTTPS server C: serves /.well-known/security.txt + HTML tech leak page
    - HTTPS server D: serves JSON tech leak error

    Asserts:
      * redirect resolution found the correct final URL + status
      * final headers contain what we set
      * modules dict exists and has entries
      * HeaderAnalyzer classifies the headers as expected
      * https_connectivity and hsts outputs look sane
      * securitytxt finds a valid security.txt on origin C
      * error_leak sees leaks on both C (HTML) and D (JSON)
    """
    start_port = find_free_port(HTTP_PORT_BASE, 0)
    final_port = find_free_port(HTTP_PORT_BASE, 1)

    final_app = web.Application()

    async def final_handler(_req):
        return web.Response(
            text="ok",
            headers={
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Content-Security-Policy": (
                    "default-src 'self'; "
                    "frame-ancestors 'none'; "
                    "object-src 'none'"
                ),
                "X-Content-Type-Options": "nosniff",
                "Permissions-Policy": "geolocation=()",
                "Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Strict",
            },
        )

    final_app.router.add_get("/final", final_handler)
    runner_final_http = await start_http_site(final_app, final_port)

    start_app = web.Application()

    async def start_handler(_req):
        raise web.HTTPFound(location=f"http://127.0.0.1:{final_port}/final")

    start_app.router.add_get("/", start_handler)
    runner_start_http = await start_http_site(start_app, start_port)

    start_url = f"http://127.0.0.1:{start_port}/"
    expected_final_url = f"http://127.0.0.1:{final_port}/final"

    origin_start = f"127.0.0.1:{start_port}"
    origin_final = f"127.0.0.1:{final_port}"

    sec_port = find_free_port(HTTPS_PORT_BASE, 0)
    origin_sec = f"127.0.0.1:{sec_port}"

    sec_app = web.Application()

    async def security_txt_handler(_req):
        body = (
            "Contact: mailto:security@example.test\n"
            "Expires: 2099-01-01T00:00:00Z\n"
        )
        return web.Response(text=body, content_type="text/plain")

    async def error_html_handler(_req):
        html = """
        <html>
          <head><title>Error</title></head>
          <body>
            <h1>Application error</h1>
            <p>Django 4.2.5 application error occurred.</p>
            <pre>
Error: simple boom
    at boom (/app/index.js:2:9)
    at main (/app/index.js:5:1)
            </pre>
          </body>
        </html>
        """
        return web.Response(text=html, content_type="text/html")

    sec_app.router.add_get("/.well-known/security.txt", security_txt_handler)
    # Match any path (including /__scanner_404__.../)
    sec_app.router.add_get("/{tail:.*}", error_html_handler)

    runner_sec_https = await start_https_site(sec_app, sec_port, ssl_ctx)

    json_port = find_free_port(HTTPS_PORT_BASE, 1)
    origin_json = f"127.0.0.1:{json_port}"

    json_app = web.Application()

    async def error_json_handler(_req):
        payload = {
            "error": "Internal Server Error",
            "details": "DatabaseError: PostgreSQL 13.4 connection failed",
        }
        return web.json_response(payload)

    json_app.router.add_get("/{tail:.*}", error_json_handler)
    runner_json_https = await start_https_site(json_app, json_port, ssl_ctx)

    try:
        result = await run_scan(
            [start_url, f"https://{origin_sec}/", f"https://{origin_json}/"],
            max_concurrency=4,
            http_timeout_s=5,
            redirect_max_hops=4,
            verify_certificate=False
        )

        resolutions = result["resolutions"]
        assert start_url in resolutions
        res = resolutions[start_url]

        assert res["final_url"] == expected_final_url
        assert res["final_status"] == 200

        headers = res["final_headers"]
        assert isinstance(headers, dict)
        assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
        assert headers["x-content-type-options"] == "nosniff"
        assert "content-security-policy" in headers
        assert "permissions-policy" in headers
        assert "set-cookie" in headers

        modules = result["modules"]

        for name in [
            "tls",
            "https_connectivity",
            "hsts",
            "securitytxt",
            "ciphers",
            "error_leak",
            "headers",
        ]:
            assert name in modules

        conn_rows = modules["https_connectivity"]
        for origin in (origin_start, origin_final):
            assert origin in conn_rows
            conn = conn_rows[origin]
            assert conn["origin"] == origin
            assert conn["success"] is False
            assert conn["has_hsts"] is False
            assert isinstance(conn["error"], str)

        hsts_rows = modules["hsts"]
        for origin in (origin_start, origin_final):
            assert origin in hsts_rows
            hrow = hsts_rows[origin]
            assert hrow["origin"] == origin
            assert hrow["https_ok"] is False
            assert hrow["has_hsts"] is False
            assert isinstance(hrow["redirected_to_https"], bool)

        analyzer = HeaderAnalyzer(default_header_rules())
        header_results = analyzer.run(headers)
        hr_by_name = {hr.name: hr for hr in header_results}

        assert hr_by_name["referrer_policy"].rating == "recommended"
        assert hr_by_name["csp_frame_ancestors"].rating == "recommended"
        assert hr_by_name["x_content_type_options"].rating == "recommended"
        assert hr_by_name["permissions_policy"].rating == "recommended"
        assert hr_by_name["cookies"].rating == "recommended"

        headers_module = modules["headers"]
        assert start_url in headers_module
        hdr_results_from_module = headers_module[start_url]
        assert isinstance(hdr_results_from_module, list)
        assert len(hdr_results_from_module) > 0

        names_from_module = {r["name"] for r in hdr_results_from_module}
        for expected_name in [
            "referrer_policy",
            "csp_frame_ancestors",
            "x_content_type_options",
            "permissions_policy",
            "cookies",
        ]:
            assert expected_name in names_from_module

        sec_rows = modules["securitytxt"]
        assert origin_sec in sec_rows
        srow = sec_rows[origin_sec]
        assert srow["origin"] == origin_sec
        assert srow["present"] is True
        assert srow["has_contact"] is True
        assert "security@example.test" in srow["contacts"]
        assert srow["has_expires"] is True
        assert srow["expires_valid"] is True
        assert "/.well-known/security.txt" in srow["location"]

        error_rows = modules["error_leak"]
        assert isinstance(error_rows, list)
        assert len(error_rows) > 0

        origins_seen = {row["origin"] for row in error_rows}
        assert origin_sec in origins_seen
        assert origin_json in origins_seen

        contexts = " ".join(row.get("version_context", "") for row in error_rows)
        contexts_lower = contexts.lower()
        assert "django" in contexts_lower or "postgresql" in contexts_lower

    finally:
        await runner_start_http.cleanup()
        await runner_final_http.cleanup()
        await runner_sec_https.cleanup()
        await runner_json_https.cleanup()
