# tests/test_headers.py
import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web

from scanner.modules.headers import (
    HeaderAnalyzer,
    default_header_rules,
)

pytestmark = pytest.mark.asyncio

@pytest_asyncio.fixture
async def session():
    async with aiohttp.ClientSession() as s:
        yield s


@pytest_asyncio.fixture
async def header_server():
    """
    Small HTTP server whose responses are driven by an injected mapping:

        scenarios[name] -> { header_name: value, ... }

    Tests can do:
        base_url, scenarios = header_server
        scenarios["referrer_recommended"] = {"Referrer-Policy": "strict-origin-when-cross-origin"}
        await session.get(f"{base_url}/referrer_recommended")
    """
    app = web.Application()
    scenarios: dict[str, dict[str, str]] = {}

    async def handler(request: web.Request):
        name = request.match_info["name"]
        hdrs = scenarios.get(name, {})
        return web.Response(text="ok", headers=hdrs)

    app.router.add_get("/{name}", handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 9880)
    await site.start()

    base_url = "http://127.0.0.1:9880"
    try:
        # tests get (base_url, scenarios) so they can populate headers
        yield base_url, scenarios
    finally:
        await runner.cleanup()


@pytest.fixture
def analyzer():
    return HeaderAnalyzer(default_header_rules())


def _get_result(results, display_name: str):
    return next(r for r in results if r.name == display_name)

async def test_referrer_policy_recommended(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["referrer_recommended"] = {
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    resp = await session.get(f"{base_url}/referrer_recommended")
    results = analyzer.run(resp.headers)

    rp = _get_result(results, "referrer_policy")
    assert rp.present is True
    assert rp.raw == "strict-origin-when-cross-origin"
    assert rp.rating == "recommended"


async def test_referrer_policy_insecure(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["referrer_insecure"] = {
        "Referrer-Policy": "unsafe-url",
    }

    resp = await session.get(f"{base_url}/referrer_insecure")
    results = analyzer.run(resp.headers)

    rp = _get_result(results, "referrer_policy")
    assert rp.present is True
    assert rp.raw == "unsafe-url"
    assert rp.rating == "insecure"


async def test_referrer_policy_unknown(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["referrer_unknown"] = {
        "Referrer-Policy": "weird-new-policy",
    }

    resp = await session.get(f"{base_url}/referrer_unknown")
    results = analyzer.run(resp.headers)

    rp = _get_result(results, "referrer_policy")
    assert rp.present is True
    assert rp.raw == "weird-new-policy"
    assert rp.rating == "unknown"


async def test_referrer_policy_missing(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["referrer_missing"] = {}

    resp = await session.get(f"{base_url}/referrer_missing")
    results = analyzer.run(resp.headers)

    rp = _get_result(results, "referrer_policy")
    assert rp.present is False
    assert rp.raw == ""
    # default_header_rules() sets on_missing_class="recommended"
    assert rp.rating == "recommended"


async def test_referrer_policy_header_name_case_insensitive(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["referrer_mixed_case"] = {
        "ReFeRreR-PolICY": "strict-origin-when-cross-origin",
    }

    resp = await session.get(f"{base_url}/referrer_mixed_case")
    results = analyzer.run(resp.headers)

    rp = _get_result(results, "referrer_policy")
    assert rp.present is True
    assert rp.rating == "recommended"
    assert rp.raw == "strict-origin-when-cross-origin"


async def test_csp_frame_ancestors_recommended(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["csp_recommended"] = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none'"
    }

    resp = await session.get(f"{base_url}/csp_recommended")
    results = analyzer.run(resp.headers)

    csp = _get_result(results, "csp_frame_ancestors")
    assert csp.present is True
    assert csp.rating == "recommended"
    assert "frame-ancestors 'none'" in csp.raw


async def test_csp_frame_ancestors_sufficient_self_only(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["csp_self"] = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'; object-src 'none'"
    }

    resp = await session.get(f"{base_url}/csp_self")
    results = analyzer.run(resp.headers)

    csp = _get_result(results, "csp_frame_ancestors")
    assert csp.present is True
    assert csp.rating == "sufficient"
    assert "frame-ancestors 'self'" in csp.raw


async def test_csp_frame_ancestors_sufficient_self_with_allowlist(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["csp_self_allowlist"] = {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "frame-ancestors 'self' https://trusted.example.com; "
            "object-src 'none'"
        )
    }

    resp = await session.get(f"{base_url}/csp_self_allowlist")
    results = analyzer.run(resp.headers)

    csp = _get_result(results, "csp_frame_ancestors")
    assert csp.present is True
    assert csp.rating == "sufficient"


async def test_csp_frame_ancestors_insecure_missing_directive(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["csp_no_frame_ancestors"] = {
        "Content-Security-Policy": "default-src 'self'; object-src 'none'"
    }

    resp = await session.get(f"{base_url}/csp_no_frame_ancestors")
    results = analyzer.run(resp.headers)

    csp = _get_result(results, "csp_frame_ancestors")
    assert csp.present is True
    assert csp.rating == "insecure"


async def test_csp_frame_ancestors_insecure_star(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["csp_star"] = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors *; object-src 'none'"
    }

    resp = await session.get(f"{base_url}/csp_star")
    results = analyzer.run(resp.headers)

    csp = _get_result(results, "csp_frame_ancestors")
    assert csp.present is True
    assert csp.rating == "insecure"


async def test_csp_missing_header(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["csp_missing"] = {}  # no CSP

    resp = await session.get(f"{base_url}/csp_missing")
    results = analyzer.run(resp.headers)

    csp = _get_result(results, "csp_frame_ancestors")
    assert csp.present is False
    assert csp.rating == "insecure"
    assert csp.raw == ""

async def test_xfo_deny_recommended(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["xfo_deny"] = {
        "X-Frame-Options": "DENY",
    }

    resp = await session.get(f"{base_url}/xfo_deny")
    results = analyzer.run(resp.headers)

    xfo = _get_result(results, "x_frame_options")
    assert xfo.present is True
    assert xfo.rating == "recommended"
    assert xfo.raw.upper().startswith("DENY")


async def test_xfo_sameorigin_sufficient(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["xfo_sameorigin"] = {
        "X-Frame-Options": "SAMEORIGIN",
    }

    resp = await session.get(f"{base_url}/xfo_sameorigin")
    results = analyzer.run(resp.headers)

    xfo = _get_result(results, "x_frame_options")
    assert xfo.present is True
    assert xfo.rating == "sufficient"


async def test_xfo_allow_from_obsolete(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["xfo_allow_from"] = {
        "X-Frame-Options": "ALLOW-FROM https://example.com/",
    }

    resp = await session.get(f"{base_url}/xfo_allow_from")
    results = analyzer.run(resp.headers)

    xfo = _get_result(results, "x_frame_options")
    assert xfo.present is True
    assert xfo.rating == "obsolete"


async def test_xfo_missing_header(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["xfo_missing"] = {}  # no XFO

    resp = await session.get(f"{base_url}/xfo_missing")
    results = analyzer.run(resp.headers)

    xfo = _get_result(results, "x_frame_options")
    assert xfo.present is False
    assert xfo.rating == "unknown"
    assert xfo.raw == ""
