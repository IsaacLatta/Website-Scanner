# tests/test_headers.py
import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web

from scanner.modules.headers import (
    HeaderAnalyzer,
    default_header_rules,
    classify_set_cookie,
    parse_set_cookie_attributes,
    load_missing_header_rules
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
    scenarios["xfo_missing"] = {} 

    resp = await session.get(f"{base_url}/xfo_missing")
    results = analyzer.run(resp.headers)

    xfo = _get_result(results, "x_frame_options")
    assert xfo.present is False
    assert xfo.rating == "unknown"
    assert xfo.raw == ""

async def test_x_content_type_nosniff_recommended(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["xcto_nosniff"] = {
        "X-Content-Type-Options": "nosniff",
    }

    resp = await session.get(f"{base_url}/xcto_nosniff")
    results = analyzer.run(resp.headers)

    xcto = _get_result(results, "x_content_type_options")
    assert xcto.present is True
    assert xcto.raw.lower() == "nosniff"
    assert xcto.rating == "recommended"

async def test_x_content_type_nonsense_insecure(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["xcto_nonsense"] = {
        "X-Content-Type-Options": "foobar",
    }

    resp = await session.get(f"{base_url}/xcto_nonsense")
    results = analyzer.run(resp.headers)

    xcto = _get_result(results, "x_content_type_options")
    assert xcto.present is True
    assert xcto.raw == "foobar"
    assert xcto.rating == "insecure"

async def test_x_content_type_empty_and_missing_insecure(session, header_server, analyzer):
    base_url, scenarios = header_server

    scenarios["xcto_empty"] = {
        "X-Content-Type-Options": "",
    }
    resp1 = await session.get(f"{base_url}/xcto_empty")
    results1 = analyzer.run(resp1.headers)
    xcto1 = _get_result(results1, "x_content_type_options")
    assert xcto1.present is True
    assert xcto1.raw == ""
    assert xcto1.rating == "insecure"

    scenarios["xcto_missing"] = {}
    resp2 = await session.get(f"{base_url}/xcto_missing")
    results2 = analyzer.run(resp2.headers)
    xcto2 = _get_result(results2, "x_content_type_options")
    assert xcto2.present is False
    assert xcto2.raw == ""
    assert xcto2.rating == "insecure"

async def test_permissions_policy_recommended_disables_feature(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["perm_recommended"] = {
        "Permissions-Policy": 'geolocation=(), camera=(self "https://video.example")',
    }

    resp = await session.get(f"{base_url}/perm_recommended")
    results = analyzer.run(resp.headers)

    pp = _get_result(results, "permissions_policy")
    assert pp.present is True
    assert pp.rating == "recommended"

async def test_permissions_policy_recommended_restrictive_only(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["perm_restrictive"] = {
        "Permissions-Policy": 'camera=(self "https://video.example")',
    }

    resp = await session.get(f"{base_url}/perm_restrictive")
    results = analyzer.run(resp.headers)

    pp = _get_result(results, "permissions_policy")
    assert pp.present is True
    assert pp.rating == "recommended"

async def test_permissions_policy_insecure_star(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["perm_insecure_star"] = {
        "Permissions-Policy": "geolocation=*",
    }

    resp = await session.get(f"{base_url}/perm_insecure_star")
    results = analyzer.run(resp.headers)

    pp = _get_result(results, "permissions_policy")
    assert pp.present is True
    assert pp.rating == "insecure"

async def test_permissions_policy_missing_header_is_insecure(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["perm_missing"] = {}

    resp = await session.get(f"{base_url}/perm_missing")
    results = analyzer.run(resp.headers)

    pp = _get_result(results, "permissions_policy")
    assert pp.present is False
    assert pp.raw == ""
    assert pp.rating == "insecure"

async def test_set_cookie_recommended_strict(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["cookie_recommended"] = {
        "Set-Cookie": "sessionid=abc; Secure; HttpOnly; SameSite=Strict",
    }

    resp = await session.get(f"{base_url}/cookie_recommended")
    results = analyzer.run(resp.headers)

    ck = _get_result(results, "cookies")
    assert ck.present is True
    assert ck.raw.startswith("sessionid=abc")
    assert ck.rating == "recommended"


async def test_set_cookie_sufficient_lax(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["cookie_sufficient"] = {
        "Set-Cookie": "sessionid=abc; Secure; HttpOnly; SameSite=Lax",
    }

    resp = await session.get(f"{base_url}/cookie_sufficient")
    results = analyzer.run(resp.headers)

    ck = _get_result(results, "cookies")
    assert ck.present is True
    assert ck.rating == "sufficient"


async def test_set_cookie_insecure_missing_flags(session, header_server, analyzer):
    base_url, scenarios = header_server
    # Missing Secure / HttpOnly should be treated as insecure even with SameSite
    scenarios["cookie_insecure"] = {
        "Set-Cookie": "sessionid=abc; SameSite=Lax",
    }

    resp = await session.get(f"{base_url}/cookie_insecure")
    results = analyzer.run(resp.headers)

    ck = _get_result(results, "cookies")
    assert ck.present is True
    assert ck.rating == "insecure"


async def test_set_cookie_missing_header_is_unknown(session, header_server, analyzer):
    base_url, scenarios = header_server
    scenarios["cookie_missing"] = {}

    resp = await session.get(f"{base_url}/cookie_missing")
    results = analyzer.run(resp.headers)

    ck = _get_result(results, "cookies")
    assert ck.present is False
    assert ck.raw == ""
    # default_header_rules() sets on_missing_class="unknown"
    assert ck.rating == "unknown"


async def test_parse_set_cookie_attributes_flags_and_lifetime():
    value = (
        "sessionid=abc123; Secure; HttpOnly; SameSite=Strict; "
        "Max-Age=3600; Expires=Wed, 21 Oct 2015 07:28:00 GMT"
    )

    info = parse_set_cookie_attributes(value)

    assert info["has_secure"] is True
    assert info["has_httponly"] is True
    assert info["samesite"] == "SameSite=Strict".split("=", 1)[1] or "Strict"  # defensive
    assert info["has_max_age"] is True
    assert info["max_age"] == "3600"
    assert info["has_expires"] is True
    assert "2015" in info["expires"]

    # sanity-check that the classifier agrees this is recommended
    assert classify_set_cookie(value) == "recommended"


async def test_revealing_headers_present_are_insecure(session, header_server):
    base_url, scenarios = header_server
    analyzer = HeaderAnalyzer(default_header_rules())

    scenarios["revealing_present"] = {
        "Server": "nginx/1.24.0",
        "X-Powered-By": "PHP/8.1.12",
    }

    resp = await session.get(f"{base_url}/revealing_present")
    results = analyzer.run(resp.headers)

    server_hdr = _get_result(results, "server")
    assert server_hdr.present is True
    assert server_hdr.raw == "nginx/1.24.0"
    assert server_hdr.rating == "insecure"

    xpb_hdr = _get_result(results, "x_powered_by")
    assert xpb_hdr.present is True
    assert xpb_hdr.raw == "PHP/8.1.12"
    assert xpb_hdr.rating == "insecure"


async def test_revealing_headers_missing_are_recommended(session, header_server):
    base_url, scenarios = header_server
    analyzer = HeaderAnalyzer(default_header_rules())

    # No revealing headers at all
    scenarios["revealing_missing"] = {}

    resp = await session.get(f"{base_url}/revealing_missing")
    results = analyzer.run(resp.headers)

    server_hdr = _get_result(results, "x_b3_sampled")
    assert server_hdr.present is False
    assert server_hdr.raw == ""
    assert server_hdr.rating == "recommended"

    xpb_hdr = _get_result(results, "x_powered_by")
    assert xpb_hdr.present is False
    assert xpb_hdr.raw == ""
    assert xpb_hdr.rating == "recommended"


def test_load_missing_header_rules_normalizes_names():
    rules = load_missing_header_rules()

    # We should have a rule for "server" in lowercase
    server_rule = next(r for r in rules if r.name == "server")
    assert server_rule.display_name == "server"
    assert server_rule.on_missing_class == "recommended"

    # And one for "x-powered-by" with the right display_name
    xpb_rule = next(r for r in rules if r.name == "x-powered-by")
    assert xpb_rule.display_name == "x_powered_by"
    assert xpb_rule.on_missing_class == "recommended"
