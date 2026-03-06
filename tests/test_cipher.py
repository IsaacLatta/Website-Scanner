import ssl
import asyncio
from aiohttp import web
import pytest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from scanner.modules.cipher import (
    CipherSuitesModule,
    TLS13_RECOMMENDED, TLS13_SUFFICIENT,
    TLS12_RECOMMENDED, TLS12_SUFFICIENT,
)
from scanner.definitions import PROJECT_ROOT

pytestmark = pytest.mark.asyncio

@pytest.fixture(scope="module")
def tiny_pool():
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cipher-tests")
    try:
        yield pool
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

async def _https_app_ok():
    app = web.Application()

    async def root(_req):
        return web.Response(text="ok")

    app.router.add_get("/", root)
    return app

def _has_tlsver(name: str) -> bool:
    return hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, name)

async def _start_https(
    *,
    port: int,
    min_ver: ssl.TLSVersion,
    max_ver: ssl.TLSVersion,
    ciphers12: str | None = None,
):
    app = await _https_app_ok()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    res = PROJECT_ROOT / "tests" / "res"
    ctx.load_cert_chain(str(res / "dev-cert.pem"), str(res / "dev-key.pem"))

    ctx.minimum_version = min_ver
    ctx.maximum_version = max_ver

    if ciphers12:
        ctx.set_ciphers(ciphers12)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port, ssl_context=ctx)
    await site.start()
    return runner

async def test_tls13_observational_classification(tiny_pool):
    if not _has_tlsver("TLSv1_3"):
        pytest.skip("Runner cannot expose TLS 1.3")

    port = 9740
    runner = await _start_https(
        port=port,
        min_ver=ssl.TLSVersion.TLSv1_3,
        max_ver=ssl.TLSVersion.TLSv1_3,
    )
    try:
        mod = CipherSuitesModule(executor=tiny_pool, timeout_s=5.0)
        await mod.run([f"127.0.0.1:{port}"])
        row = list(mod.results().values())[0]

        if row["tls13_forced_cipher"] is None:
            pytest.skip("No TLS 1.3 cipher negotiated; environment limitation")

        cipher = row["tls13_forced_cipher"]
        cat = row["tls13_forced_category"]

        if cipher in TLS13_RECOMMENDED:
            assert cat == "recommended"
        elif cipher in TLS13_SUFFICIENT:
            assert cat == "sufficient"
        else:
            assert cat == "unknown"
    finally:
        await runner.cleanup()



async def test_tls12_recommended_bucket_and_forced(tiny_pool):
    if not _has_tlsver("TLSv1_2"):
        pytest.skip("Runner cannot expose TLS 1.2")

    # Pick only the ECDHE-RSA recommended ciphers—I only self signed RSA
    tls12_subset = [c for c in TLS12_RECOMMENDED if "ECDHE-RSA" in c][:2]
    if not tls12_subset:
        pytest.skip("No ECDHE-RSA ciphers in TLS12_RECOMMENDED for this test")

    port = 9742

    runner = await _start_https(
        port=port,
        min_ver=ssl.TLSVersion.TLSv1_2,
        max_ver=ssl.TLSVersion.TLSv1_2,
        ciphers12=":".join(tls12_subset),
    )
    try:
        mod = CipherSuitesModule(executor=tiny_pool, timeout_s=5.0)
        await mod.run([f"127.0.0.1:{port}"])
        row = list(mod.results().values())[0]

        # Forced TLS1.2 handshake should pick from our subset
        assert row["tls12_forced_cipher"] in tls12_subset
        assert row["tls12_forced_category"] == "recommended"

        # Bucket probes
        assert row["accepts_recommended_tls12"] is True
        # We did not configure any "sufficient" ciphers, so this should be False
        assert row["accepts_sufficient_tls12"] is False
        # And we didn't enable weak ones
        assert row["accepts_insecure_tls12"] is False

        # These RSA-GCM/CCM suites should not involve SHA1-only or CBC
        assert row["allows_sha1_tls12"] is False
        assert row["allows_cbc_tls12"] is False
    finally:
        await runner.cleanup()


async def test_tls12_sufficient_bucket_and_forced(tiny_pool):
    if not _has_tlsver("TLSv1_2"):
        pytest.skip("Runner cannot expose TLS 1.2")

    # Choose sufficient ciphers that do NOT use SHA1 (SHA256/SHA384 or CCM8)
    tls12_suf_subset = [
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES256-SHA384",
    ]
    port = 9743

    runner = await _start_https(
        port=port,
        min_ver=ssl.TLSVersion.TLSv1_2,
        max_ver=ssl.TLSVersion.TLSv1_2,
        ciphers12=":".join(tls12_suf_subset),
    )
    try:
        mod = CipherSuitesModule(executor=tiny_pool, timeout_s=5.0)
        await mod.run([f"127.0.0.1:{port}"])
        row = list(mod.results().values())[0]

        assert row["tls12_forced_cipher"] in tls12_suf_subset
        assert row["tls12_forced_category"] == "sufficient"

        # Bucket probes
        assert row["accepts_recommended_tls12"] is False
        assert row["accepts_sufficient_tls12"] is True
        assert row["accepts_insecure_tls12"] is False

        # These are CBC suites with SHA256/SHA384
        assert row["allows_cbc_tls12"] is True
        assert row["allows_sha1_tls12"] is False
    finally:
        await runner.cleanup()

async def test_ciphers_catalog_rating_is_recorded(tiny_pool):
    if not _has_tlsver("TLSv1_2"):
        pytest.skip("Runner cannot expose TLS 1.2")

    chosen = "ECDHE-RSA-AES256-GCM-SHA384"
    catalog = [
        {
            "ECDHE-RSA-AES256-GCM-SHA384": {
                "openssl_name": "ECDHE-RSA-AES256-GCM-SHA384",
                "security": "recommended",
            }
        }
    ]   
    port = 9745

    runner = await _start_https(
        port=port,
        min_ver=ssl.TLSVersion.TLSv1_2,
        max_ver=ssl.TLSVersion.TLSv1_2,
        ciphers12=chosen,
    )
    try:
        mod = CipherSuitesModule(
            executor=tiny_pool,
            timeout_s=5.0,
            catalog=catalog,
        )
        await mod.run([f"127.0.0.1:{port}"])
        row = list(mod.results().values())[0]

        assert row["negotiated_cipher"] == chosen
        assert row["negotiated_security"] == "recommended"
    finally:
        await runner.cleanup()


async def test_cipher_catalog_loaded_from_remote_when_none(tiny_pool):
    if not _has_tlsver("TLSv1_2"):
        pytest.skip("TLS 1.2 required for this test")

    port = 9746
    chosen = "ECDHE-RSA-AES128-GCM-SHA256"

    runner = await _start_https(
        port=port,
        min_ver=ssl.TLSVersion.TLSv1_2,
        max_ver=ssl.TLSVersion.TLSv1_2,
        ciphers12=chosen,
        )

    try:
        mod = CipherSuitesModule(
            executor=tiny_pool,
            timeout_s=5.0,
        )

        await mod.run([f"127.0.0.1:{port}"])
        results = mod.results()
        assert results

        (_origin, row), = results.items()
        assert row["negotiated_cipher"] == chosen

        # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 is marked "secure"
        # in the ciphersuite.info catalog, so the module should record
        # that classification once it has fetched the catalog.
        assert row["negotiated_security"] == "secure"
    finally:
        await runner.cleanup()
