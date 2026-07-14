"""Tests for the abuse.ch connectors: normalization and the mocked HTTP path.

All HTTP is served by ``httpx.MockTransport`` — no real calls, no keys, no waits
(the retry ``sleep`` is stubbed).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx
import pytest

from threatweave.connectors.abusech import (
    FeodoTrackerConnector,
    MalwareBazaarConnector,
    URLhausConnector,
    normalize_feodo,
    normalize_malwarebazaar,
    normalize_urlhaus,
)
from threatweave.connectors.http import request_with_retry
from threatweave.models.ioc import IOCType


def _no_sleep(_seconds: float) -> None:
    """A sleep stub so retry tests never actually wait."""


# --- URLhaus --------------------------------------------------------------


def test_normalize_urlhaus_emits_url_and_host(urlhaus_payload: dict[str, Any]) -> None:
    iocs = normalize_urlhaus(urlhaus_payload, source="urlhaus")
    by_type: dict[IOCType, set[str]] = {}
    for ioc in iocs:
        by_type.setdefault(ioc.type, set()).add(ioc.value)

    # The domain host and the IPv4 host are both split out from their URLs.
    assert by_type[IOCType.DOMAIN] == {"malicious.example"}
    assert by_type[IOCType.IPV4] == {"203.0.113.20"}
    assert by_type[IOCType.URL] == {
        "http://malicious.example/payload.bin",
        "http://203.0.113.20/gate.php",
    }


def test_normalize_urlhaus_dedups_repeated_url(urlhaus_payload: dict[str, Any]) -> None:
    iocs = normalize_urlhaus(urlhaus_payload, source="urlhaus")
    # 2 unique URLs + 1 domain + 1 IPv4 = 4, despite the repeated URL record.
    assert len(iocs) == 4
    assert all(ioc.source == "urlhaus" for ioc in iocs)


def test_urlhaus_fetch_sends_auth_key(urlhaus_payload: dict[str, Any]) -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth_key"] = request.headers.get("Auth-Key")
        return httpx.Response(200, json=urlhaus_payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    connector = URLhausConnector(
        base_url="https://urlhaus.test", auth_key="secret", client=client
    )

    iocs = connector.fetch_iocs()

    assert len(iocs) == 4
    assert captured["auth_key"] == "secret"
    assert captured["url"].startswith("https://urlhaus.test/downloads/json_recent/")


# --- MalwareBazaar --------------------------------------------------------


def test_normalize_malwarebazaar_extracts_hashes(malwarebazaar_payload: dict[str, Any]) -> None:
    iocs = normalize_malwarebazaar(malwarebazaar_payload, source="malwarebazaar")
    by_type = {ioc.type for ioc in iocs}

    assert by_type == {IOCType.SHA256, IOCType.SHA1, IOCType.MD5}
    # Hashes are lower-cased for a canonical form.
    assert all(ioc.value == ioc.value.lower() for ioc in iocs)
    sha1 = {ioc.value for ioc in iocs if ioc.type is IOCType.SHA1}
    assert sha1 == {"aabbccddeeff00112233445566778899aabbccdd"}  # the null sha1 is dropped


def test_normalize_malwarebazaar_no_results_is_empty() -> None:
    assert normalize_malwarebazaar({"query_status": "no_results"}, source="x") == []


def test_malwarebazaar_fetch_posts_query(malwarebazaar_payload: dict[str, Any]) -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["auth_key"] = request.headers.get("Auth-Key")
        captured["body"] = request.content.decode()
        return httpx.Response(200, json=malwarebazaar_payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    connector = MalwareBazaarConnector(
        base_url="https://mb.test/api/v1", auth_key="secret", client=client
    )

    iocs = connector.fetch_iocs()

    assert len(iocs) == 5  # 2 sha256 + 1 sha1 + 2 md5
    assert captured["method"] == "POST"
    assert captured["auth_key"] == "secret"
    assert "get_recent" in captured["body"]


# --- Feodo Tracker --------------------------------------------------------


def test_normalize_feodo_extracts_ips(feodo_payload: list[dict[str, Any]]) -> None:
    iocs = normalize_feodo(feodo_payload, source="feodo")

    assert all(ioc.type is IOCType.IPV4 for ioc in iocs)
    # The blocklist repeats one IP; it collapses to a single indicator.
    assert {ioc.value for ioc in iocs} == {"203.0.113.20", "198.51.100.30"}
    ip = next(ioc for ioc in iocs if ioc.value == "203.0.113.20")
    assert ip.first_seen == datetime.fromisoformat("2026-01-05T08:00:00")


def test_feodo_fetch_needs_no_auth(feodo_payload: list[dict[str, Any]]) -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth_key"] = request.headers.get("Auth-Key")
        return httpx.Response(200, json=feodo_payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    connector = FeodoTrackerConnector(base_url="https://feodo.test", client=client)

    iocs = connector.fetch_iocs()

    assert len(iocs) == 2
    assert captured["auth_key"] is None  # public feed, no key sent
    assert captured["url"].endswith("/downloads/ipblocklist.json")


# --- Retry / rate-limit policy --------------------------------------------


def test_retry_recovers_after_429() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    response = request_with_retry(
        client, "GET", "https://feed.test/x", sleep=_no_sleep
    )

    assert response.json() == {"ok": True}
    assert calls["n"] == 2  # one 429, then success


def test_retry_gives_up_and_raises() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        request_with_retry(
            client, "GET", "https://feed.test/x", max_retries=2, sleep=_no_sleep
        )


def test_retry_does_not_retry_client_error() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        request_with_retry(client, "GET", "https://feed.test/x", sleep=_no_sleep)
    assert calls["n"] == 1  # 4xx (non-429) is not retried
