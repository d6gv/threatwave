"""abuse.ch ingestion connectors: URLhaus, MalwareBazaar and Feodo Tracker.

Three structured feeds from abuse.ch, each following the same pattern as the OTX
connector: a pure, deterministic ``normalize_*`` function (a field lookup, no AI)
plus a thin :class:`~threatweave.connectors.base.Connector` that fetches over an
injectable HTTP client and applies the shared retry/backoff policy. These feeds
already carry their indicators in fields, so ingestion is regex/normalization +
batched upsert — never the LLM extractor and never embeddings.

abuse.ch gates its feeds behind a single account ``Auth-Key`` (sent as the
``Auth-Key`` header); it is read from configuration, never hardcoded.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx

from threatweave.connectors.base import Connector
from threatweave.connectors.http import request_with_retry
from threatweave.models.ioc import IOC, IOCType

logger = logging.getLogger(__name__)


def _host_type(host: str) -> IOCType:
    """Classify a URLhaus ``host`` as an IPv4 literal or a domain."""
    try:
        ipaddress.IPv4Address(host)
        return IOCType.IPV4
    except ValueError:
        return IOCType.DOMAIN


def _parse_timestamp(value: str | None) -> datetime | None:
    """Best-effort parse of an abuse.ch timestamp (``YYYY-MM-DD HH:MM:SS`` UTC)."""
    if not value:
        return None
    cleaned = value.replace(" UTC", "").strip()
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        logger.warning("could not parse abuse.ch timestamp: %r", value)
        return None


def _dedup_sorted(seen: dict[tuple[IOCType, str], IOC]) -> list[IOC]:
    """Return the deduplicated IOCs in a deterministic order."""
    return sorted(seen.values(), key=lambda ioc: (ioc.type.value, ioc.value))


# --- URLhaus --------------------------------------------------------------


def normalize_urlhaus(payload: dict[str, Any], *, source: str) -> list[IOC]:
    """Normalize a URLhaus ``json_recent`` payload into internal IOCs.

    The feed is a mapping of id -> list of URL records; each record yields the
    malicious URL and, as a separate indicator, its host (an IPv4 or a domain).
    """
    seen: dict[tuple[IOCType, str], IOC] = {}

    def add(ioc_type: IOCType, value: str, first_seen: datetime | None) -> None:
        key = (ioc_type, value)
        if key not in seen:
            seen[key] = IOC(value=value, type=ioc_type, source=source, first_seen=first_seen)

    for records in payload.values():
        for record in records:
            url = record.get("url")
            if not url:
                continue
            first_seen = _parse_timestamp(record.get("date_added"))
            add(IOCType.URL, url, first_seen)
            host = record.get("host")
            if host:
                host_type = _host_type(host)
                value = host if host_type is IOCType.IPV4 else host.lower()
                add(host_type, value, first_seen)

    return _dedup_sorted(seen)


class URLhausConnector(Connector):
    """Fetches recently reported malicious URLs from abuse.ch URLhaus."""

    name = "urlhaus"

    def __init__(
        self,
        base_url: str = "https://urlhaus.abuse.ch",
        *,
        auth_key: str = "",
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_key = auth_key
        self._client = client
        self._owns_client = client is None
        self._sleep = sleep

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=30.0)
        return self._client

    def _headers(self) -> dict[str, str]:
        return {"Auth-Key": self._auth_key} if self._auth_key else {}

    def _fetch_payload(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"headers": self._headers()}
        if self._sleep is not None:
            kwargs["sleep"] = self._sleep
        response = request_with_retry(
            self._http(), "GET", f"{self._base_url}/downloads/json_recent/", **kwargs
        )
        return response.json()

    def fetch_iocs(self) -> list[IOC]:
        return normalize_urlhaus(self._fetch_payload(), source=self.name)

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()


# --- MalwareBazaar --------------------------------------------------------


def normalize_malwarebazaar(payload: dict[str, Any], *, source: str) -> list[IOC]:
    """Normalize a MalwareBazaar ``get_recent`` payload into hash IOCs.

    Each sample carries up to three file hashes (SHA256/SHA1/MD5); all present
    ones become separate, lower-cased indicators.
    """
    if payload.get("query_status") != "ok":
        # "no_results" and friends are normal empty responses, not errors.
        logger.debug("MalwareBazaar query_status=%r", payload.get("query_status"))
        return []

    seen: dict[tuple[IOCType, str], IOC] = {}
    hash_fields: tuple[tuple[str, IOCType], ...] = (
        ("sha256_hash", IOCType.SHA256),
        ("sha1_hash", IOCType.SHA1),
        ("md5_hash", IOCType.MD5),
    )
    for sample in payload.get("data", []):
        first_seen = _parse_timestamp(sample.get("first_seen"))
        for field, ioc_type in hash_fields:
            value = sample.get(field)
            if not value:
                continue
            key = (ioc_type, value.lower())
            if key not in seen:
                seen[key] = IOC(
                    value=value.lower(), type=ioc_type, source=source, first_seen=first_seen
                )

    return _dedup_sorted(seen)


class MalwareBazaarConnector(Connector):
    """Fetches recent malware sample hashes from abuse.ch MalwareBazaar."""

    name = "malwarebazaar"

    def __init__(
        self,
        base_url: str = "https://mb-api.abuse.ch/api/v1",
        *,
        auth_key: str = "",
        selector: str = "time",
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Create the connector.

        Args:
            selector: MalwareBazaar ``get_recent`` selector — ``"time"`` (last
                60 minutes) or ``"100"`` (last 100 samples).
        """
        self._base_url = base_url.rstrip("/")
        self._auth_key = auth_key
        self._selector = selector
        self._client = client
        self._owns_client = client is None
        self._sleep = sleep

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=30.0)
        return self._client

    def _headers(self) -> dict[str, str]:
        return {"Auth-Key": self._auth_key} if self._auth_key else {}

    def _fetch_payload(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "headers": self._headers(),
            "data": {"query": "get_recent", "selector": self._selector},
        }
        if self._sleep is not None:
            kwargs["sleep"] = self._sleep
        response = request_with_retry(self._http(), "POST", f"{self._base_url}/", **kwargs)
        return response.json()

    def fetch_iocs(self) -> list[IOC]:
        return normalize_malwarebazaar(self._fetch_payload(), source=self.name)

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()


# --- Feodo Tracker --------------------------------------------------------


def normalize_feodo(payload: list[dict[str, Any]], *, source: str) -> list[IOC]:
    """Normalize a Feodo Tracker ``ipblocklist.json`` payload into IPv4 IOCs."""
    seen: dict[tuple[IOCType, str], IOC] = {}
    for entry in payload:
        ip = entry.get("ip_address")
        if not ip:
            continue
        key = (IOCType.IPV4, ip)
        if key not in seen:
            seen[key] = IOC(
                value=ip,
                type=IOCType.IPV4,
                source=source,
                first_seen=_parse_timestamp(entry.get("first_seen")),
            )
    return _dedup_sorted(seen)


class FeodoTrackerConnector(Connector):
    """Fetches botnet C2 IP addresses from abuse.ch Feodo Tracker."""

    name = "feodo"

    def __init__(
        self,
        base_url: str = "https://feodotracker.abuse.ch",
        *,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        # Feodo Tracker's blocklist is public — no Auth-Key required.
        self._base_url = base_url.rstrip("/")
        self._client = client
        self._owns_client = client is None
        self._sleep = sleep

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=30.0)
        return self._client

    def _fetch_payload(self) -> list[dict[str, Any]]:
        kwargs: dict[str, Any] = {}
        if self._sleep is not None:
            kwargs["sleep"] = self._sleep
        response = request_with_retry(
            self._http(), "GET", f"{self._base_url}/downloads/ipblocklist.json", **kwargs
        )
        return response.json()

    def fetch_iocs(self) -> list[IOC]:
        return normalize_feodo(self._fetch_payload(), source=self.name)

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
