"""Shared HTTP helper for feed connectors: retry with backoff.

Feed sources (abuse.ch, ...) rate-limit aggressive polling and occasionally blip
with transient 5xx or connection errors. This helper centralises a polite retry
policy so every connector reacts the same way: back off on ``429`` (honouring a
``Retry-After`` header when present) and on transient transport/5xx errors, then
surface the error if retries are exhausted. ``sleep`` is injectable so tests never
actually wait.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def _retry_after(response: httpx.Response) -> float | None:
    """Return the ``Retry-After`` delay in seconds, if the header is a number."""
    value = response.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    data: Mapping[str, Any] | None = None,
    max_retries: int = 3,
    backoff: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> httpx.Response:
    """Issue an HTTP request, retrying on rate limits and transient failures.

    Retries on ``429`` and ``5xx`` responses and on :class:`httpx.TransportError`
    (connection resets, timeouts), with exponential backoff — respecting the
    source's rate limit rather than hammering it. Non-retryable HTTP errors (4xx
    other than 429) raise immediately via ``raise_for_status``.

    Returns the successful response, or raises the last error once ``max_retries``
    is exhausted.
    """
    attempt = 0
    while True:
        try:
            response = client.request(
                method, url, headers=headers, params=params, data=data
            )
        except httpx.TransportError:
            if attempt >= max_retries:
                raise
            delay = backoff * (2**attempt)
            logger.warning("transport error for %s; retrying in %.1fs", url, delay)
            sleep(delay)
            attempt += 1
            continue

        if response.status_code == 429 or response.status_code >= 500:
            if attempt >= max_retries:
                response.raise_for_status()
            delay = _retry_after(response) or backoff * (2**attempt)
            logger.warning(
                "rate-limited/5xx (%d) for %s; retrying in %.1fs",
                response.status_code,
                url,
                delay,
            )
            sleep(delay)
            attempt += 1
            continue

        response.raise_for_status()
        return response
