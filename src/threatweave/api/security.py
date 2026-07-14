"""API gating for the public HTTP surface: casual API-key check + rate limiting.

The API key is deliberately **not** treated as a strong secret. The single-page
frontend ships it in its bundle (``VITE_API_KEY``), so anyone loading the page
can read it. It exists only as casual gating to keep drive-by traffic off a
public deployment; the real protection is the per-client rate limit. When
``API_KEY`` is unset — as in the in-memory demo — the check is disabled entirely
so the demo runs without any keys.
"""

from __future__ import annotations

from fastapi import Header, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from threatweave.config import get_settings

# Shared limiter, keyed by client address. Routes opt in via ``@limiter.limit``.
limiter = Limiter(key_func=get_remote_address)


def rate_limit() -> str:
    """Return the configured rate-limit string (read per request from settings)."""
    return get_settings().api_rate_limit


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Casual API-key gate for ``/api/*`` routes.

    No-op when ``API_KEY`` is unset (the demo). Otherwise the request must carry
    a matching ``X-API-Key`` header, or it is rejected with 401. This is gating,
    not authentication — see the module docstring.
    """
    expected = get_settings().api_key
    if not expected:
        return
    if x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing API key",
        )
