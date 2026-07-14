"""Tests for the API-key gating and rate limiting on the ``/api/*`` routes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from threatweave.api.app import create_app
from threatweave.config import get_settings
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest import ingest_otx_payload

_SAMPLE = Path(__file__).resolve().parents[1] / "data" / "samples" / "otx_subscribed.json"


def _client() -> TestClient:
    payload: dict[str, Any] = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    store = InMemoryGraphStore()
    ingest_otx_payload(store, payload)
    return TestClient(create_app(store=store))


def test_no_key_configured_allows_requests() -> None:
    """With API_KEY unset (the demo default), gating is disabled."""
    client = _client()
    response = client.get("/api/correlate", params={"ioc": "203.0.113.10"})
    assert response.status_code == 200


def test_missing_key_rejected_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_KEY", "s3cret-gate")
    get_settings.cache_clear()
    client = _client()

    response = client.get("/api/correlate", params={"ioc": "203.0.113.10"})
    assert response.status_code == 401


def test_wrong_key_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_KEY", "s3cret-gate")
    get_settings.cache_clear()
    client = _client()

    response = client.get(
        "/api/correlate",
        params={"ioc": "203.0.113.10"},
        headers={"X-API-Key": "wrong"},
    )
    assert response.status_code == 401


def test_correct_key_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_KEY", "s3cret-gate")
    get_settings.cache_clear()
    client = _client()

    response = client.get(
        "/api/correlate",
        params={"ioc": "203.0.113.10"},
        headers={"X-API-Key": "s3cret-gate"},
    )
    assert response.status_code == 200


def test_health_is_open_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """/health stays an unauthenticated liveness probe even when gating is on."""
    monkeypatch.setenv("API_KEY", "s3cret-gate")
    get_settings.cache_clear()
    client = _client()

    response = client.get("/health")
    assert response.status_code == 200


def test_rate_limit_returns_429(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_RATE_LIMIT", "2/minute")
    get_settings.cache_clear()
    client = _client()

    params = {"ioc": "203.0.113.10"}
    assert client.get("/api/correlate", params=params).status_code == 200
    assert client.get("/api/correlate", params=params).status_code == 200
    # Third request within the window is throttled.
    assert client.get("/api/correlate", params=params).status_code == 429
