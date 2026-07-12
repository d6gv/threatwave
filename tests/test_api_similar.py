"""Tests for the /api/similar endpoint and semantic correlation over HTTP."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import FakeProvider
from threatweave.api.app import create_app
from threatweave.connectors.document import DocumentIntel
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest import ingest_document
from threatweave.llm.base import ExtractionResult
from threatweave.models.ioc import IOC, IOCType
from threatweave.vector.memory import InMemoryVectorStore

_VECTORS = {"a": [1.0, 0.0, 0.0], "b": [0.95, 0.05, 0.0], "c": [0.0, 1.0, 0.0]}
_REPORTS = [
    ("Report A", "1.1.1.1", "a"),
    ("Report B", "2.2.2.2", "b"),
    ("Report C", "3.3.3.3", "c"),
]


def _make_app(*, with_vectors: bool = True):
    store = InMemoryGraphStore()
    vectors = InMemoryVectorStore() if with_vectors else None
    provider = FakeProvider(embeddings=_VECTORS)
    for name, ip, text in _REPORTS:
        intel = DocumentIntel(
            report_name=name,
            source="s",
            text=text,
            iocs=[IOC(value=ip, type=IOCType.IPV4)],
            extraction=ExtractionResult(),
        )
        ingest_document(store, intel, provider=provider, vector_store=vectors)
    return create_app(store=store, vector_store=vectors)


def test_similar_returns_neighbours() -> None:
    with TestClient(_make_app()) as client:
        response = client.get(
            "/api/similar", params={"id": "campaign:Report A", "min_score": 0.5}
        )
        assert response.status_code == 200
        body = response.json()
        assert body[0]["id"] == "campaign:Report B"
        assert body[0]["label"] == "Report B"
        assert body[0]["score"] > 0.5


def test_similar_unknown_entity_returns_404() -> None:
    with TestClient(_make_app()) as client:
        response = client.get("/api/similar", params={"id": "campaign:Nope"})
        assert response.status_code == 404


def test_similar_disabled_returns_503() -> None:
    with TestClient(_make_app(with_vectors=False)) as client:
        response = client.get("/api/similar", params={"id": "campaign:Report A"})
        assert response.status_code == 503


def test_correlate_with_semantic_flag_includes_similarity_edges() -> None:
    with TestClient(_make_app()) as client:
        response = client.get(
            "/api/correlate",
            params={"ioc": "1.1.1.1", "semantic": "true", "min_score": 0.5},
        )
        assert response.status_code == 200
        edges = response.json()["edges"]
        semantic = [e for e in edges if e["type"] == "semantic_similarity"]
        assert len(semantic) == 1
        assert semantic[0]["score"] > 0.5


def test_correlate_without_semantic_flag_has_no_similarity_edges() -> None:
    with TestClient(_make_app()) as client:
        response = client.get("/api/correlate", params={"ioc": "1.1.1.1"})
        assert response.status_code == 200
        edges = response.json()["edges"]
        assert all(e["type"] != "semantic_similarity" for e in edges)
