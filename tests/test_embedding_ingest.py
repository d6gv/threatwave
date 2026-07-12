"""Tests for embedding generation and caching during ingestion."""

from __future__ import annotations

from tests.conftest import FakeProvider
from threatweave.connectors.document import DocumentIntel
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest import ingest_document
from threatweave.llm.base import ExtractionResult
from threatweave.vector.memory import InMemoryVectorStore


def _intel(text: str, name: str = "Report") -> DocumentIntel:
    return DocumentIntel(
        report_name=name, source="s", text=text, extraction=ExtractionResult()
    )


def test_embedding_is_stored_on_ingest() -> None:
    store = InMemoryGraphStore()
    vectors = InMemoryVectorStore()
    provider = FakeProvider(embeddings={"txt": [1.0, 0.0, 0.0]})

    campaign = ingest_document(store, _intel("txt"), provider=provider, vector_store=vectors)

    assert vectors.get(campaign.id) == [1.0, 0.0, 0.0]
    assert provider.embed_calls == 1


def test_reingest_same_text_hits_cache() -> None:
    store = InMemoryGraphStore()
    vectors = InMemoryVectorStore()
    provider = FakeProvider(embeddings={"txt": [1.0, 0.0, 0.0]})

    ingest_document(store, _intel("txt"), provider=provider, vector_store=vectors)
    ingest_document(store, _intel("txt"), provider=provider, vector_store=vectors)

    assert provider.embed_calls == 1  # second ingest used the cache


def test_changed_text_recomputes_embedding() -> None:
    store = InMemoryGraphStore()
    vectors = InMemoryVectorStore()
    provider = FakeProvider(embeddings={"t1": [1.0, 0.0, 0.0], "t2": [0.0, 1.0, 0.0]})

    ingest_document(store, _intel("t1"), provider=provider, vector_store=vectors)
    ingest_document(store, _intel("t2"), provider=provider, vector_store=vectors)

    assert provider.embed_calls == 2
    assert vectors.get("campaign:Report") == [0.0, 1.0, 0.0]


def test_no_vector_store_skips_embedding() -> None:
    store = InMemoryGraphStore()
    provider = FakeProvider(embeddings={"txt": [1.0, 0.0, 0.0]})

    ingest_document(store, _intel("txt"), provider=provider)

    assert provider.embed_calls == 0


def test_blank_text_skips_embedding() -> None:
    store = InMemoryGraphStore()
    vectors = InMemoryVectorStore()
    provider = FakeProvider()

    ingest_document(store, _intel("   "), provider=provider, vector_store=vectors)

    assert provider.embed_calls == 0
